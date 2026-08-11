// Package stats counts per-host traffic for the dashboard charts.
//
// nginx ships one UDP syslog datagram per request to this process (see
// engine.statsLog); the collector buckets them by hour into a fixed-size ring
// per host, so memory is capped regardless of traffic, and snapshots to
// /data/db/stats.json so counts survive a restart.
//
// A log file was the obvious alternative and was rejected: the runtime is
// distroless with a read-only rootfs, so rotation would have to be hand-rolled
// (rename + SIGUSR1 + prune) along with a disk cap and a parser. UDP needs none
// of that.
//
// ponytail: one sendto() per request, and the kernel drops datagrams when the
// receive queue is full, so counts are approximate under very high RPS — the
// tradeoff is deliberate, since a stalled collector can then never slow nginx
// down. Sample in the log_format, or move to a file + tail, if exact counts
// ever matter.
package stats

import (
	"bytes"
	"encoding/json"
	"log"
	"math"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"sync"
	"time"
)

const (
	// Addr is loopback-only on purpose: only processes inside the container
	// network namespace (i.e. nginx) can reach it.
	Addr = "127.0.0.1:8514"
	// Hours is the ring size — 30 days of hourly buckets.
	Hours = 24 * 30
	// maxHosts bounds the ring map so a misbehaving sender cannot grow it
	// without limit. Well past any realistic host count.
	maxHosts   = 4096
	flushEvery = time.Minute
	secPerHour = 3600
)

// bucket is one host-hour. hour records which hour the slot currently holds, so
// a slot left over from 30 days ago reads as empty instead of reporting a stale
// count — that is what makes retention free: writing a new hour overwrites the
// oldest slot, and no prune pass is ever needed.
//
// 4xx and 5xx are tracked separately because they answer different questions
// (someone probing vs. something broken); 2xx/3xx are the remainder and need no
// counter of their own.
type bucket struct {
	hour  int64
	hits  uint32
	e4xx  uint32
	e5xx  uint32
	bytes uint64
	rtMs  uint64 // summed request_time; the average is rtMs/hits
}

type ring [Hours]bucket

func slot(hour int64) int { return int(((hour % Hours) + Hours) % Hours) }

// sample is one request as reported by nginx.
type sample struct {
	status int
	bytes  uint64
	rtMs   uint64
}

func (r *ring) add(hour int64, s sample) {
	b := &r[slot(hour)]
	if b.hour != hour {
		*b = bucket{hour: hour}
	}
	b.hits++
	b.bytes += s.bytes
	b.rtMs += s.rtMs
	switch {
	case s.status >= 500:
		b.e5xx++
	case s.status >= 400:
		b.e4xx++
	}
}

func (r *ring) at(hour int64) bucket {
	if b := r[slot(hour)]; b.hour == hour {
		return b
	}
	return bucket{}
}

// Metrics is one series per statistic, aligned to the bucket list.
type Metrics struct {
	Hits  []uint32 `json:"hits"`
	E4xx  []uint32 `json:"e4xx"`
	E5xx  []uint32 `json:"e5xx"`
	Bytes []uint64 `json:"bytes"`
	AvgMs []uint32 `json:"avg_ms"`
}

func newMetrics(n int) *Metrics {
	return &Metrics{
		Hits: make([]uint32, n), E4xx: make([]uint32, n), E5xx: make([]uint32, n),
		Bytes: make([]uint64, n), AvgMs: make([]uint32, n),
	}
}

// Collector aggregates per-host request statistics.
type Collector struct {
	path  string
	hosts func() []int // live host ids, for dropping deleted hosts

	mu    sync.Mutex
	rings map[int]*ring
}

// New loads any previous snapshot from path. hosts may be nil (no reconcile).
func New(path string, hosts func() []int) *Collector {
	c := &Collector{path: path, hosts: hosts, rings: map[int]*ring{}}
	c.load()
	return c
}

// Run serves the UDP listener forever. A bind failure disables statistics and
// returns: losing counts must never take down the proxy.
func (c *Collector) Run() {
	pc, err := net.ListenPacket("udp", Addr)
	if err != nil {
		log.Printf("warn: stats collector disabled: %v", err)
		return
	}
	defer pc.Close()
	go c.flushLoop()

	buf := make([]byte, 512)
	for {
		n, _, err := pc.ReadFrom(buf)
		if err != nil {
			log.Printf("warn: stats collector stopped: %v", err)
			return
		}
		if id, s, ok := parse(buf[:n]); ok {
			c.Add(id, s, time.Now())
		}
	}
}

// parse reads one syslog datagram. nginx sends
// "<190>Aug 11 12:00:00 sn: 5 200 1234 0.007" — priority, timestamp and tag,
// then the log_format fields: host id, status, bytes sent, request time.
// The tag is the only ": " followed by a space (the timestamp's colons are
// not), so it is a safe place to cut the header off.
func parse(b []byte) (int, sample, bool) {
	if i := bytes.Index(b, []byte(": ")); i >= 0 {
		b = b[i+2:]
	}
	f := bytes.Fields(b)
	if len(f) != 4 {
		return 0, sample{}, false
	}
	id, err := strconv.Atoi(string(f[0]))
	if err != nil || id <= 0 {
		return 0, sample{}, false
	}
	// A malformed field degrades that one number to zero rather than dropping
	// the whole request: a missing byte count should not lose the hit.
	status, _ := strconv.Atoi(string(f[1]))
	sent, _ := strconv.ParseUint(string(f[2]), 10, 64)
	return id, sample{status: status, bytes: sent, rtMs: parseMs(f[3])}, true
}

// parseMs converts nginx's $request_time ("0.007" seconds) to whole
// milliseconds, clamped so a garbage value cannot poison the average.
func parseMs(b []byte) uint64 {
	secs, err := strconv.ParseFloat(string(b), 64)
	if err != nil || math.IsNaN(secs) || secs <= 0 {
		return 0
	}
	if ms := secs * 1000; ms < math.MaxUint32 {
		return uint64(ms)
	}
	return math.MaxUint32
}

// Add records one request for host id at time t.
func (c *Collector) Add(id int, s sample, t time.Time) {
	hour := t.Unix() / secPerHour
	c.mu.Lock()
	defer c.mu.Unlock()
	r := c.rings[id]
	if r == nil {
		// Unknown ids are accepted rather than dropped: a host created a second
		// ago must not lose its first requests. reconcile cleans up ids that
		// really do not exist.
		if len(c.rings) >= maxHosts {
			return
		}
		r = &ring{}
		c.rings[id] = r
	}
	r.add(hour, s)
}

// Series returns the last n hourly buckets (unix seconds, oldest first), the
// per-host metrics aligned to them, and the totals across all hosts. Hosts with
// no traffic in the window are omitted.
func (c *Collector) Series(n int, now time.Time) (buckets []int64, per map[int]*Metrics, total *Metrics) {
	if n < 1 {
		n = 1
	}
	if n > Hours {
		n = Hours
	}
	end := now.Unix() / secPerHour
	hours := make([]int64, n)
	buckets = make([]int64, n)
	for i := range hours {
		hours[i] = end - int64(n-1-i)
		buckets[i] = hours[i] * secPerHour
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	per = make(map[int]*Metrics, len(c.rings))
	total = newMetrics(n)
	totalRt := make([]uint64, n)
	for id, r := range c.rings {
		m := newMetrics(n)
		var seen uint32
		for i, h := range hours {
			b := r.at(h)
			m.Hits[i], m.E4xx[i], m.E5xx[i], m.Bytes[i] = b.hits, b.e4xx, b.e5xx, b.bytes
			m.AvgMs[i] = avg(b.rtMs, b.hits)
			total.Hits[i] += b.hits
			total.E4xx[i] += b.e4xx
			total.E5xx[i] += b.e5xx
			total.Bytes[i] += b.bytes
			totalRt[i] += b.rtMs
			seen += b.hits
		}
		if seen > 0 {
			per[id] = m
		}
	}
	// the overall average is weighted by hits, not an average of averages
	for i := range total.AvgMs {
		total.AvgMs[i] = avg(totalRt[i], total.Hits[i])
	}
	return buckets, per, total
}

func avg(sum uint64, hits uint32) uint32 {
	if hits == 0 {
		return 0
	}
	return uint32(sum / uint64(hits))
}

func (c *Collector) flushLoop() {
	t := time.NewTicker(flushEvery)
	defer t.Stop()
	for range t.C {
		c.reconcile()
		c.Flush()
	}
}

// reconcile drops rings for hosts that no longer exist, keeping the snapshot
// from accumulating deleted hosts forever.
func (c *Collector) reconcile() {
	if c.hosts == nil {
		return
	}
	live := map[int]bool{}
	for _, id := range c.hosts() {
		live[id] = true
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for id := range c.rings {
		if !live[id] {
			delete(c.rings, id)
		}
	}
}

// stored is the on-disk form of one bucket. Short keys because there are up to
// 720 of them per host.
type stored struct {
	H uint32 `json:"h"`
	F uint32 `json:"f,omitempty"` // 4xx
	V uint32 `json:"v,omitempty"` // 5xx
	B uint64 `json:"b,omitempty"`
	T uint64 `json:"t,omitempty"` // summed request time, ms
}

// snapshot holds only non-empty buckets, so the file stays small and reloading
// is a plain replay.
type snapshot map[int]map[int64]stored

// Flush writes the snapshot atomically (temp file + rename), matching
// store.Save. Failure is logged, not fatal: with no /data mounted the collector
// keeps counting in memory.
func (c *Collector) Flush() {
	if c.path == "" {
		return
	}
	c.mu.Lock()
	snap := make(snapshot, len(c.rings))
	for id, r := range c.rings {
		m := map[int64]stored{}
		for _, b := range r {
			if b.hits > 0 {
				m[b.hour] = stored{H: b.hits, F: b.e4xx, V: b.e5xx, B: b.bytes, T: b.rtMs}
			}
		}
		if len(m) > 0 {
			snap[id] = m
		}
	}
	c.mu.Unlock()

	raw, err := json.Marshal(snap)
	if err != nil {
		log.Printf("warn: stats marshal: %v", err)
		return
	}
	if err := os.MkdirAll(filepath.Dir(c.path), 0o755); err != nil {
		log.Printf("warn: stats dir: %v", err)
		return
	}
	tmp := c.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		log.Printf("warn: stats write: %v", err)
		return
	}
	if err := os.Rename(tmp, c.path); err != nil {
		log.Printf("warn: stats rename: %v", err)
	}
}

func (c *Collector) load() {
	raw, err := os.ReadFile(c.path)
	if err != nil {
		return // missing file on first boot is normal
	}
	var snap snapshot
	if err := json.Unmarshal(raw, &snap); err != nil {
		log.Printf("warn: stats snapshot unreadable, starting empty: %v", err)
		return
	}
	oldest := time.Now().Unix()/secPerHour - Hours + 1
	for id, m := range snap {
		if id <= 0 || len(c.rings) >= maxHosts {
			continue
		}
		r := &ring{}
		for hour, s := range m {
			// Out-of-window hours would alias onto a live slot; drop them so the
			// replay is deterministic regardless of map order.
			if hour < oldest {
				continue
			}
			r[slot(hour)] = bucket{hour: hour, hits: s.H, e4xx: s.F, e5xx: s.V, bytes: s.B, rtMs: s.T}
		}
		c.rings[id] = r
	}
}

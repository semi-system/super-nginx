package stats

import (
	"path/filepath"
	"testing"
	"time"
)

func TestParse(t *testing.T) {
	// what nginx actually sends: syslog priority + timestamp + tag, then the
	// four log_format fields
	id, s, ok := parse([]byte("<190>Aug 11 12:00:00 sn: 7 404 1234 0.007"))
	if !ok || id != 7 {
		t.Fatalf("host id: got (%d, %v), want (7, true)", id, ok)
	}
	if s.status != 404 || s.bytes != 1234 || s.rtMs != 7 {
		t.Fatalf("sample: got %+v, want {404 1234 7}", s)
	}
	for _, bad := range []string{"", "sn: ", "sn: abc 200 1 0.1", "sn: 0 200 1 0.1", "sn: 1 200", "sn: 1 200 1 0.1 extra"} {
		if id, _, ok := parse([]byte(bad)); ok {
			t.Fatalf("%q should be rejected, got id %d", bad, id)
		}
	}
	// one broken field must not cost the whole hit
	if _, s, ok := parse([]byte("sn: 3 200 - x")); !ok || s.bytes != 0 || s.rtMs != 0 {
		t.Fatalf("unparseable fields should degrade to 0, got %+v ok=%v", s, ok)
	}
}

func TestBucketing(t *testing.T) {
	c := New("", nil)
	now := time.Unix(1_700_000_000, 0)
	prev := now.Add(-time.Hour)

	c.Add(1, sample{status: 200, bytes: 100, rtMs: 10}, now)
	c.Add(1, sample{status: 404, bytes: 50, rtMs: 30}, now)
	c.Add(1, sample{status: 500, bytes: 10, rtMs: 0}, prev)
	c.Add(2, sample{status: 200, bytes: 7, rtMs: 4}, now)

	buckets, per, total := c.Series(2, now)
	if len(buckets) != 2 || buckets[1]-buckets[0] != secPerHour {
		t.Fatalf("buckets not hourly and oldest-first: %v", buckets)
	}
	h1 := per[1]
	if h1.Hits[0] != 1 || h1.Hits[1] != 2 {
		t.Fatalf("host 1 hits: want [1 2], got %v", h1.Hits)
	}
	if h1.E5xx[0] != 1 || h1.E4xx[1] != 1 || h1.E5xx[1] != 0 {
		t.Fatalf("host 1 errors: want 5xx=[1 0] 4xx=[0 1], got 5xx=%v 4xx=%v", h1.E5xx, h1.E4xx)
	}
	if h1.Bytes[1] != 150 {
		t.Fatalf("host 1 bytes: want 150, got %d", h1.Bytes[1])
	}
	if h1.AvgMs[1] != 20 { // (10+30)/2
		t.Fatalf("host 1 avg ms: want 20, got %d", h1.AvgMs[1])
	}
	if total.Hits[1] != 3 || total.Bytes[1] != 157 {
		t.Fatalf("total: want hits 3 / bytes 157, got %d / %d", total.Hits[1], total.Bytes[1])
	}
	// weighted by hits, not an average of the two hosts' averages (which is 12)
	if total.AvgMs[1] != 14 { // (10+30+4)/3
		t.Fatalf("total avg must be hit-weighted: want 14, got %d", total.AvgMs[1])
	}
	// hosts with no traffic in the window are left out of the response entirely
	c.Add(3, sample{status: 200}, now.Add(-48*time.Hour))
	if _, per, _ := c.Series(2, now); len(per) != 2 || per[3] != nil {
		t.Fatalf("host idle in the window should be omitted, got %v", per)
	}
}

// A slot is reused every 720 hours; the stamp must make the stale value read as
// empty instead of resurfacing a month-old count.
func TestRingWraparound(t *testing.T) {
	c := New("", nil)
	now := time.Unix(1_700_000_000, 0)
	old := now.Add(-Hours * time.Hour) // exactly one full lap: same slot

	c.Add(1, sample{status: 200, bytes: 99}, old)
	if _, per, _ := c.Series(1, old); per[1].Hits[0] != 1 {
		t.Fatal("count not recorded at its own hour")
	}
	if _, per, _ := c.Series(1, now); len(per) != 0 {
		t.Fatalf("stale slot must read empty, got %v", per)
	}
	// and writing the new hour resets rather than accumulating onto the stale one
	c.Add(1, sample{status: 200, bytes: 1}, now)
	_, per, _ := c.Series(1, now)
	if per[1].Hits[0] != 1 || per[1].Bytes[0] != 1 {
		t.Fatalf("new hour should start fresh, got hits=%v bytes=%v", per[1].Hits, per[1].Bytes)
	}
}

func TestReconcileDropsDeletedHosts(t *testing.T) {
	live := []int{1}
	c := New("", func() []int { return live })
	now := time.Now()
	c.Add(1, sample{status: 200}, now)
	c.Add(2, sample{status: 200}, now) // accepted on arrival even though unknown

	c.reconcile()
	if _, per, _ := c.Series(1, now); len(per) != 1 || per[1] == nil {
		t.Fatalf("only host 1 should survive reconcile, got %v", per)
	}
}

func TestFlushLoadRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "stats.json")
	now := time.Now()

	c := New(path, nil)
	c.Add(4, sample{status: 200, bytes: 10, rtMs: 6}, now)
	c.Add(4, sample{status: 503, bytes: 20, rtMs: 4}, now)
	c.Flush()

	_, per, _ := New(path, nil).Series(1, now)
	m := per[4]
	if m == nil || m.Hits[0] != 2 || m.E5xx[0] != 1 || m.Bytes[0] != 30 || m.AvgMs[0] != 5 {
		t.Fatalf("stats did not survive restart intact, got %+v", m)
	}
}

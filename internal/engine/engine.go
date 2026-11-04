// Package engine renders nginx config from state and applies it safely:
// render staging tree -> atomic directory swap -> nginx -t -> reload, restoring
// the old tree when validation fails. nginx only re-reads config on SIGHUP, so
// swapping files never affects the running instance until Test passes.
package engine

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"io"
	"io/fs"
	"log"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/morningstar-sudo/super-nginx/internal/stats"
	"github.com/morningstar-sudo/super-nginx/internal/store"
	"github.com/morningstar-sudo/super-nginx/internal/supervisor"
)

const (
	LiveDir  = "/data/nginx"
	bakDir   = "/data/nginx.bak"
	nextDir  = "/data/nginx.next"
	CertsDir = "/data/certs"
	WWWDir   = "/data/www"
	// lego's HTTP-01 solver listens here during a challenge; every :8080
	// server proxies /.well-known/acme-challenge/ to it.
	ACMEPort = "8402"
	// custom page for the catch-all server (Settings -> default site, "html")
	defaultDir = LiveDir + "/default"
)

func CertPath(id int) (fullchain, privkey string) {
	d := filepath.Join(CertsDir, fmt.Sprint(id))
	return filepath.Join(d, "fullchain.pem"), filepath.Join(d, "privkey.pem")
}

// Apply renders state into a staging tree and hot-reloads nginx. Unchanged
// trees skip nginx -t and reload. Caller holds the store mutex.
func Apply(s *store.State, sup *supervisor.Supervisor, reload bool) error {
	return apply(s, sup, reload, false)
}

// ApplyCertChange forces nginx to validate and reload even when the rendered
// config is unchanged. Certificate renewal changes PEM bytes, not config paths.
func ApplyCertChange(s *store.State, sup *supervisor.Supervisor) error {
	return apply(s, sup, true, true)
}

func apply(s *store.State, sup *supervisor.Supervisor, reload, forceReload bool) error {
	started := time.Now()
	renderStarted := time.Now()
	_ = os.RemoveAll(nextDir)
	if err := writeAt(s, nextDir); err != nil {
		_ = os.RemoveAll(nextDir)
		return err
	}
	renderDuration := time.Since(renderStarted)

	compareStarted := time.Now()
	same, err := treesEqual(nextDir, LiveDir)
	compareDuration := time.Since(compareStarted)
	if err != nil {
		_ = os.RemoveAll(nextDir)
		return fmt.Errorf("compare rendered config: %w", err)
	}
	if same {
		_ = os.RemoveAll(nextDir)
		if reload && !forceReload {
			log.Printf("engine: config unchanged, apply skipped (render=%s compare=%s total=%s)", renderDuration, compareDuration, time.Since(started))
			return nil
		}
	}

	var swapDuration time.Duration
	if !same {
		swapStarted := time.Now()
		_ = os.RemoveAll(bakDir)
		hadLive := false
		if _, statErr := os.Stat(LiveDir); statErr == nil {
			hadLive = true
			if err := os.Rename(LiveDir, bakDir); err != nil {
				_ = os.RemoveAll(nextDir)
				return fmt.Errorf("stage rendered config backup: %w", err)
			}
		} else if !os.IsNotExist(statErr) {
			_ = os.RemoveAll(nextDir)
			return fmt.Errorf("stat rendered config: %w", statErr)
		}
		if err := os.Rename(nextDir, LiveDir); err != nil {
			if hadLive {
				_ = os.Rename(bakDir, LiveDir)
			}
			return fmt.Errorf("activate staged config: %w", err)
		}
		swapDuration = time.Since(swapStarted)
	}

	restore := func() {
		if same {
			return
		}
		_ = os.RemoveAll(LiveDir)
		if _, err := os.Stat(bakDir); err == nil {
			_ = os.Rename(bakDir, LiveDir)
		}
	}
	testStarted := time.Now()
	if err := sup.Test(); err != nil {
		restore()
		return err
	}
	testDuration := time.Since(testStarted)

	var reloadDuration time.Duration
	if reload {
		reloadStarted := time.Now()
		if err := sup.Reload(); err != nil {
			restore()
			return err
		}
		reloadDuration = time.Since(reloadStarted)
	}
	_ = os.RemoveAll(bakDir)
	log.Printf("engine: apply complete (changed=%t forced=%t render=%s compare=%s swap=%s test=%s reload=%s total=%s)",
		!same, forceReload, renderDuration, compareDuration, swapDuration, testDuration, reloadDuration, time.Since(started))
	return nil
}

func writeAt(s *store.State, root string) error {
	for _, d := range []string{"conf.d", "mail.d", "stream.d", "htpasswd", "default"} {
		dir := filepath.Join(root, d)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	for _, al := range s.AccessLists {
		if len(al.Users) == 0 {
			continue
		}
		b := &bytes.Buffer{}
		for _, u := range al.Users {
			fmt.Fprintf(b, "%s:%s\n", u.Username, u.Hash)
		}
		if err := os.WriteFile(filepath.Join(root, "htpasswd", fmt.Sprint(al.ID)), b.Bytes(), 0o600); err != nil {
			return err
		}
	}
	// cache dirs must exist and be writable before nginx references them
	for _, h := range s.Hosts {
		if h.Enabled && cacheEnabled(h) {
			if err := os.MkdirAll(fmt.Sprintf("/data/cache/%d", h.ID), 0o755); err != nil {
				return err
			}
		}
	}
	if s.Settings.DefaultAction == "html" {
		if err := os.WriteFile(filepath.Join(root, "default", "index.html"), []byte(s.Settings.DefaultHTML), 0o644); err != nil {
			return err
		}
	}
	if err := os.WriteFile(filepath.Join(root, "conf.d", "hosts.conf"), renderHTTP(s), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(root, "stream.d", "streams.conf"), renderStream(s), 0o644)
}

func treeDigest(root string) ([sha256.Size]byte, error) {
	h := sha256.New()
	err := filepath.WalkDir(root, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		if _, err := io.WriteString(h, rel+"\x00"); err != nil {
			return err
		}
		if entry.IsDir() {
			_, err = io.WriteString(h, "d\x00")
			return err
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if _, err := fmt.Fprintf(h, "f:%o\x00", info.Mode().Perm()); err != nil {
			return err
		}
		file, err := os.Open(path)
		if err != nil {
			return err
		}
		_, copyErr := io.Copy(h, file)
		closeErr := file.Close()
		if copyErr != nil {
			return copyErr
		}
		return closeErr
	})
	if err != nil {
		return [sha256.Size]byte{}, err
	}
	var digest [sha256.Size]byte
	copy(digest[:], h.Sum(nil))
	return digest, nil
}

func treesEqual(left, right string) (bool, error) {
	leftDigest, err := treeDigest(left)
	if err != nil {
		return false, err
	}
	rightDigest, err := treeDigest(right)
	if os.IsNotExist(err) {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return leftDigest == rightDigest, nil
}

func htpasswdPath(id int) string {
	return filepath.Join(LiveDir, "htpasswd", fmt.Sprint(id))
}

// RenderedFiles returns the current rendered config for the UI viewer.
func RenderedFiles() map[string]string {
	out := map[string]string{}
	for _, d := range []string{"conf.d", "mail.d", "stream.d"} {
		files, _ := filepath.Glob(filepath.Join(LiveDir, d, "*.conf"))
		for _, f := range files {
			raw, err := os.ReadFile(f)
			if err == nil {
				out[d+"/"+filepath.Base(f)] = string(raw)
			}
		}
	}
	return out
}

const acmeLocation = `    location /.well-known/acme-challenge/ {
        proxy_pass http://127.0.0.1:` + ACMEPort + `;
        proxy_set_header Host $host;
    }
`

// statsLog feeds the per-host request counter (internal/stats): one UDP syslog
// datagram per request carrying nothing but the host id. No file is written, so
// this stays clear of the read-only rootfs and needs no rotation.
func statsLog(id int) string {
	return fmt.Sprintf("    set $sn_hid %d;\n    access_log syslog:server=%s,nohostname,tag=sn sn_stats;\n", id, stats.Addr)
}

func renderHTTP(s *store.State) []byte {
	b := &bytes.Buffer{}
	fmt.Fprint(b, "# generated by super-nginx — do not edit; source of truth is /data/db/state.json\n\n")
	// Shared TLS sessions avoid a full handshake when clients reconnect. The
	// cache is shared by workers and all TLS virtual hosts.
	fmt.Fprint(b, "ssl_session_cache shared:SN_SSL:20m;\nssl_session_timeout 10m;\n\n")
	fmt.Fprint(b, "map $http_upgrade $sn_connection {\n    default upgrade;\n    ''      close;\n}\n")
	// payload for the stats collector — see stats.parse
	fmt.Fprint(b, "log_format sn_stats '$sn_hid $status $bytes_sent $request_time';\n")
	// internal metrics endpoint for the dashboard
	// `set $sn_hid 0;` here is what makes the variable exist even with zero
	// hosts configured — nginx rejects the whole config with `unknown "sn_hid"
	// variable` if a log_format names a variable nothing ever sets. This server
	// keeps access_log off, so it never actually reports anything.
	fmt.Fprint(b, "server {\n    listen 127.0.0.1:8090;\n    access_log off;\n    modsecurity off;\n    set $sn_hid 0;\n    location = /stub_status {\n        stub_status;\n    }\n}\n")
	writeDefaultServer(b, s.Settings)
	for _, h := range s.Hosts {
		if !h.Enabled {
			continue
		}
		if h.Type == "load_balancer" {
			writeUpstream(b, h)
		}
		writeHost(b, s, h)
	}
	return b.Bytes()
}

// writeDefaultServer renders the catch-all (`server_name _`) pair: what answers
// a request whose Host — or TLS SNI — matches no configured host. Without it
// nginx falls back to the base image's welcome page on :8080 and to the first
// rendered host block on :8443, both of which leak.
func writeDefaultServer(b *bytes.Buffer, set store.Settings) {
	fmt.Fprint(b, "\n# default (catch-all) site — Settings -> default site\nserver {\n    listen 8080 default_server;\n    server_name _;\n")
	// no version/name in error pages or the Server header for unmatched hosts
	fmt.Fprint(b, "    server_tokens off;\n    modsecurity off;\n    access_log off;\n")
	// same reason as the stub_status server above: log_format sn_stats names
	// $sn_hid, so every server must set it even when it logs nothing.
	fmt.Fprint(b, "    set $sn_hid 0;\n")
	// unconditional: HTTP-01 issuance for a domain with no host block yet is
	// answered here, whatever the chosen action.
	fmt.Fprint(b, acmeLocation)
	switch set.DefaultAction {
	case "404":
		// own body on purpose: nginx's built-in 404 page prints "nginx" in its
		// footer. An empty string here is not enough — nginx falls back to the
		// branded page — so return one line of plain text instead. The Server
		// header still says "nginx"; dropping it needs headers_more, which the
		// base image does not build in.
		fmt.Fprint(b, "    location / {\n        default_type text/plain;\n        return 404 \"404 Not Found\";\n    }\n")
	case "redirect":
		fmt.Fprintf(b, "    location / {\n        return 301 %s$request_uri;\n    }\n", set.DefaultTarget)
	case "html":
		fmt.Fprintf(b, "    root %s;\n    location / {\n        try_files /index.html =404;\n    }\n", defaultDir)
	default: // close
		fmt.Fprint(b, "    location / {\n        return 444;\n    }\n")
	}
	fmt.Fprint(b, "}\n")

	// Unmatched SNI is dropped at the handshake. ssl_reject_handshake needs no
	// certificate, so there is nothing to configure and nothing to expire.
	fmt.Fprint(b, "server {\n    listen 8443 ssl default_server;\n    ssl_reject_handshake on;\n}\n")
}

// cacheZone is the shared-memory zone name for a host's proxy cache.
func cacheZone(id int) string { return fmt.Sprintf("sn_cache_%d", id) }

func cacheEnabled(h store.Host) bool {
	return (h.Type == "proxy" || h.Type == "load_balancer") && h.Cache
}

func upstreamName(id int) string { return fmt.Sprintf("sn_lb_%d", id) }

func writeUpstream(b *bytes.Buffer, h store.Host) {
	fmt.Fprintf(b, "\nupstream %s {\n", upstreamName(h.ID))
	// Share passive health/load-balancing state across workers and retain hot
	// backend connections per worker.
	fmt.Fprintf(b, "    zone %s 64k;\n    keepalive 64;\n", upstreamName(h.ID))
	switch h.LoadBalance {
	case "least_conn":
		fmt.Fprint(b, "    least_conn;\n")
	case "ip_hash":
		fmt.Fprint(b, "    ip_hash;\n")
	}
	for _, u := range h.Upstreams {
		fmt.Fprintf(b, "    server %s", u.Address)
		if u.Weight > 0 {
			fmt.Fprintf(b, " weight=%d", u.Weight)
		}
		fmt.Fprintf(b, " max_fails=%d", u.MaxFails)
		if u.FailTimeout != "" {
			fmt.Fprintf(b, " fail_timeout=%s", u.FailTimeout)
		}
		if u.Backup {
			fmt.Fprint(b, " backup")
		}
		fmt.Fprint(b, ";\n")
	}
	fmt.Fprint(b, "}\n")
}

func cacheTime(h store.Host) string {
	if h.CacheTime == "" {
		return "10m"
	}
	return h.CacheTime
}

func writeHost(b *bytes.Buffer, s *store.State, h store.Host) {
	names := strings.Join(h.Domains, " ")
	cert := s.CertByID(h.CertID)
	hasTLS := cert != nil
	if h.IsolateCerts {
		hasTLS = len(h.Domains) > 0
		for _, domain := range h.Domains {
			if s.CertByID(h.DomainCerts[domain]) == nil {
				hasTLS = false
				break
			}
		}
	}

	// proxy_cache_path is http-level (hosts.conf is included inside http{});
	// declared once per host, both the :8080 and :8443 servers reference it.
	// ponytail: max_size fixed at 512m — expose a knob if it ever bites.
	if cacheEnabled(h) {
		fmt.Fprintf(b, "\nproxy_cache_path /data/cache/%d levels=1:2 keys_zone=%s:10m max_size=512m inactive=%s use_temp_path=off;\n",
			h.ID, cacheZone(h.ID), cacheTime(h))
	}

	// plain :8080 server — ACME challenges always answered; either redirects
	// to https (force_ssl) or serves content
	fmt.Fprintf(b, "\n# host %d (%s)\nserver {\n    listen 8080;\n    server_name %s;\n", h.ID, h.Type, names)
	fmt.Fprint(b, statsLog(h.ID))
	fmt.Fprint(b, acmeLocation)
	if hasTLS && h.ForceSSL {
		fmt.Fprint(b, "    location / {\n        return 301 https://$host$request_uri;\n    }\n}\n")
	} else {
		writeServerCommon(b, h)
		writeContent(b, s, h)
		fmt.Fprint(b, "}\n")
	}

	if h.IsolateCerts {
		for _, domain := range h.Domains {
			if domainCert := s.CertByID(h.DomainCerts[domain]); domainCert != nil {
				writeTLSHost(b, s, h, domain, domainCert)
			}
		}
		return
	}
	if cert == nil {
		return
	}
	writeTLSHost(b, s, h, names, cert)
}

// writeTLSHost emits one TLS virtual server. Shared certificates call it once
// with every host name; isolated certificates call it once per domain so SNI
// can never serve a certificate whose SAN list reveals sibling domains.
func writeTLSHost(b *bytes.Buffer, s *store.State, h store.Host, names string, cert *store.Cert) {
	fullchain, privkey := CertPath(cert.ID)
	fmt.Fprintf(b, "server {\n    listen 8443 ssl;\n")
	if h.HTTP2 {
		fmt.Fprint(b, "    http2 on;\n")
	}
	fmt.Fprintf(b, "    server_name %s;\n    ssl_certificate %s;\n    ssl_certificate_key %s;\n", names, fullchain, privkey)
	fmt.Fprint(b, statsLog(h.ID))
	if h.HSTS {
		fmt.Fprint(b, "    add_header Strict-Transport-Security \"max-age=63072000\" always;\n")
	}
	fmt.Fprint(b, acmeLocation)
	writeServerCommon(b, h)
	writeContent(b, s, h)
	fmt.Fprint(b, "}\n")
}

// accessLines renders auth_basic + allow/deny inside a content location (not
// server-wide, so ACME challenges stay reachable).
func accessLines(s *store.State, h store.Host) string {
	al := s.AccessListByID(h.AccessListID)
	if al == nil {
		return ""
	}
	b := &bytes.Buffer{}
	hasUsers, hasIP := len(al.Users) > 0, len(al.Allow) > 0 || len(al.Deny) > 0
	if hasUsers && hasIP {
		satisfy := "all"
		if al.Satisfy == "any" {
			satisfy = "any"
		}
		fmt.Fprintf(b, "        satisfy %s;\n", satisfy)
	}
	if hasUsers {
		fmt.Fprintf(b, "        auth_basic \"Restricted\";\n        auth_basic_user_file %s;\n", htpasswdPath(al.ID))
	}
	for _, c := range al.Allow {
		fmt.Fprintf(b, "        allow %s;\n", c)
	}
	for _, c := range al.Deny {
		fmt.Fprintf(b, "        deny %s;\n", c)
	}
	if len(al.Allow) > 0 {
		fmt.Fprint(b, "        deny all;\n")
	}
	return b.String()
}

func writeServerCommon(b *bytes.Buffer, h store.Host) {
	// explicit per-host toggle wins over whatever the global conf says
	if h.WAF {
		fmt.Fprint(b, "    modsecurity on;\n    modsecurity_rules_file /etc/nginx/modsecurity.conf;\n")
	} else {
		fmt.Fprint(b, "    modsecurity off;\n")
	}
	for _, d := range h.Directives {
		if d.Key != "" {
			fmt.Fprintf(b, "    %s %s;\n", d.Key, d.Value)
		}
	}
	if h.ServerSnippet != "" {
		fmt.Fprintf(b, "    # server snippet\n%s\n", indent(h.ServerSnippet))
	}
}

func writeContent(b *bytes.Buffer, s *store.State, h store.Host) {
	access := accessLines(s, h)
	switch h.Type {
	case "redirect":
		fmt.Fprintf(b, "    location / {\n        return 301 %s$request_uri;\n    }\n", h.Target)
	case "static":
		fmt.Fprintf(b, "    root %s;\n    index index.html;\n    location / {\n%s        try_files $uri $uri/ =404;\n", filepath.Join(WWWDir, h.Target), access)
		if h.LocationSnippet != "" {
			fmt.Fprintf(b, "%s\n", indent(indent(h.LocationSnippet)))
		}
		fmt.Fprint(b, "    }\n")
	default: // proxy or load_balancer
		fmt.Fprint(b, "    location / {\n")
		fmt.Fprint(b, access)
		if h.Type == "load_balancer" {
			fmt.Fprintf(b, "        proxy_pass %s://%s;\n", h.UpstreamScheme, upstreamName(h.ID))
			if h.VerifyBackendTLS {
				fmt.Fprint(b, "        proxy_ssl_verify on;\n")
				fmt.Fprint(b, "        proxy_ssl_server_name on;\n")
				fmt.Fprintf(b, "        proxy_ssl_name %s;\n", h.BackendTLSServerName)
				fmt.Fprint(b, "        proxy_ssl_trusted_certificate /etc/ssl/certs/ca-certificates.crt;\n")
				fmt.Fprint(b, "        proxy_ssl_verify_depth 5;\n")
				fmt.Fprint(b, "        proxy_ssl_protocols TLSv1.2 TLSv1.3;\n")
			}
		} else {
			fmt.Fprintf(b, "        proxy_pass %s;\n", h.Target)
		}
		fmt.Fprint(b, "        proxy_http_version 1.1;\n        proxy_set_header Host $host;\n        proxy_set_header X-Real-IP $remote_addr;\n        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;\n        proxy_set_header X-Forwarded-Proto $scheme;\n")
		if h.Websocket {
			fmt.Fprint(b, "        proxy_set_header Upgrade $http_upgrade;\n        proxy_set_header Connection $sn_connection;\n")
		} else {
			fmt.Fprint(b, "        proxy_set_header Connection \"\";\n")
		}
		if cacheEnabled(h) {
			fmt.Fprintf(b, "        proxy_cache %s;\n        proxy_cache_lock on;\n        proxy_cache_background_update on;\n        proxy_cache_revalidate on;\n        proxy_cache_valid 200 302 %s;\n        proxy_cache_valid 404 1m;\n        proxy_cache_use_stale error timeout updating;\n        add_header X-Cache-Status $upstream_cache_status;\n",
				cacheZone(h.ID), cacheTime(h))
		}
		if h.LocationSnippet != "" {
			fmt.Fprintf(b, "        # location snippet\n%s\n", indent(indent(h.LocationSnippet)))
		}
		fmt.Fprint(b, "    }\n")
	}
}

func renderStream(s *store.State) []byte {
	b := &bytes.Buffer{}
	fmt.Fprint(b, "# generated by super-nginx — do not edit\nstream {\n")

	domains := append([]store.MailDomain(nil), s.MailDomains...)
	sort.Slice(domains, func(i, j int) bool { return domains[i].Domain < domains[j].Domain })

	// Every mail domain rides every listener: SNI only picks the cert, traffic
	// goes to the listener's one backend (literal proxy_pass, no resolver needed).
	for _, l := range s.MailListeners {
		if !l.Enabled || l.DefaultBackend == "" { // empty: pre-validation legacy state, would render `proxy_pass ;`
			continue
		}
		switch l.Mode {
		case "terminate":
			crt, key := fmt.Sprintf("$sn_crt_%d", l.ID), fmt.Sprintf("$sn_key_%d", l.ID)
			defFull, defKey := defaultCert(s, domains)
			fmt.Fprintf(b, "\n    # mail listener %d (%s, TLS terminate, SNI cert)\n", l.ID, l.Label)
			fmt.Fprintf(b, "    map $ssl_server_name %s {\n        default %s;\n", crt, defFull)
			for _, d := range domains {
				if full, _, ok := domainCert(s, d); ok {
					fmt.Fprintf(b, "        %s %s;\n", d.Domain, full)
				}
			}
			fmt.Fprint(b, "    }\n")
			fmt.Fprintf(b, "    map $ssl_server_name %s {\n        default %s;\n", key, defKey)
			for _, d := range domains {
				if _, priv, ok := domainCert(s, d); ok {
					fmt.Fprintf(b, "        %s %s;\n", d.Domain, priv)
				}
			}
			fmt.Fprint(b, "    }\n")
			proxySSL := ""
			if l.ProxySSL {
				// re-encrypt to the backend (backend listens on its TLS port, e.g. 993)
				proxySSL = "        proxy_ssl on;\n"
			}
			fmt.Fprintf(b, "    server {\n        listen %d ssl;\n        ssl_certificate %s;\n        ssl_certificate_key %s;\n%s        proxy_pass %s;\n    }\n", l.Port, crt, key, proxySSL, l.DefaultBackend)
		default: // passthrough: backend holds the cert
			fmt.Fprintf(b, "\n    # mail listener %d (%s, passthrough)\n", l.ID, l.Label)
			fmt.Fprintf(b, "    server {\n        listen %d;\n        proxy_pass %s;\n    }\n", l.Port, l.DefaultBackend)
		}
	}

	for _, r := range s.Streams {
		if !r.Enabled {
			continue
		}
		proto := ""
		if r.UDP {
			proto = " udp"
		}
		fmt.Fprintf(b, "\n    # stream %d\n    server {\n        listen %d%s;\n        proxy_pass %s;\n    }\n", r.ID, r.Port, proto, r.Backend)
	}

	fmt.Fprint(b, "}\n")
	return b.Bytes()
}

func domainCert(s *store.State, d store.MailDomain) (fullchain, privkey string, ok bool) {
	if s.CertByID(d.CertID) == nil {
		return "", "", false
	}
	full, priv := CertPath(d.CertID)
	return full, priv, true
}

// defaultCert picks the first mail domain's cert for clients that send no
// SNI. ponytail: good enough; add an explicit default_cert_id if it matters.
func defaultCert(s *store.State, domains []store.MailDomain) (fullchain, privkey string) {
	for _, d := range domains {
		if full, priv, ok := domainCert(s, d); ok {
			return full, priv
		}
	}
	return "/dev/null", "/dev/null"
}

func indent(s string) string {
	lines := strings.Split(strings.TrimRight(s, "\n"), "\n")
	for i, l := range lines {
		lines[i] = "    " + l
	}
	return strings.Join(lines, "\n")
}

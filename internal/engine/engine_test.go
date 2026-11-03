package engine

import (
	"strings"
	"testing"

	"github.com/morningstar-sudo/super-nginx/internal/store"
)

func TestProxyHostRender(t *testing.T) {
	// proxy host with cache on emits http-level path + location directives
	cached := &store.State{
		Hosts: []store.Host{
			{ID: 5, Type: "proxy", Domains: []string{"a.example.com"}, Target: "http://127.0.0.1:3000", Cache: true, CacheTime: "30s", Enabled: true},
		},
	}
	cg := string(renderHTTP(cached))
	if !strings.Contains(cg, "proxy_cache_path /data/cache/5") || !strings.Contains(cg, "keys_zone=sn_cache_5:") {
		t.Fatalf("cache host missing proxy_cache_path, got:\n%s", cg)
	}
	if !strings.Contains(cg, "proxy_cache sn_cache_5;") || !strings.Contains(cg, "proxy_cache_valid 200 302 30s;") {
		t.Fatalf("cache host missing location cache directives, got:\n%s", cg)
	}
	// non-cache proxy host emits nothing cache-related
	if strings.Contains(string(renderHTTP(&store.State{Hosts: []store.Host{{ID: 6, Type: "proxy", Domains: []string{"b"}, Target: "http://127.0.0.1:1", Enabled: true}}})), "proxy_cache") {
		t.Fatal("non-cache host should not emit proxy_cache")
	}

	// extra directives render in server context as `name value;`
	withDir := &store.State{
		Hosts: []store.Host{
			{ID: 7, Type: "proxy", Domains: []string{"d.example.com"}, Target: "http://127.0.0.1:8",
				Directives: []store.HostDirective{{Key: "client_max_body_size", Value: "100m"}}, Enabled: true},
		},
	}
	if !strings.Contains(string(renderHTTP(withDir)), "client_max_body_size 100m;") {
		t.Fatal("directive not rendered")
	}
}

func TestLoadBalancerHostRender(t *testing.T) {
	s := &store.State{Hosts: []store.Host{{
		ID: 12, Type: "load_balancer", Domains: []string{"lb.example.com"},
		UpstreamScheme: "https", LoadBalance: "least_conn", Cache: true, CacheTime: "1m", Enabled: true,
		Upstreams: []store.Upstream{
			{Address: "app-1:3000", Weight: 3, MaxFails: 2, FailTimeout: "15s"},
			{Address: "app-2:3000", Weight: 1, MaxFails: 1, FailTimeout: "10s", Backup: true},
		},
	}}}
	got := string(renderHTTP(s))
	for _, want := range []string{
		"upstream sn_lb_12 {",
		"least_conn;",
		"server app-1:3000 weight=3 max_fails=2 fail_timeout=15s;",
		"server app-2:3000 weight=1 max_fails=1 fail_timeout=10s backup;",
		"proxy_pass https://sn_lb_12;",
		"proxy_cache sn_cache_12;",
	} {
		if !strings.Contains(got, want) {
			t.Fatalf("load balancer config missing %q, got:\n%s", want, got)
		}
	}
}

// Every user-facing server block must feed the stats collector, including the
// force_ssl redirect block (which skips writeServerCommon) and the https block.
// The internal stub_status server must stay out of the counts.
func TestStatsLogRendered(t *testing.T) {
	s := &store.State{
		Certs: []store.Cert{{ID: 1, Name: "c", Type: "custom"}},
		Hosts: []store.Host{
			{ID: 9, Type: "proxy", Domains: []string{"a.example.com"}, Target: "http://127.0.0.1:3000",
				CertID: 1, ForceSSL: true, Enabled: true},
		},
	}
	got := string(renderHTTP(s))

	// field order and count must match stats.parse
	if !strings.Contains(got, "log_format sn_stats '$sn_hid $status $bytes_sent $request_time';") {
		t.Fatalf("missing log_format, got:\n%s", got)
	}
	if n := strings.Count(got, "set $sn_hid 9;"); n != 2 {
		t.Fatalf("want $sn_hid in both the :8080 and :8443 blocks, got %d:\n%s", n, got)
	}
	if n := strings.Count(got, "access_log syslog:server=127.0.0.1:8514,nohostname,tag=sn sn_stats;"); n != 2 {
		t.Fatalf("want 2 syslog access_log lines, got %d:\n%s", n, got)
	}
	if !strings.Contains(got, "access_log off;") {
		t.Fatalf("stub_status server must keep access_log off, got:\n%s", got)
	}

	// With no hosts at all, nginx still has to accept the config: a log_format
	// naming a variable nothing sets fails with `unknown "sn_hid" variable`, so
	// the stub_status server carries a placeholder set.
	empty := string(renderHTTP(&store.State{}))
	if !strings.Contains(empty, "log_format sn_stats") || !strings.Contains(empty, "set $sn_hid 0;") {
		t.Fatalf("empty state must still define $sn_hid, got:\n%s", empty)
	}
}

// The catch-all server must exist for every action, never leak nginx's own
// pages, and always keep answering ACME challenges.
func TestDefaultServer(t *testing.T) {
	cases := []struct {
		set  store.Settings
		want string
	}{
		{store.Settings{}, "return 444;"},                                     // zero value == close
		{store.Settings{DefaultAction: "close"}, "return 444;"},               //
		{store.Settings{DefaultAction: "404"}, `return 404 "404 Not Found";`}, //
		{store.Settings{DefaultAction: "redirect", DefaultTarget: "https://example.com"}, //
			"return 301 https://example.com$request_uri;"},
		{store.Settings{DefaultAction: "html", DefaultHTML: "<h1>x</h1>"}, "root " + defaultDir + ";"},
	}
	for _, c := range cases {
		got := string(renderHTTP(&store.State{Settings: c.set}))
		if !strings.Contains(got, c.want) {
			t.Fatalf("action %q: want %q, got:\n%s", c.set.DefaultAction, c.want, got)
		}
		if !strings.Contains(got, "listen 8080 default_server;") || !strings.Contains(got, "server_name _;") {
			t.Fatalf("action %q: missing :8080 catch-all, got:\n%s", c.set.DefaultAction, got)
		}
		// unmatched SNI is dropped at the handshake instead of falling through
		// to whichever host block happens to render first
		if !strings.Contains(got, "listen 8443 ssl default_server;") || !strings.Contains(got, "ssl_reject_handshake on;") {
			t.Fatalf("action %q: missing :8443 catch-all, got:\n%s", c.set.DefaultAction, got)
		}
		if !strings.Contains(got, "location /.well-known/acme-challenge/") {
			t.Fatalf("action %q: catch-all dropped ACME location, got:\n%s", c.set.DefaultAction, got)
		}
		if !strings.Contains(got, "server_tokens off;") {
			t.Fatalf("action %q: catch-all must not advertise nginx, got:\n%s", c.set.DefaultAction, got)
		}
	}

	// nginx rejects a second default_server on the same port, so a rendered host
	// must never add one.
	withHost := string(renderHTTP(&store.State{
		Hosts: []store.Host{{ID: 1, Type: "proxy", Domains: []string{"a.example.com"}, Target: "http://127.0.0.1:1", Enabled: true}},
	}))
	if n := strings.Count(withHost, "default_server"); n != 2 {
		t.Fatalf("want exactly one default_server per port, got %d:\n%s", n, withHost)
	}
}

// Every mail domain rides every listener: its cert lands in each terminate
// listener's SNI map once, and traffic goes to the listener's backend
// (literal proxy_pass, so no resolver).
func TestMailListenerRender(t *testing.T) {
	s := &store.State{
		Certs: []store.Cert{{ID: 1, Name: "c", Type: "custom"}},
		MailDomains: []store.MailDomain{
			{ID: 2, Domain: "webmail.example.com", CertID: 1},
			{ID: 3, Domain: "mail.other.vn", CertID: 1},
		},
		MailListeners: []store.MailListener{
			{ID: 4, Label: "imap", Port: 2993, Mode: "terminate", DefaultBackend: "10.0.0.5:143", Enabled: true},
			{ID: 5, Label: "pop3", Port: 2995, Mode: "terminate", DefaultBackend: "10.0.0.5:110", Enabled: true},
			{ID: 6, Label: "smtp", Port: 2525, Mode: "passthrough", DefaultBackend: "10.0.0.5:25", Enabled: true},
			{ID: 7, Label: "old", Port: 2000, Mode: "passthrough", Enabled: true}, // legacy: no backend → skipped
		},
	}
	got := string(renderStream(s))
	for _, want := range []string{"proxy_pass 10.0.0.5:143;", "proxy_pass 10.0.0.5:110;", "proxy_pass 10.0.0.5:25;"} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q:\n%s", want, got)
		}
	}
	// crt + key map on each of the 2 terminate listeners
	if n := strings.Count(got, "webmail.example.com "); n != 4 {
		t.Fatalf("want domain in 4 cert maps, got %d:\n%s", n, got)
	}
	if strings.Contains(got, "resolver") || strings.Contains(got, "listen 2000") {
		t.Fatalf("unexpected resolver or legacy listener:\n%s", got)
	}
}

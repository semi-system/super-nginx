package engine

import (
	"strings"
	"testing"

	"github.com/morningstar-sudo/super-nginx/internal/store"
)

// terminate/SNI listeners emit variable proxy_pass, which needs a resolver for
// hostname backends; a passthrough non-SNI listener (literal proxy_pass) must not.
func TestStreamResolver(t *testing.T) {
	terminate := &store.State{
		Certs:       []store.Cert{{ID: 1, Name: "c", Type: "custom"}},
		MailDomains: []store.MailDomain{{ID: 2, Domain: "mail.example.com", Backend: "mailhost:465", CertID: 1}},
		MailListeners: []store.MailListener{
			{ID: 3, Port: 2465, Mode: "terminate", Enabled: true},
		},
	}
	got := string(renderStream(terminate))
	if !strings.Contains(got, "resolver 127.0.0.11") {
		t.Fatalf("terminate listener should emit resolver, got:\n%s", got)
	}
	// empty default backend must render as valid quoted map default, not `default ;`
	if !strings.Contains(got, `default "";`) {
		t.Fatalf("empty default backend should render `default \"\";`, got:\n%s", got)
	}

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

	plain := &store.State{
		MailListeners: []store.MailListener{
			{ID: 1, Port: 2525, Mode: "passthrough", DefaultBackend: "10.0.0.5:25", Enabled: true},
		},
	}
	if got := string(renderStream(plain)); strings.Contains(got, "resolver") {
		t.Fatalf("passthrough non-SNI uses literal proxy_pass, no resolver needed, got:\n%s", got)
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
		{store.Settings{}, "return 444;"},                       // zero value == close
		{store.Settings{DefaultAction: "close"}, "return 444;"}, //
		{store.Settings{DefaultAction: "404"}, `return 404 "404 Not Found";`},   //
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

// One mail domain is routed on every listener, each to the domain host on that
// listener's backend port; a legacy listener (no port) keeps domain host:port.
func TestMailDomainPerListenerPort(t *testing.T) {
	s := &store.State{
		Certs:       []store.Cert{{ID: 1, Name: "c", Type: "custom"}},
		MailDomains: []store.MailDomain{{ID: 2, Domain: "webmail.example.com", Backend: "mail", CertID: 1}},
		MailListeners: []store.MailListener{
			{ID: 3, Label: "smtp", Port: 2465, Mode: "terminate", BackendPort: 465, ProxySSL: true, Enabled: true},
			{ID: 4, Label: "imap", Port: 2993, Mode: "terminate", BackendPort: 993, ProxySSL: true, Enabled: true},
			{ID: 5, Label: "pop3", Port: 2995, Mode: "passthrough", SNIRoute: true, BackendPort: 995, Enabled: true},
		},
	}
	got := string(renderStream(s))
	for _, want := range []string{"webmail.example.com mail:465;", "webmail.example.com mail:993;", "webmail.example.com mail:995;"} {
		if n := strings.Count(got, want); n != 1 {
			t.Fatalf("want %q once, got %d:\n%s", want, n, got)
		}
	}

	legacy := &store.State{
		MailDomains:   []store.MailDomain{{ID: 2, Domain: "webmail.example.com", Backend: "mail:465"}},
		MailListeners: []store.MailListener{{ID: 3, Port: 2465, Mode: "passthrough", SNIRoute: true, Enabled: true}},
	}
	if got := string(renderStream(legacy)); !strings.Contains(got, "webmail.example.com mail:465;") {
		t.Fatalf("legacy host:port backend changed:\n%s", got)
	}
	// listener port overrides a legacy domain port
	legacy.MailListeners[0].BackendPort = 995
	if got := string(renderStream(legacy)); !strings.Contains(got, "webmail.example.com mail:995;") {
		t.Fatalf("listener backend port not applied to host:port domain:\n%s", got)
	}
}

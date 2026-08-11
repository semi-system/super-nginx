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

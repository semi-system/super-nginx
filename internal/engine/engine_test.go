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

	plain := &store.State{
		MailListeners: []store.MailListener{
			{ID: 1, Port: 2525, Mode: "passthrough", DefaultBackend: "10.0.0.5:25", Enabled: true},
		},
	}
	if got := string(renderStream(plain)); strings.Contains(got, "resolver") {
		t.Fatalf("passthrough non-SNI uses literal proxy_pass, no resolver needed, got:\n%s", got)
	}
}

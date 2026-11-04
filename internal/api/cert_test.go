package api

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/morningstar-sudo/super-nginx/internal/store"
)

func TestCertUsage(t *testing.T) {
	s := &store.State{
		Hosts: []store.Host{
			{ID: 1, Domains: []string{"shared.example.com"}, CertID: 10},
			{ID: 2, Domains: []string{"isolated.example.com"}, IsolateCerts: true, DomainCerts: map[string]int{"isolated.example.com": 20}},
		},
		MailDomains: []store.MailDomain{{Domain: "mail.example.com", CertID: 30}},
	}
	tests := []struct {
		id   int
		want string
	}{
		{10, "host 1"},
		{20, "host 2"},
		{30, "mail domain mail.example.com"},
		{40, ""},
	}
	for _, tt := range tests {
		got := certUsage(s, tt.id)
		if (tt.want == "" && got != "") || (tt.want != "" && !strings.Contains(got, tt.want)) {
			t.Errorf("certUsage(%d) = %q, want it to contain %q", tt.id, got, tt.want)
		}
	}
}

func TestCertCleanupCandidate(t *testing.T) {
	now := time.Now()
	tests := []struct {
		name string
		cert store.Cert
		want bool
	}{
		{"valid acme", store.Cert{Type: "acme", ExpiresAt: now.Add(time.Hour)}, true},
		{"expired acme", store.Cert{Type: "acme", ExpiresAt: now.Add(-time.Hour)}, true},
		{"expired custom", store.Cert{Type: "custom", ExpiresAt: now.Add(-time.Hour)}, true},
		{"valid custom", store.Cert{Type: "custom", ExpiresAt: now.Add(time.Hour)}, false},
		{"custom without expiry", store.Cert{Type: "custom"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := certCleanupCandidate(tt.cert, now); got != tt.want {
				t.Fatalf("certCleanupCandidate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIssueIsolatedACMECertsBuildsOrderedCerts(t *testing.T) {
	s := &store.State{Seq: 40, Settings: store.Settings{ACMEEmail: "admin@example.com"}}
	in := acmeRequest{Domains: []string{"one.example.com", "two.example.com"}, Challenge: "http"}

	ids, err := issueIsolatedACMECerts(s, in, func(certificates []*store.Cert, settings store.Settings) []error {
		if settings.ACMEEmail != "admin@example.com" {
			t.Fatalf("settings not passed to batch issuer: %+v", settings)
		}
		for _, cert := range certificates {
			cert.ExpiresAt = time.Now().Add(90 * 24 * time.Hour)
		}
		return make([]error, len(certificates))
	}, func(int) {})
	if err != nil {
		t.Fatalf("issueIsolatedACMECerts() error = %v", err)
	}
	if ids["one.example.com"] != 41 || ids["two.example.com"] != 42 {
		t.Fatalf("unexpected domain ids: %+v", ids)
	}
	if s.Seq != 42 || len(s.Certs) != 2 {
		t.Fatalf("unexpected state after issuance: seq=%d certs=%+v", s.Seq, s.Certs)
	}
	for index, cert := range s.Certs {
		if cert.ID != 41+index || len(cert.Domains) != 1 || cert.Domains[0] != in.Domains[index] {
			t.Fatalf("certificate %d lost input ordering: %+v", index, cert)
		}
		if cert.Name == "" || !strings.Contains(cert.Name, strings.TrimSuffix(in.Domains[index], ".com")) {
			t.Fatalf("certificate %d has unexpected generated name %q", index, cert.Name)
		}
	}
}

func TestIssueIsolatedACMECertsRollsBackBatch(t *testing.T) {
	s := &store.State{Seq: 7, Certs: []store.Cert{{ID: 3, Name: "existing"}}}
	in := acmeRequest{Domains: []string{"one.example.com", "two.example.com", "three.example.com"}, Challenge: "dns"}
	removed := []int{}

	ids, err := issueIsolatedACMECerts(s, in, func(certificates []*store.Cert, _ store.Settings) []error {
		errs := make([]error, len(certificates))
		errs[1] = errors.New("provider rejected request")
		return errs
	}, func(id int) { removed = append(removed, id) })
	if err == nil || !strings.Contains(err.Error(), `domain "two.example.com"`) {
		t.Fatalf("expected domain-specific batch error, got ids=%v err=%v", ids, err)
	}
	if s.Seq != 7 || len(s.Certs) != 1 || s.Certs[0].Name != "existing" {
		t.Fatalf("state was not rolled back: seq=%d certs=%+v", s.Seq, s.Certs)
	}
	wantRemoved := []int{8, 9, 10}
	if len(removed) != len(wantRemoved) {
		t.Fatalf("removed ids = %v, want %v", removed, wantRemoved)
	}
	for index := range wantRemoved {
		if removed[index] != wantRemoved[index] {
			t.Fatalf("removed ids = %v, want %v", removed, wantRemoved)
		}
	}
}

package api

import (
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

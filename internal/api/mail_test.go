package api

import (
	"testing"
	"time"

	"github.com/morningstar-sudo/super-nginx/internal/store"
)

func TestCheckMailDomain(t *testing.T) {
	s := &store.State{
		Certs:       []store.Cert{{ID: 9, Name: "c", Type: "custom", Domains: []string{"webmail.example.com"}, ExpiresAt: time.Now().Add(time.Hour)}},
		MailDomains: []store.MailDomain{{ID: 1, Domain: "webmail.example.com", CertID: 9}},
	}
	if err := checkMailDomain(s, &store.MailDomain{Domain: "WEBMAIL.example.com", CertID: 9}); err == nil {
		t.Error("duplicate domain (case-insensitive) accepted")
	}
	if err := checkMailDomain(s, &store.MailDomain{ID: 1, Domain: "webmail.example.com", CertID: 9}); err != nil {
		t.Errorf("editing self flagged: %v", err)
	}
	if err := checkMailDomain(s, &store.MailDomain{Domain: "other.example.com"}); err == nil {
		t.Error("domain without cert accepted")
	}
	s.Certs[0].ExpiresAt = time.Now().Add(-time.Hour)
	if err := checkMailDomain(s, &store.MailDomain{ID: 1, Domain: "webmail.example.com", CertID: 9}); err == nil {
		t.Error("expired certificate accepted")
	}
}

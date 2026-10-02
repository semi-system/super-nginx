package api

import (
	"testing"

	"github.com/morningstar-sudo/super-nginx/internal/store"
)

func TestCheckMailDomain(t *testing.T) {
	s := &store.State{
		MailDomains:   []store.MailDomain{{ID: 1, Domain: "webmail.example.com", Backend: "mail"}},
		MailListeners: []store.MailListener{{ID: 2, Label: "imap", Port: 2993, Mode: "terminate", BackendPort: 993}},
	}
	if err := checkMailDomain(s, &store.MailDomain{Domain: "WEBMAIL.example.com", Backend: "mail"}); err == nil {
		t.Error("duplicate domain (case-insensitive) accepted")
	}
	if err := checkMailDomain(s, &store.MailDomain{ID: 1, Domain: "webmail.example.com", Backend: "mail2"}); err != nil {
		t.Errorf("editing self flagged: %v", err)
	}
	if err := checkMailDomain(s, &store.MailDomain{Domain: "other.example.com", Backend: "10.0.0.5"}); err != nil {
		t.Errorf("bare host rejected: %v", err)
	}
	s.MailListeners[0].BackendPort = 0
	if err := checkMailDomain(s, &store.MailDomain{Domain: "other.example.com", Backend: "10.0.0.5"}); err == nil {
		t.Error("bare host accepted while a listener has no backend port")
	}
	if err := checkMailDomain(s, &store.MailDomain{Domain: "other.example.com", Backend: "10.0.0.5:993"}); err != nil {
		t.Errorf("legacy host:port rejected: %v", err)
	}
}

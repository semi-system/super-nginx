package certs

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/go-acme/lego/v4/lego"
	"github.com/morningstar-sudo/super-nginx/internal/store"
)

func TestSharedHTTPProviderRoutesByDomainAndToken(t *testing.T) {
	provider := &sharedHTTPProvider{entries: map[httpChallengeKey]httpChallengeEntry{
		{domain: "one.example.com", token: "token-one"}: {keyAuth: "auth-one", refs: 1},
		{domain: "two.example.com", token: "token-two"}: {keyAuth: "auth-two", refs: 1},
	}}

	request := httptest.NewRequest(http.MethodGet, "http://one.example.com/.well-known/acme-challenge/token-one", nil)
	request.Host = "ONE.EXAMPLE.COM:80"
	response := httptest.NewRecorder()
	provider.ServeHTTP(response, request)
	if response.Code != http.StatusOK || response.Body.String() != "auth-one" {
		t.Fatalf("matching challenge response = %d %q", response.Code, response.Body.String())
	}

	request = httptest.NewRequest(http.MethodGet, "http://two.example.com/.well-known/acme-challenge/token-one", nil)
	response = httptest.NewRecorder()
	provider.ServeHTTP(response, request)
	if response.Code != http.StatusNotFound {
		t.Fatalf("cross-domain token returned status %d, want 404", response.Code)
	}
}

func TestRunPreparedIssuesUsesOneWorkerPerDomain(t *testing.T) {
	const total = 8
	items := make([]preparedIssue, total)
	for index := range items {
		items[index].cert = &store.Cert{ID: index + 1}
	}

	gate := make(chan struct{})
	started := make(chan struct{}, total)
	result := make(chan []error, 1)
	var active atomic.Int32
	var maximum atomic.Int32
	go func() {
		result <- runPreparedIssues(items, len(items), func(_ *lego.Client, _ *store.Cert) error {
			current := active.Add(1)
			for {
				previous := maximum.Load()
				if current <= previous || maximum.CompareAndSwap(previous, current) {
					break
				}
			}
			started <- struct{}{}
			<-gate
			active.Add(-1)
			return nil
		})
	}()

	for range total {
		select {
		case <-started:
		case <-time.After(time.Second):
			t.Fatal("worker pool did not start concurrent certificate issues")
		}
	}
	close(gate)

	select {
	case errs := <-result:
		for index, err := range errs {
			if err != nil {
				t.Fatalf("issue %d failed: %v", index, err)
			}
		}
	case <-time.After(time.Second):
		t.Fatal("worker pool did not finish")
	}
	if got := maximum.Load(); got != total {
		t.Fatalf("maximum concurrent issues = %d, want %d", got, total)
	}
}

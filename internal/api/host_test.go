package api

import (
	"strings"
	"testing"

	"github.com/morningstar-sudo/super-nginx/internal/store"
)

func validLoadBalancerHost() store.Host {
	return store.Host{
		Type: "load_balancer", Domains: []string{"lb.example.com"},
		Upstreams: []store.Upstream{
			{Address: "app-1:3000", Weight: 2, MaxFails: 1},
			{Address: "app-2:3000", Weight: 1, MaxFails: 1, Backup: true},
		},
	}
}

func TestCheckLoadBalancerHost(t *testing.T) {
	h := validLoadBalancerHost()
	if err := checkHost(&store.State{}, &h); err != nil {
		t.Fatalf("valid load balancer rejected: %v", err)
	}
	if h.UpstreamScheme != "http" || h.LoadBalance != "round_robin" {
		t.Fatalf("defaults not applied: scheme=%q method=%q", h.UpstreamScheme, h.LoadBalance)
	}
	for _, u := range h.Upstreams {
		if u.FailTimeout != "10s" {
			t.Fatalf("default fail_timeout not applied: %+v", u)
		}
	}
}

func TestCheckLoadBalancerHostRejectsInvalidBackends(t *testing.T) {
	tests := []struct {
		name string
		edit func(*store.Host)
		want string
	}{
		{"one backend", func(h *store.Host) { h.Upstreams = h.Upstreams[:1] }, "at least two"},
		{"duplicate", func(h *store.Host) { h.Upstreams[1].Address = h.Upstreams[0].Address }, "duplicated"},
		{"bad address", func(h *store.Host) { h.Upstreams[0].Address = "missing-port" }, "want host:port"},
		{"bad timeout", func(h *store.Host) { h.Upstreams[0].FailTimeout = "ten seconds" }, "nginx time"},
		{"ip hash backup", func(h *store.Host) { h.LoadBalance = "ip_hash" }, "cannot be used with ip_hash"},
		{"all backup", func(h *store.Host) { h.Upstreams[0].Backup = true }, "primary backend"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := validLoadBalancerHost()
			tt.edit(&h)
			err := checkHost(&store.State{}, &h)
			if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("want error containing %q, got %v", tt.want, err)
			}
		})
	}
}

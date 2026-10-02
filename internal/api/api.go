// Package api is the REST layer. Every mutation goes through one pipeline:
// lock store -> validate + mutate state -> engine.Apply (render, nginx -t,
// reload; auto-rollback) -> save. A failed apply reloads state from disk so
// memory never drifts from the last good config.
//
package api

import (
	"archive/zip"
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"

	"github.com/morningstar-sudo/super-nginx/internal/certs"
	"github.com/morningstar-sudo/super-nginx/internal/engine"
	"github.com/morningstar-sudo/super-nginx/internal/stats"
	"github.com/morningstar-sudo/super-nginx/internal/store"
	"github.com/morningstar-sudo/super-nginx/internal/supervisor"
)

type API struct {
	St  *store.Store
	Sup *supervisor.Supervisor
	// Stats is optional: nil simply means the stats endpoint reports no data.
	Stats *stats.Collector

	sesMu    sync.Mutex
	sessions map[string]session
}

type session struct {
	user string
	exp  time.Time
}

func New(st *store.Store, sup *supervisor.Supervisor) *API {
	return &API{St: st, Sup: sup, sessions: map[string]session{}}
}

// EnsureAdmin creates the admin user with a random password on first boot.
func EnsureAdmin(st *store.Store) {
	st.Mu.Lock()
	defer st.Mu.Unlock()
	if len(st.S.Users) > 0 {
		return
	}
	raw := make([]byte, 9)
	_, _ = rand.Read(raw)
	pw := hex.EncodeToString(raw)
	hash, _ := bcrypt.GenerateFromPassword([]byte(pw), bcrypt.DefaultCost)
	st.S.Users = append(st.S.Users, store.User{
		ID: st.S.NextID(), Username: "admin", Hash: string(hash), MustChange: true,
	})
	_ = st.Save()
	log.Printf("super-nginx: created admin user — username: admin  password: %s (change it in Settings)", pw)
}

// ---- plumbing ---------------------------------------------------------------

// nonNil keeps empty lists as [] in JSON — nil slices marshal to null and
// crash naive frontend .map calls.
func nonNil[T any](s []T) []T {
	if s == nil {
		return []T{}
	}
	return s
}

func jsonOut(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, code int, format string, a ...any) {
	jsonOut(w, code, map[string]string{"error": fmt.Sprintf(format, a...)})
}

func decode(r *http.Request, v any) error {
	dec := json.NewDecoder(r.Body)
	dec.DisallowUnknownFields()
	return dec.Decode(v)
}

func (a *API) audit(r *http.Request) {
	f, err := os.OpenFile("/data/logs/audit.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintf(f, "%s %s %s\n", time.Now().Format(time.RFC3339), r.Method, r.URL.Path)
}

// applyLocked re-renders + reloads with the store lock already held.
func (a *API) applyLocked() error {
	return engine.Apply(&a.St.S, a.Sup, true)
}

// mutate runs fn on state under the lock, then applies + saves; on apply
// failure state is rolled back and the nginx -t output returned to the client.
func (a *API) mutate(w http.ResponseWriter, r *http.Request, fn func(*store.State) error) {
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()
	if err := fn(&a.St.S); err != nil {
		fail(w, 400, "%s", err)
		return
	}
	if err := engine.Apply(&a.St.S, a.Sup, true); err != nil {
		_ = a.St.Reload()
		fail(w, 422, "config rejected: %s", err)
		return
	}
	if err := a.St.Save(); err != nil {
		fail(w, 500, "save state: %s", err)
		return
	}
	a.audit(r)
	jsonOut(w, 200, map[string]string{"status": "ok"})
}

// ---- validation -------------------------------------------------------------

var domainRe = regexp.MustCompile(`^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]*[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$|^[a-zA-Z0-9]([a-zA-Z0-9.-]*[a-zA-Z0-9])?$`)

func checkDomains(ds []string) error {
	if len(ds) == 0 {
		return fmt.Errorf("at least one domain required")
	}
	for _, d := range ds {
		if !domainRe.MatchString(d) {
			return fmt.Errorf("invalid domain %q", d)
		}
	}
	return nil
}

func checkHostPort(s string) error {
	host, port, err := net.SplitHostPort(s)
	if err != nil || host == "" {
		return fmt.Errorf("invalid backend %q (want host:port)", s)
	}
	if p, err := strconv.Atoi(port); err != nil || p < 1 || p > 65535 {
		return fmt.Errorf("invalid port in %q", s)
	}
	return nil
}

func checkPort(p int) error {
	if p < 1025 || p > 65535 {
		return fmt.Errorf("port must be 1025-65535 (nonroot cannot bind <1024)")
	}
	return nil
}

// checkDefaultSite validates the catch-all site fields. An empty action means
// "close", so old state files stay valid.
func checkDefaultSite(set *store.Settings) error {
	switch set.DefaultAction {
	case "", "close", "404":
	case "redirect":
		u, err := url.Parse(set.DefaultTarget)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("default site redirect target must be an absolute URL")
		}
	case "html":
		if strings.TrimSpace(set.DefaultHTML) == "" {
			return fmt.Errorf("default site HTML page is empty")
		}
	default:
		return fmt.Errorf("default site action must be close, 404, redirect or html")
	}
	return nil
}

func checkHost(s *store.State, h *store.Host) error {
	if err := checkDomains(h.Domains); err != nil {
		return err
	}
	switch h.Type {
	case "proxy":
		u, err := url.Parse(h.Target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("proxy target must be http(s)://host[:port]")
		}
	case "redirect":
		u, err := url.Parse(h.Target)
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" {
			return fmt.Errorf("redirect target must be an absolute URL")
		}
	case "static":
		if h.Target == "" || strings.Contains(h.Target, "..") || strings.HasPrefix(h.Target, "/") {
			return fmt.Errorf("static target must be a directory name under /data/www")
		}
	default:
		return fmt.Errorf("type must be proxy, redirect or static")
	}
	if h.CertID != 0 && s.CertByID(h.CertID) == nil {
		return fmt.Errorf("cert %d not found", h.CertID)
	}
	if h.CertID == 0 && h.ForceSSL {
		return fmt.Errorf("force_ssl requires a certificate")
	}
	if h.AccessListID != 0 && s.AccessListByID(h.AccessListID) == nil {
		return fmt.Errorf("access list %d not found", h.AccessListID)
	}
	if h.Cache && h.CacheTime != "" && !nginxTime.MatchString(h.CacheTime) {
		return fmt.Errorf("cache time %q must be an nginx time (e.g. 30s, 10m, 1h)", h.CacheTime)
	}
	if h.Directives == nil {
		h.Directives = []store.HostDirective{} // store [] not null in the DB
	}
	for _, d := range h.Directives {
		if !directiveKey.MatchString(d.Key) {
			return fmt.Errorf("invalid directive name %q", d.Key)
		}
		if strings.TrimSpace(d.Value) == "" {
			return fmt.Errorf("directive %q needs a value", d.Key)
		}
		// keep it a single simple directive; complex nginx goes in a snippet
		if strings.ContainsAny(d.Value, ";{}\n\r") {
			return fmt.Errorf("directive %q value must not contain ; { } or newlines — use a server snippet instead", d.Key)
		}
	}
	return nil
}

// nginx time: digits + optional unit (ms/s/m/h/d/w/M/y), e.g. 10m, 1h, 60s.
var nginxTime = regexp.MustCompile(`^[0-9]+(ms|s|m|h|d|w|M|y)?$`)

// directiveKey: a bare nginx directive name (letters, digits, underscore).
var directiveKey = regexp.MustCompile(`^[a-zA-Z0-9_]+$`)

func checkListener(s *store.State, l *store.MailListener) error {
	if err := checkPort(l.Port); err != nil {
		return err
	}
	if l.Mode != "terminate" && l.Mode != "passthrough" {
		return fmt.Errorf("mode must be terminate or passthrough")
	}
	if l.DefaultBackend != "" {
		if err := checkHostPort(l.DefaultBackend); err != nil {
			return err
		}
	}
	if sniRouted(l) && (l.BackendPort < 1 || l.BackendPort > 65535) {
		return fmt.Errorf("backend port must be 1-65535 (port mail domains are forwarded to)")
	}
	if l.Mode == "terminate" {
		ok := false
		for _, d := range s.MailDomains {
			if s.CertByID(d.CertID) != nil {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("terminate mode needs at least one mail domain with a certificate")
		}
	}
	return nil
}

// ---- sessions ---------------------------------------------------------------

const cookieName = "sn_session"

func (a *API) newSession(user string) string {
	raw := make([]byte, 32)
	_, _ = rand.Read(raw)
	tok := hex.EncodeToString(raw)
	a.sesMu.Lock()
	a.sessions[tok] = session{user: user, exp: time.Now().Add(24 * time.Hour)}
	a.sesMu.Unlock()
	return tok
}

func (a *API) sessionUser(r *http.Request) string {
	tok := ""
	if c, err := r.Cookie(cookieName); err == nil {
		tok = c.Value
	} else if h := r.Header.Get("Authorization"); strings.HasPrefix(h, "Bearer ") {
		tok = strings.TrimPrefix(h, "Bearer ")
	}
	if tok == "" {
		return ""
	}
	a.sesMu.Lock()
	defer a.sesMu.Unlock()
	s, ok := a.sessions[tok]
	if !ok || time.Now().After(s.exp) {
		delete(a.sessions, tok)
		return ""
	}
	return s.user
}

func (a *API) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a.sessionUser(r) == "" {
			fail(w, 401, "unauthorized")
			return
		}
		next(w, r)
	}
}

// ---- routes -----------------------------------------------------------------

func (a *API) Register(mux *http.ServeMux) {
	mux.HandleFunc("GET /api/v1/health", a.health)
	mux.HandleFunc("POST /api/v1/login", a.login)

	auth := func(p string, h http.HandlerFunc) { mux.HandleFunc(p, a.requireAuth(h)) }
	auth("POST /api/v1/logout", a.logout)
	auth("GET /api/v1/me", a.me)
	auth("POST /api/v1/password", a.password)
	auth("GET /api/v1/summary", a.summary)
	auth("GET /api/v1/nginx/config", a.nginxConfig)
	auth("GET /api/v1/settings", a.getSettings)
	auth("PUT /api/v1/settings", a.putSettings)

	auth("GET /api/v1/hosts", a.listHosts)
	auth("POST /api/v1/hosts", a.createHost)
	auth("PUT /api/v1/hosts/{id}", a.updateHost)
	auth("DELETE /api/v1/hosts/{id}", a.deleteHost)

	auth("GET /api/v1/certs", a.listCerts)
	auth("POST /api/v1/certs/custom", a.createCustomCert)
	auth("POST /api/v1/certs/acme", a.createACMECert)
	auth("POST /api/v1/certs/{id}/renew", a.renewCert)
	auth("GET /api/v1/certs/{id}/download", a.downloadCert)
	auth("DELETE /api/v1/certs/{id}", a.deleteCert)

	auth("GET /api/v1/mail/listeners", a.listListeners)
	auth("POST /api/v1/mail/listeners", a.createListener)
	auth("PUT /api/v1/mail/listeners/{id}", a.updateListener)
	auth("DELETE /api/v1/mail/listeners/{id}", a.deleteListener)

	auth("GET /api/v1/mail/domains", a.listMailDomains)
	auth("POST /api/v1/mail/domains", a.createMailDomain)
	auth("PUT /api/v1/mail/domains/{id}", a.updateMailDomain)
	auth("DELETE /api/v1/mail/domains/{id}", a.deleteMailDomain)

	auth("GET /api/v1/streams", a.listStreams)
	auth("POST /api/v1/streams", a.createStream)
	auth("PUT /api/v1/streams/{id}", a.updateStream)
	auth("DELETE /api/v1/streams/{id}", a.deleteStream)

	auth("GET /api/v1/accesslists", a.listAccessLists)
	auth("POST /api/v1/accesslists", a.createAccessList)
	auth("PUT /api/v1/accesslists/{id}", a.updateAccessList)
	auth("DELETE /api/v1/accesslists/{id}", a.deleteAccessList)

	auth("POST /api/v1/backup", a.backup)
	auth("POST /api/v1/restore", a.restore)
	auth("GET /api/v1/audit", a.auditLog)
	auth("GET /api/v1/metrics", a.metrics)
	auth("GET /api/v1/stats", a.hostStats)
}

func pathID(r *http.Request) (int, error) {
	return strconv.Atoi(r.PathValue("id"))
}

// ---- auth endpoints ---------------------------------------------------------

// setSessionCookie writes (maxAge > 0) or clears (maxAge < 0) the session cookie.
// Secure is decided per request rather than hardcoded: nginx may terminate TLS in
// front of us, but the UI is just as often published as plain http on :8181 (see
// docker-compose.yml), and a hardcoded Secure would silently break login there —
// the browser would drop the cookie and the user would see an unexplained login
// loop. Hardcode Secure: true once plain-HTTP access stops being supported.
func setSessionCookie(w http.ResponseWriter, r *http.Request, val string, maxAge int) {
	https := r.TLS != nil || strings.EqualFold(r.Header.Get("X-Forwarded-Proto"), "https")
	// nosemgrep: go.lang.security.audit.net.cookie-missing-secure.cookie-missing-secure
	http.SetCookie(w, &http.Cookie{
		Name: cookieName, Value: val, Path: "/", HttpOnly: true,
		SameSite: http.SameSiteLaxMode, Secure: https, MaxAge: maxAge,
	})
}

func (a *API) login(w http.ResponseWriter, r *http.Request) {
	var in struct{ Username, Password string }
	if err := decode(r, &in); err != nil {
		fail(w, 400, "bad request")
		return
	}
	a.St.Mu.Lock()
	var user *store.User
	for i := range a.St.S.Users {
		if a.St.S.Users[i].Username == in.Username {
			user = &a.St.S.Users[i]
		}
	}
	a.St.Mu.Unlock()
	if user == nil || bcrypt.CompareHashAndPassword([]byte(user.Hash), []byte(in.Password)) != nil {
		time.Sleep(300 * time.Millisecond) // blunt brute-force damper
		fail(w, 401, "invalid credentials")
		return
	}
	tok := a.newSession(user.Username)
	setSessionCookie(w, r, tok, 86400)
	jsonOut(w, 200, map[string]any{"token": tok, "must_change": user.MustChange})
}

func (a *API) logout(w http.ResponseWriter, r *http.Request) {
	if c, err := r.Cookie(cookieName); err == nil {
		a.sesMu.Lock()
		delete(a.sessions, c.Value)
		a.sesMu.Unlock()
	}
	setSessionCookie(w, r, "", -1)
	jsonOut(w, 200, map[string]string{"status": "ok"})
}

func (a *API) me(w http.ResponseWriter, r *http.Request) {
	user := a.sessionUser(r)
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()
	for _, u := range a.St.S.Users {
		if u.Username == user {
			jsonOut(w, 200, map[string]any{"username": u.Username, "must_change": u.MustChange})
			return
		}
	}
	fail(w, 401, "unauthorized")
}

func (a *API) password(w http.ResponseWriter, r *http.Request) {
	var in struct{ Old, New string }
	if err := decode(r, &in); err != nil || len(in.New) < 8 {
		fail(w, 400, "new password must be at least 8 characters")
		return
	}
	user := a.sessionUser(r)
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()
	for i := range a.St.S.Users {
		u := &a.St.S.Users[i]
		if u.Username != user {
			continue
		}
		if bcrypt.CompareHashAndPassword([]byte(u.Hash), []byte(in.Old)) != nil {
			fail(w, 401, "current password incorrect")
			return
		}
		hash, _ := bcrypt.GenerateFromPassword([]byte(in.New), bcrypt.DefaultCost)
		u.Hash = string(hash)
		u.MustChange = false
		_ = a.St.Save()
		jsonOut(w, 200, map[string]string{"status": "ok"})
		return
	}
	fail(w, 401, "unauthorized")
}

// ---- info endpoints ---------------------------------------------------------

func (a *API) health(w http.ResponseWriter, _ *http.Request) {
	jsonOut(w, 200, map[string]any{
		"status": "ok",
		"nginx":  map[string]any{"running": a.Sup.Running.Load(), "pid": a.Sup.Pid()},
	})
}

func (a *API) summary(w http.ResponseWriter, _ *http.Request) {
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()
	s := &a.St.S
	type expiring struct {
		Name    string    `json:"name"`
		Expires time.Time `json:"expires"`
		Error   string    `json:"error,omitempty"`
	}
	certs := []expiring{}
	for _, c := range s.Certs {
		certs = append(certs, expiring{c.Name, c.ExpiresAt, c.LastError})
	}
	jsonOut(w, 200, map[string]any{
		"nginx":     map[string]any{"running": a.Sup.Running.Load(), "pid": a.Sup.Pid()},
		"hosts":     len(s.Hosts),
		"streams":   len(s.Streams),
		"listeners": len(s.MailListeners),
		"certs":     certs,
	})
}

func (a *API) nginxConfig(w http.ResponseWriter, _ *http.Request) {
	jsonOut(w, 200, engine.RenderedFiles())
}

func (a *API) getSettings(w http.ResponseWriter, _ *http.Request) {
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()
	jsonOut(w, 200, a.St.S.Settings)
}

// putSettings goes through mutate because the default-site fields are rendered
// into nginx config: saving them without a re-render would leave the catch-all
// server stale until some unrelated change happened to trigger an apply.
func (a *API) putSettings(w http.ResponseWriter, r *http.Request) {
	var in store.Settings
	if err := decode(r, &in); err != nil {
		fail(w, 400, "bad request")
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		if err := checkDefaultSite(&in); err != nil {
			return err
		}
		s.Settings = in
		return nil
	})
}

// ---- hosts ------------------------------------------------------------------

func (a *API) listHosts(w http.ResponseWriter, _ *http.Request) {
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()
	// normalize nil directives to [] so the UI (which maps over them) never
	// sees null for hosts saved before the field existed
	hosts := make([]store.Host, len(a.St.S.Hosts))
	copy(hosts, a.St.S.Hosts)
	for i := range hosts {
		if hosts[i].Directives == nil {
			hosts[i].Directives = []store.HostDirective{}
		}
	}
	jsonOut(w, 200, nonNil(hosts))
}

func (a *API) createHost(w http.ResponseWriter, r *http.Request) {
	var h store.Host
	if err := decode(r, &h); err != nil {
		fail(w, 400, "bad request: %s", err)
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		if err := checkHost(s, &h); err != nil {
			return err
		}
		h.ID = s.NextID()
		s.Hosts = append(s.Hosts, h)
		return nil
	})
}

func (a *API) updateHost(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	var h store.Host
	if err := decode(r, &h); err != nil {
		fail(w, 400, "bad request: %s", err)
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		for i := range s.Hosts {
			if s.Hosts[i].ID == id {
				if err := checkHost(s, &h); err != nil {
					return err
				}
				h.ID = id
				s.Hosts[i] = h
				return nil
			}
		}
		return fmt.Errorf("host %d not found", id)
	})
}

func (a *API) deleteHost(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		for i := range s.Hosts {
			if s.Hosts[i].ID == id {
				s.Hosts = append(s.Hosts[:i], s.Hosts[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("host %d not found", id)
	})
}

// ---- certs ------------------------------------------------------------------

func (a *API) listCerts(w http.ResponseWriter, _ *http.Request) {
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()
	jsonOut(w, 200, nonNil(a.St.S.Certs))
}

func (a *API) createCustomCert(w http.ResponseWriter, r *http.Request) {
	var in struct{ Name, Cert, Key string }
	if err := decode(r, &in); err != nil || in.Name == "" {
		fail(w, 400, "name, cert and key required")
		return
	}
	domains, expires, err := certs.ParseCustom([]byte(in.Cert), []byte(in.Key))
	if err != nil {
		fail(w, 400, "%s", err)
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		c := store.Cert{ID: s.NextID(), Name: in.Name, Type: "custom", Domains: domains, ExpiresAt: expires}
		if err := certs.WriteFiles(c.ID, []byte(in.Cert), []byte(in.Key)); err != nil {
			return err
		}
		s.Certs = append(s.Certs, c)
		return nil
	})
}

func (a *API) createACMECert(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Name        string            `json:"name"`
		Domains     []string          `json:"domains"`
		Challenge   string            `json:"challenge"`
		DNSProvider string            `json:"dns_provider"`
		DNSEnv      map[string]string `json:"dns_env"`
	}
	if err := decode(r, &in); err != nil || in.Name == "" {
		fail(w, 400, "bad request")
		return
	}
	if err := checkDomains(in.Domains); err != nil {
		fail(w, 400, "%s", err)
		return
	}
	if in.Challenge != "dns" {
		in.Challenge = "http"
		for _, d := range in.Domains {
			if strings.HasPrefix(d, "*.") {
				fail(w, 400, "wildcard domains require the dns challenge")
				return
			}
		}
	}
	a.mutate(w, r, func(s *store.State) error {
		c := store.Cert{
			ID: s.NextID(), Name: in.Name, Type: "acme", Domains: in.Domains,
			Challenge: in.Challenge, DNSProvider: in.DNSProvider, DNSEnv: in.DNSEnv,
		}
		// issue synchronously — the client sees the ACME error directly
		if err := certs.Issue(&c, s.Settings); err != nil {
			return fmt.Errorf("ACME issue failed: %w", err)
		}
		s.Certs = append(s.Certs, c)
		return nil
	})
}

func (a *API) renewCert(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		c := s.CertByID(id)
		if c == nil {
			return fmt.Errorf("cert %d not found", id)
		}
		if c.Type != "acme" {
			return fmt.Errorf("only acme certs can be renewed")
		}
		if err := certs.Issue(c, s.Settings); err != nil {
			c.LastError = err.Error()
			return fmt.Errorf("renew failed: %w", err)
		}
		return nil
	})
}

// downloadCert streams a zip of fullchain.pem + privkey.pem for the cert.
func (a *API) downloadCert(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	a.St.Mu.Lock()
	c := a.St.S.CertByID(id)
	a.St.Mu.Unlock()
	if c == nil {
		fail(w, 404, "cert %d not found", id)
		return
	}
	fullchain, privkey := engine.CertPath(id)
	fc, err1 := os.ReadFile(fullchain)
	pk, err2 := os.ReadFile(privkey)
	if err1 != nil || err2 != nil {
		fail(w, 404, "cert files not found on disk")
		return
	}
	var buf bytes.Buffer
	zw := zip.NewWriter(&buf)
	for _, f := range []struct {
		name string
		data []byte
	}{{"fullchain.pem", fc}, {"privkey.pem", pk}} {
		fw, err := zw.Create(f.name)
		if err == nil {
			_, _ = fw.Write(f.data)
		}
	}
	if err := zw.Close(); err != nil {
		fail(w, 500, "%s", err)
		return
	}
	fname := safeFilename(c.Name)
	w.Header().Set("Content-Type", "application/zip")
	w.Header().Set("Content-Disposition", fmt.Sprintf(`attachment; filename=%q`, fname+".zip"))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// zip bytes, not markup — Content-Type is explicit and sniffing is off.
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	_, _ = w.Write(buf.Bytes())
}

// safeFilename keeps letters/digits/-._; everything else becomes _.
func safeFilename(s string) string {
	if s == "" {
		return "cert"
	}
	return strings.Map(func(r rune) rune {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '-', r == '_', r == '.':
			return r
		default:
			return '_'
		}
	}, s)
}

func (a *API) deleteCert(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		for _, h := range s.Hosts {
			if h.CertID == id {
				return fmt.Errorf("cert in use by host %d (%s)", h.ID, strings.Join(h.Domains, " "))
			}
		}
		for _, d := range s.MailDomains {
			if d.CertID == id {
				return fmt.Errorf("cert in use by mail domain %s", d.Domain)
			}
		}
		for i := range s.Certs {
			if s.Certs[i].ID == id {
				s.Certs = append(s.Certs[:i], s.Certs[i+1:]...)
				certs.RemoveFiles(id)
				return nil
			}
		}
		return fmt.Errorf("cert %d not found", id)
	})
}

// ---- mail listeners ---------------------------------------------------------

func (a *API) listListeners(w http.ResponseWriter, _ *http.Request) {
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()
	jsonOut(w, 200, nonNil(a.St.S.MailListeners))
}

func (a *API) createListener(w http.ResponseWriter, r *http.Request) {
	var l store.MailListener
	if err := decode(r, &l); err != nil {
		fail(w, 400, "bad request: %s", err)
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		if err := checkListener(s, &l); err != nil {
			return err
		}
		l.ID = s.NextID()
		s.MailListeners = append(s.MailListeners, l)
		return nil
	})
}

func (a *API) updateListener(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	var l store.MailListener
	if err := decode(r, &l); err != nil {
		fail(w, 400, "bad request: %s", err)
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		for i := range s.MailListeners {
			if s.MailListeners[i].ID == id {
				if err := checkListener(s, &l); err != nil {
					return err
				}
				l.ID = id
				s.MailListeners[i] = l
				return nil
			}
		}
		return fmt.Errorf("listener %d not found", id)
	})
}

func (a *API) deleteListener(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		for i := range s.MailListeners {
			if s.MailListeners[i].ID == id {
				s.MailListeners = append(s.MailListeners[:i], s.MailListeners[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("listener %d not found", id)
	})
}

// ---- mail domains -----------------------------------------------------------

func (a *API) listMailDomains(w http.ResponseWriter, _ *http.Request) {
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()
	jsonOut(w, 200, nonNil(a.St.S.MailDomains))
}

// sniRouted: listener forwards per mail domain (SNI map), so it needs BackendPort.
func sniRouted(l *store.MailListener) bool {
	return l.Mode == "terminate" || (l.Mode == "passthrough" && l.SNIRoute)
}

// checkMailDomain: backend is a bare host (port comes from each listener) or
// legacy host:port; one entry per domain since every listener routes it.
func checkMailDomain(s *store.State, d *store.MailDomain) error {
	if !domainRe.MatchString(d.Domain) {
		return fmt.Errorf("invalid domain %q", d.Domain)
	}
	for _, o := range s.MailDomains {
		if o.ID != d.ID && strings.EqualFold(o.Domain, d.Domain) {
			return fmt.Errorf("mail domain %q already exists", d.Domain)
		}
	}
	if strings.Contains(d.Backend, ":") {
		if err := checkHostPort(d.Backend); err != nil {
			return err
		}
	} else {
		if !domainRe.MatchString(d.Backend) {
			return fmt.Errorf("invalid backend host %q", d.Backend)
		}
		for i := range s.MailListeners {
			if l := &s.MailListeners[i]; sniRouted(l) && l.BackendPort == 0 {
				return fmt.Errorf("listener %q (port %d) has no backend port; set it or use host:port", l.Label, l.Port)
			}
		}
	}
	if d.CertID != 0 && s.CertByID(d.CertID) == nil {
		return fmt.Errorf("cert %d not found", d.CertID)
	}
	return nil
}

func (a *API) createMailDomain(w http.ResponseWriter, r *http.Request) {
	var d store.MailDomain
	if err := decode(r, &d); err != nil {
		fail(w, 400, "bad request: %s", err)
		return
	}
	d.ID = 0 // a client-sent id must not dodge the duplicate check
	a.mutate(w, r, func(s *store.State) error {
		if err := checkMailDomain(s, &d); err != nil {
			return err
		}
		d.ID = s.NextID()
		s.MailDomains = append(s.MailDomains, d)
		return nil
	})
}

func (a *API) updateMailDomain(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	var d store.MailDomain
	if err := decode(r, &d); err != nil {
		fail(w, 400, "bad request: %s", err)
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		for i := range s.MailDomains {
			if s.MailDomains[i].ID == id {
				d.ID = id // before check, so the entry isn't its own duplicate
				if err := checkMailDomain(s, &d); err != nil {
					return err
				}
				s.MailDomains[i] = d
				return nil
			}
		}
		return fmt.Errorf("mail domain %d not found", id)
	})
}

func (a *API) deleteMailDomain(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		for i := range s.MailDomains {
			if s.MailDomains[i].ID == id {
				s.MailDomains = append(s.MailDomains[:i], s.MailDomains[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("mail domain %d not found", id)
	})
}

// ---- streams ----------------------------------------------------------------

func (a *API) listStreams(w http.ResponseWriter, _ *http.Request) {
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()
	jsonOut(w, 200, nonNil(a.St.S.Streams))
}

func checkStream(r *store.StreamRule) error {
	if err := checkPort(r.Port); err != nil {
		return err
	}
	return checkHostPort(r.Backend)
}

func (a *API) createStream(w http.ResponseWriter, r *http.Request) {
	var st store.StreamRule
	if err := decode(r, &st); err != nil {
		fail(w, 400, "bad request: %s", err)
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		if err := checkStream(&st); err != nil {
			return err
		}
		st.ID = s.NextID()
		s.Streams = append(s.Streams, st)
		return nil
	})
}

func (a *API) updateStream(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	var st store.StreamRule
	if err := decode(r, &st); err != nil {
		fail(w, 400, "bad request: %s", err)
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		for i := range s.Streams {
			if s.Streams[i].ID == id {
				if err := checkStream(&st); err != nil {
					return err
				}
				st.ID = id
				s.Streams[i] = st
				return nil
			}
		}
		return fmt.Errorf("stream %d not found", id)
	})
}

func (a *API) deleteStream(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		for i := range s.Streams {
			if s.Streams[i].ID == id {
				s.Streams = append(s.Streams[:i], s.Streams[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("stream %d not found", id)
	})
}

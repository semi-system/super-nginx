// Package store holds all persistent state as a single JSON file on /data.
// ponytail: JSON file instead of SQLite — state is tiny (tens of records),
// single process, mutations rare; switch to SQLite if concurrency or scale
// ever demands it.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type User struct {
	ID         int    `json:"id"`
	Username   string `json:"username"`
	Hash       string `json:"hash"`
	MustChange bool   `json:"must_change"`
}

type Host struct {
	ID              int             `json:"id"`
	Type            string          `json:"type"` // proxy | redirect | static
	Domains         []string        `json:"domains"`
	Target          string          `json:"target"` // proxy: http://host:port, redirect: URL prefix, static: dir under /data/www
	CertID          int             `json:"cert_id"`
	ForceSSL        bool            `json:"force_ssl"`
	HTTP2           bool            `json:"http2"`
	HSTS            bool            `json:"hsts"`
	Websocket       bool            `json:"websocket"`
	WAF             bool            `json:"waf"`
	AccessListID    int             `json:"access_list_id"`
	Cache           bool            `json:"cache"`      // proxy: enable proxy_cache
	CacheTime       string          `json:"cache_time"` // nginx time for 200/302 (e.g. 10m); default 10m
	Directives      []HostDirective `json:"directives"` // extra server-context directives (client_max_body_size, ...)
	ServerSnippet   string          `json:"server_snippet"`
	LocationSnippet string          `json:"location_snippet"`
	Enabled         bool            `json:"enabled"`
}

// HostDirective is one nginx directive rendered in the server context,
// e.g. {Key: "client_max_body_size", Value: "100m"} -> `client_max_body_size 100m;`.
type HostDirective struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

type Cert struct {
	ID          int               `json:"id"`
	Name        string            `json:"name"`
	Type        string            `json:"type"` // custom | acme
	Domains     []string          `json:"domains"`
	Challenge   string            `json:"challenge,omitempty"`    // http | dns (acme only)
	DNSProvider string            `json:"dns_provider,omitempty"` // lego provider name (dns challenge)
	DNSEnv      map[string]string `json:"dns_env,omitempty"`      // provider credentials (env style)
	ExpiresAt   time.Time         `json:"expires_at"`
	LastError   string            `json:"last_error,omitempty"`
}

type MailListener struct {
	ID             int    `json:"id"`
	Label          string `json:"label"`           // smtp | imap | pop3 — display only, stream is protocol-agnostic
	Port           int    `json:"port"`            // container port >1024
	Mode           string `json:"mode"`            // terminate | passthrough
	DefaultBackend string `json:"default_backend"` // host:port, used when client sends no SNI
	SNIRoute       bool   `json:"sni_route"`       // passthrough: route by SNI via ssl_preread
	ProxySSL       bool   `json:"proxy_ssl"`       // terminate: re-encrypt to backend (backend on TLS port)
	Enabled        bool   `json:"enabled"`
}

type MailDomain struct {
	ID      int    `json:"id"`
	Domain  string `json:"domain"`
	Backend string `json:"backend"` // host:port
	CertID  int    `json:"cert_id"` // used by terminate listeners (SNI-selected)
}

type StreamRule struct {
	ID      int    `json:"id"`
	Port    int    `json:"port"`
	UDP     bool   `json:"udp"`
	Backend string `json:"backend"` // host:port
	Enabled bool   `json:"enabled"`
}

type AccessUser struct {
	Username string `json:"username"`
	Hash     string `json:"hash"` // htpasswd {SHA} entry value
}

type AccessList struct {
	ID      int          `json:"id"`
	Name    string       `json:"name"`
	Satisfy string       `json:"satisfy"` // any | all (nginx satisfy)
	Users   []AccessUser `json:"users"`
	Allow   []string     `json:"allow"` // CIDRs / IPs
	Deny    []string     `json:"deny"`
}

type Settings struct {
	ACMEEmail   string `json:"acme_email"`
	ACMEStaging bool   `json:"acme_staging"`
}

type State struct {
	Seq           int            `json:"seq"`
	Users         []User         `json:"users"`
	Hosts         []Host         `json:"hosts"`
	Certs         []Cert         `json:"certs"`
	MailListeners []MailListener `json:"mail_listeners"`
	MailDomains   []MailDomain   `json:"mail_domains"`
	Streams       []StreamRule   `json:"streams"`
	AccessLists   []AccessList   `json:"access_lists"`
	Settings      Settings       `json:"settings"`
}

func (s *State) AccessListByID(id int) *AccessList {
	for i := range s.AccessLists {
		if s.AccessLists[i].ID == id {
			return &s.AccessLists[i]
		}
	}
	return nil
}

func (s *State) NextID() int {
	s.Seq++
	return s.Seq
}

func (s *State) CertByID(id int) *Cert {
	for i := range s.Certs {
		if s.Certs[i].ID == id {
			return &s.Certs[i]
		}
	}
	return nil
}

// Store serializes access to State. Handlers must hold Mu across
// read-modify-apply-save so config renders never interleave.
type Store struct {
	Mu   sync.Mutex
	path string
	S    State
}

func Load(path string) (*Store, error) {
	st := &Store{path: path}
	raw, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return st, nil
	case err != nil:
		return nil, err
	}
	if err := json.Unmarshal(raw, &st.S); err != nil {
		return nil, fmt.Errorf("corrupt state file %s: %w", path, err)
	}
	return st, nil
}

// Save writes atomically (temp file + rename). Caller holds Mu.
func (st *Store) Save() error {
	raw, err := json.MarshalIndent(&st.S, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(st.path), 0o755); err != nil {
		return err
	}
	tmp := st.path + ".tmp"
	if err := os.WriteFile(tmp, raw, 0o600); err != nil {
		return err
	}
	return os.Rename(tmp, st.path)
}

// Reload discards in-memory state and re-reads the file (rollback after a
// failed apply). Caller holds Mu.
func (st *Store) Reload() error {
	raw, err := os.ReadFile(st.path)
	if errors.Is(err, os.ErrNotExist) {
		st.S = State{}
		return nil
	}
	if err != nil {
		return err
	}
	var s State
	if err := json.Unmarshal(raw, &s); err != nil {
		return err
	}
	st.S = s
	return nil
}

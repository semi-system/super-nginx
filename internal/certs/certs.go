// Package certs manages certificate material under /data/certs: custom
// uploads and ACME (Let's Encrypt) issue/renew via the embedded lego client —
// no certbot, no shell, works on distroless.
package certs

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/go-acme/lego/v4/certcrypto"
	"github.com/go-acme/lego/v4/certificate"
	"github.com/go-acme/lego/v4/challenge/http01"
	"github.com/go-acme/lego/v4/lego"
	"github.com/go-acme/lego/v4/providers/dns"
	"github.com/go-acme/lego/v4/registration"

	"github.com/morningstar-sudo/super-nginx/internal/engine"
	"github.com/morningstar-sudo/super-nginx/internal/store"
)

const acmeDir = "/data/acme"

// WriteFiles stores PEM material for a cert id.
func WriteFiles(id int, fullchain, privkey []byte) error {
	dir := filepath.Join(engine.CertsDir, fmt.Sprint(id))
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dir, "fullchain.pem"), fullchain, 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "privkey.pem"), privkey, 0o600)
}

func RemoveFiles(id int) {
	_ = os.RemoveAll(filepath.Join(engine.CertsDir, fmt.Sprint(id)))
}

// ParseCustom validates an uploaded cert/key pair and extracts SANs + expiry.
func ParseCustom(certPEM, keyPEM []byte) (domains []string, expires time.Time, err error) {
	if _, err = tls.X509KeyPair(certPEM, keyPEM); err != nil {
		return nil, time.Time{}, fmt.Errorf("cert/key pair invalid: %w", err)
	}
	block, _ := pem.Decode(certPEM)
	if block == nil {
		return nil, time.Time{}, fmt.Errorf("no PEM block in certificate")
	}
	leaf, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, time.Time{}, err
	}
	domains = leaf.DNSNames
	if len(domains) == 0 && leaf.Subject.CommonName != "" {
		domains = []string{leaf.Subject.CommonName}
	}
	if time.Now().After(leaf.NotAfter) {
		return nil, time.Time{}, fmt.Errorf("certificate expired %s", leaf.NotAfter.Format(time.RFC3339))
	}
	return domains, leaf.NotAfter, nil
}

// ---- ACME account -----------------------------------------------------------

type acmeUser struct {
	Email string                 `json:"email"`
	Reg   *registration.Resource `json:"registration"`
	key   crypto.PrivateKey
}

func (u *acmeUser) GetEmail() string                        { return u.Email }
func (u *acmeUser) GetRegistration() *registration.Resource { return u.Reg }
func (u *acmeUser) GetPrivateKey() crypto.PrivateKey        { return u.key }

// acmeMu keeps normal issuance/renewal mutually exclusive with an isolated
// batch. IssueBatch holds it once while its prepared requests run in parallel.
var acmeMu sync.Mutex

type httpChallengeKey struct {
	domain string
	token  string
}

type httpChallengeEntry struct {
	keyAuth string
	refs    int
}

// sharedHTTPProvider serves every in-flight HTTP-01 token from one listener.
// A separate lego ProviderServer per certificate cannot run concurrently
// because every instance tries to bind the same internal ACME port.
type sharedHTTPProvider struct {
	once     sync.Once
	startErr error

	mu      sync.RWMutex
	entries map[httpChallengeKey]httpChallengeEntry
}

var batchHTTPProvider = &sharedHTTPProvider{entries: make(map[httpChallengeKey]httpChallengeEntry)}

func (p *sharedHTTPProvider) start() {
	listener, err := net.Listen("tcp", net.JoinHostPort("127.0.0.1", engine.ACMEPort))
	if err != nil {
		p.startErr = fmt.Errorf("could not start shared HTTP challenge server: %w", err)
		return
	}
	go func() {
		if err := http.Serve(listener, p); err != nil && err != http.ErrServerClosed {
			log.Printf("certs: shared HTTP challenge server: %v", err)
		}
	}()
}

func (p *sharedHTTPProvider) Present(domain, token, keyAuth string) error {
	if http01.ChallengePath(token) != http01.PathPrefix+token {
		return fmt.Errorf("invalid HTTP-01 challenge token")
	}
	p.once.Do(p.start)
	if p.startErr != nil {
		return p.startErr
	}
	key := httpChallengeKey{domain: strings.TrimSuffix(strings.ToLower(domain), "."), token: token}
	p.mu.Lock()
	entry := p.entries[key]
	entry.keyAuth = keyAuth
	entry.refs++
	p.entries[key] = entry
	p.mu.Unlock()
	return nil
}

func (p *sharedHTTPProvider) CleanUp(domain, token, _ string) error {
	key := httpChallengeKey{domain: strings.TrimSuffix(strings.ToLower(domain), "."), token: token}
	p.mu.Lock()
	entry, ok := p.entries[key]
	if ok && entry.refs > 1 {
		entry.refs--
		p.entries[key] = entry
	} else {
		delete(p.entries, key)
	}
	p.mu.Unlock()
	return nil
}

func (p *sharedHTTPProvider) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet || !strings.HasPrefix(r.URL.Path, http01.PathPrefix) {
		http.NotFound(w, r)
		return
	}
	token := strings.TrimPrefix(r.URL.Path, http01.PathPrefix)
	if token == "" || strings.Contains(token, "/") {
		http.NotFound(w, r)
		return
	}
	host := r.Host
	if parsed, _, err := net.SplitHostPort(host); err == nil {
		host = parsed
	}
	p.mu.RLock()
	entry, ok := p.entries[httpChallengeKey{domain: strings.TrimSuffix(strings.ToLower(host), "."), token: token}]
	p.mu.RUnlock()
	if !ok {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("Content-Type", "text/plain")
	_, _ = w.Write([]byte(entry.keyAuth))
}

func loadUser(email string, staging bool) (*lego.Client, *acmeUser, error) {
	if err := os.MkdirAll(acmeDir, 0o700); err != nil {
		return nil, nil, err
	}
	suffix := "prod"
	if staging {
		suffix = "staging"
	}
	keyPath := filepath.Join(acmeDir, "account-"+suffix+".key")
	regPath := filepath.Join(acmeDir, "account-"+suffix+".json")

	u := &acmeUser{Email: email}
	if raw, err := os.ReadFile(keyPath); err == nil {
		block, _ := pem.Decode(raw)
		if block == nil {
			return nil, nil, fmt.Errorf("corrupt account key %s", keyPath)
		}
		k, err := x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return nil, nil, err
		}
		u.key = k
		if raw, err := os.ReadFile(regPath); err == nil {
			_ = json.Unmarshal(raw, u)
		}
	} else {
		k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, nil, err
		}
		der, _ := x509.MarshalECPrivateKey(k)
		if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: der}), 0o600); err != nil {
			return nil, nil, err
		}
		u.key = k
	}
	u.Email = email

	cfg := lego.NewConfig(u)
	cfg.CADirURL = lego.LEDirectoryProduction
	if staging {
		cfg.CADirURL = lego.LEDirectoryStaging
	}
	cfg.Certificate.KeyType = certcrypto.EC256
	client, err := lego.NewClient(cfg)
	if err != nil {
		return nil, nil, err
	}
	if u.Reg == nil {
		reg, err := client.Registration.Register(registration.RegisterOptions{TermsOfServiceAgreed: true})
		if err != nil {
			return nil, nil, fmt.Errorf("ACME registration: %w", err)
		}
		u.Reg = reg
		raw, _ := json.Marshal(u)
		if err := os.WriteFile(regPath, raw, 0o600); err != nil {
			return nil, nil, err
		}
	}
	return client, u, nil
}

func prepareIssue(c *store.Cert, settings store.Settings, httpProvider *sharedHTTPProvider) (*lego.Client, error) {
	if settings.ACMEEmail == "" {
		return nil, fmt.Errorf("set ACME email in Settings first")
	}
	client, _, err := loadUser(settings.ACMEEmail, settings.ACMEStaging)
	if err != nil {
		return nil, err
	}

	switch c.Challenge {
	case "dns":
		for k, v := range c.DNSEnv {
			_ = os.Setenv(k, v)
		}
		p, err := dns.NewDNSChallengeProviderByName(c.DNSProvider)
		for k := range c.DNSEnv {
			_ = os.Unsetenv(k)
		}
		if err != nil {
			return nil, fmt.Errorf("dns provider %q: %w", c.DNSProvider, err)
		}
		if err := client.Challenge.SetDNS01Provider(p); err != nil {
			return nil, err
		}
	default: // http
		if httpProvider == nil {
			if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("127.0.0.1", engine.ACMEPort)); err != nil {
				return nil, err
			}
		} else if err := client.Challenge.SetHTTP01Provider(httpProvider); err != nil {
			return nil, err
		}
	}
	return client, nil
}

func obtain(client *lego.Client, c *store.Cert) error {
	res, err := client.Certificate.Obtain(certificate.ObtainRequest{Domains: c.Domains, Bundle: true})
	if err != nil {
		return err
	}
	if err := WriteFiles(c.ID, res.Certificate, res.PrivateKey); err != nil {
		return err
	}
	if block, _ := pem.Decode(res.Certificate); block != nil {
		if leaf, err := x509.ParseCertificate(block.Bytes); err == nil {
			c.ExpiresAt = leaf.NotAfter
		}
	}
	c.LastError = ""
	return nil
}

// Issue obtains (or re-obtains) one certificate and writes its files. Normal
// issuance stays serialized; isolated multi-domain requests use IssueBatch.
func Issue(c *store.Cert, settings store.Settings) error {
	acmeMu.Lock()
	defer acmeMu.Unlock()

	client, err := prepareIssue(c, settings, batchHTTPProvider)
	if err != nil {
		return err
	}
	return obtain(client, c)
}

type preparedIssue struct {
	client *lego.Client
	cert   *store.Cert
}

// runPreparedIssues is separated from ACME setup so concurrency and failure
// behavior can be tested without contacting a certificate authority.
func runPreparedIssues(items []preparedIssue, workers int, issue func(*lego.Client, *store.Cert) error) []error {
	errs := make([]error, len(items))
	if len(items) == 0 {
		return errs
	}
	if workers < 1 {
		workers = 1
	}
	if workers > len(items) {
		workers = len(items)
	}

	jobs := make(chan int)
	var failed atomic.Bool
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for index := range jobs {
				if failed.Load() {
					continue
				}
				if err := issue(items[index].client, items[index].cert); err != nil {
					errs[index] = err
					failed.Store(true)
				}
			}
		}()
	}
	for index := range items {
		jobs <- index
	}
	close(jobs)
	wg.Wait()
	return errs
}

// IssueBatch prepares isolated certificates sequentially (account files and
// DNS environment are process-global), then performs the slow ACME obtains in
// parallel. The caller owns state rollback and removal of partially written
// certificate files when any returned error is non-nil.
func IssueBatch(certificates []*store.Cert, settings store.Settings) []error {
	acmeMu.Lock()
	defer acmeMu.Unlock()

	errs := make([]error, len(certificates))
	items := make([]preparedIssue, len(certificates))
	for index, cert := range certificates {
		client, err := prepareIssue(cert, settings, batchHTTPProvider)
		if err != nil {
			errs[index] = err
			return errs
		}
		items[index] = preparedIssue{client: client, cert: cert}
	}
	// Isolated issuance is intentionally one goroutine per domain. Each item has
	// its own lego client, while the HTTP-01 listener is shared safely.
	return runPreparedIssues(items, len(items), obtain)
}

// RenewLoop renews ACME certs expiring within 30 days, checking every 12h.
// apply re-renders config and reloads nginx after a successful renewal.
func RenewLoop(st *store.Store, apply func() error) {
	for {
		time.Sleep(12 * time.Hour)
		st.Mu.Lock()
		changed := false
		for i := range st.S.Certs {
			c := &st.S.Certs[i]
			if c.Type != "acme" || time.Until(c.ExpiresAt) > 30*24*time.Hour {
				continue
			}
			log.Printf("certs: renewing %q (%v, expires %s)", c.Name, c.Domains, c.ExpiresAt.Format(time.RFC3339))
			if err := Issue(c, st.S.Settings); err != nil {
				c.LastError = err.Error()
				log.Printf("certs: renew %q failed: %v", c.Name, err)
				continue
			}
			changed = true
		}
		if changed {
			if err := apply(); err != nil {
				log.Printf("certs: reload after renew failed: %v", err)
			}
			_ = st.Save()
		} else {
			_ = st.Save() // persist LastError updates
		}
		st.Mu.Unlock()
	}
}

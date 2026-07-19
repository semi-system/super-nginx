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
	"os"
	"path/filepath"
	"sync"
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

// acmeMu: one ACME operation at a time (lego env-based DNS config is
// process-global, and the HTTP-01 solver binds a fixed port).
var acmeMu sync.Mutex

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

// Issue obtains (or re-obtains) the certificate described by c and writes the
// files. It mutates c (ExpiresAt/LastError) but does not touch the store.
func Issue(c *store.Cert, settings store.Settings) error {
	acmeMu.Lock()
	defer acmeMu.Unlock()

	if settings.ACMEEmail == "" {
		return fmt.Errorf("set ACME email in Settings first")
	}
	client, _, err := loadUser(settings.ACMEEmail, settings.ACMEStaging)
	if err != nil {
		return err
	}

	switch c.Challenge {
	case "dns":
		for k, v := range c.DNSEnv {
			os.Setenv(k, v)
		}
		p, err := dns.NewDNSChallengeProviderByName(c.DNSProvider)
		for k := range c.DNSEnv {
			defer os.Unsetenv(k)
		}
		if err != nil {
			return fmt.Errorf("dns provider %q: %w", c.DNSProvider, err)
		}
		if err := client.Challenge.SetDNS01Provider(p); err != nil {
			return err
		}
	default: // http
		if err := client.Challenge.SetHTTP01Provider(http01.NewProviderServer("127.0.0.1", engine.ACMEPort)); err != nil {
			return err
		}
	}

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

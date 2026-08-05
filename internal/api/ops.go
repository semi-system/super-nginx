package api

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
	"io/fs"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/morningstar-sudo/super-nginx/internal/store"
)

// ---- access lists -----------------------------------------------------------

// htpasswd {SHA} scheme — supported by nginx everywhere, no crypt(3) needed.
// SHA-1 is weak in the abstract, but this is the format nginx's
// auth_basic_user_file reads without depending on the base image's libc crypt(3),
// which the distroless runtime may not provide (and Go cannot produce SHA-crypt
// hashes anyway). Access-list passwords only — admin login uses bcrypt. Switch to
// bcrypt here if the base image is confirmed to ship crypt(3) with $2y$ support;
// that invalidates stored hashes, so users must re-enter access-list passwords.
func shaHash(pw string) string {
	// nosemgrep: go.lang.security.audit.crypto.use_of_weak_crypto.use-of-sha1
	sum := sha1.Sum([]byte(pw))
	return "{SHA}" + base64.StdEncoding.EncodeToString(sum[:])
}

type accessListIn struct {
	Name    string   `json:"name"`
	Satisfy string   `json:"satisfy"`
	Users   []struct {
		Username string `json:"username"`
		Password string `json:"password"` // empty on update = keep existing hash
	} `json:"users"`
	Allow []string `json:"allow"`
	Deny  []string `json:"deny"`
}

func (in *accessListIn) toList(prev *store.AccessList) (store.AccessList, error) {
	if in.Name == "" {
		return store.AccessList{}, fmt.Errorf("name required")
	}
	al := store.AccessList{Name: in.Name, Satisfy: in.Satisfy, Allow: in.Allow, Deny: in.Deny}
	for _, cidr := range append(append([]string{}, in.Allow...), in.Deny...) {
		if _, _, err := net.ParseCIDR(cidr); err != nil {
			if net.ParseIP(cidr) == nil {
				return store.AccessList{}, fmt.Errorf("invalid IP/CIDR %q", cidr)
			}
		}
	}
	for _, u := range in.Users {
		if u.Username == "" || strings.Contains(u.Username, ":") {
			return store.AccessList{}, fmt.Errorf("invalid username %q", u.Username)
		}
		hash := ""
		if u.Password != "" {
			hash = shaHash(u.Password)
		} else if prev != nil {
			for _, pu := range prev.Users {
				if pu.Username == u.Username {
					hash = pu.Hash
				}
			}
		}
		if hash == "" {
			return store.AccessList{}, fmt.Errorf("password required for user %q", u.Username)
		}
		al.Users = append(al.Users, store.AccessUser{Username: u.Username, Hash: hash})
	}
	return al, nil
}

type accessListOut struct {
	ID      int      `json:"id"`
	Name    string   `json:"name"`
	Satisfy string   `json:"satisfy"`
	Users   []string `json:"users"`
	Allow   []string `json:"allow"`
	Deny    []string `json:"deny"`
}

func toOut(al store.AccessList) accessListOut {
	out := accessListOut{ID: al.ID, Name: al.Name, Satisfy: al.Satisfy, Allow: al.Allow, Deny: al.Deny}
	for _, u := range al.Users {
		out.Users = append(out.Users, u.Username)
	}
	return out
}

func (a *API) listAccessLists(w http.ResponseWriter, _ *http.Request) {
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()
	out := []accessListOut{}
	for _, al := range a.St.S.AccessLists {
		out = append(out, toOut(al))
	}
	jsonOut(w, 200, out)
}

func (a *API) createAccessList(w http.ResponseWriter, r *http.Request) {
	var in accessListIn
	if err := decode(r, &in); err != nil {
		fail(w, 400, "bad request: %s", err)
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		al, err := in.toList(nil)
		if err != nil {
			return err
		}
		al.ID = s.NextID()
		s.AccessLists = append(s.AccessLists, al)
		return nil
	})
}

func (a *API) updateAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	var in accessListIn
	if err := decode(r, &in); err != nil {
		fail(w, 400, "bad request: %s", err)
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		for i := range s.AccessLists {
			if s.AccessLists[i].ID == id {
				al, err := in.toList(&s.AccessLists[i])
				if err != nil {
					return err
				}
				al.ID = id
				s.AccessLists[i] = al
				return nil
			}
		}
		return fmt.Errorf("access list %d not found", id)
	})
}

func (a *API) deleteAccessList(w http.ResponseWriter, r *http.Request) {
	id, err := pathID(r)
	if err != nil {
		fail(w, 400, "bad id")
		return
	}
	a.mutate(w, r, func(s *store.State) error {
		for _, h := range s.Hosts {
			if h.AccessListID == id {
				return fmt.Errorf("access list in use by host %d (%s)", h.ID, strings.Join(h.Domains, " "))
			}
		}
		for i := range s.AccessLists {
			if s.AccessLists[i].ID == id {
				s.AccessLists = append(s.AccessLists[:i], s.AccessLists[i+1:]...)
				return nil
			}
		}
		return fmt.Errorf("access list %d not found", id)
	})
}

// ---- backup / restore -------------------------------------------------------

// backup = tar.gz of everything needed to rebuild /data. The logical data goes
// in as the portable store.Export envelope (data.json) — driver-independent, so
// a future postgres/mysql driver reads the same file. Certs + ACME account are
// file blobs carried alongside. Rendered config is derived, not included.
const exportFile = "data.json"

var backupBlobRoots = []string{"certs", "acme"}

// backup is POST so the password rides in a header (X-Backup-Password), never
// a query string. Empty password = encrypt with the per-instance key.
func (a *API) backup(w http.ResponseWriter, r *http.Request) {
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	// portable data envelope first
	if data, err := a.St.S.MarshalExport(); err == nil {
		hdr := &tar.Header{Name: exportFile, Mode: 0o600, Size: int64(len(data)), ModTime: time.Now()}
		if tw.WriteHeader(hdr) == nil {
			_, _ = tw.Write(data)
		}
	}
	for _, root := range backupBlobRoots {
		base := filepath.Join("/data", root)
		_ = filepath.Walk(base, func(path string, fi os.FileInfo, err error) error {
			if err != nil || fi.IsDir() {
				return nil
			}
			rel, _ := filepath.Rel("/data", path)
			hdr := &tar.Header{Name: filepath.ToSlash(rel), Mode: 0o600, Size: fi.Size(), ModTime: fi.ModTime()}
			if err := tw.WriteHeader(hdr); err != nil {
				return err
			}
			f, err := os.Open(path)
			if err != nil {
				return err
			}
			defer f.Close()
			_, err = io.Copy(tw, f)
			return err
		})
	}
	if err := tw.Close(); err != nil {
		fail(w, 500, "%s", err)
		return
	}
	if err := gz.Close(); err != nil {
		fail(w, 500, "%s", err)
		return
	}

	enc, err := encryptBackup(buf.Bytes(), r.Header.Get("X-Backup-Password"))
	if err != nil {
		fail(w, 500, "encrypt backup: %s", err)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="super-nginx-backup-%s.snb"`, time.Now().Format("20060102-150405")))
	w.Header().Set("X-Content-Type-Options", "nosniff")
	// encrypted archive bytes, not markup — Content-Type is explicit, sniffing off.
	// nosemgrep: go.lang.security.audit.xss.no-direct-write-to-responsewriter.no-direct-write-to-responsewriter
	_, _ = w.Write(enc)
}

// Caps on a restore: the archive is attacker-shaped data even though the endpoint
// is admin-only, and both the upload and the decompressed members land in memory
// or on a read-only-rootfs /data with finite room.
const (
	maxRestoreFile  = 32 << 20  // per member inside the archive
	maxRestoreTotal = 256 << 20 // uploaded body, and total bytes written out
)

// safeBackupPath reports whether a tar member name may be written under /data.
// fs.ValidPath rejects absolute paths, "", and any unclean form including a ".."
// element, so no separate traversal check is needed; the roots allowlist does the
// rest (and rejects the "." that ValidPath lets through).
func safeBackupPath(name string) (string, bool) {
	name = filepath.ToSlash(name)
	if !fs.ValidPath(name) {
		return "", false
	}
	for _, root := range backupBlobRoots {
		if strings.HasPrefix(name, root+"/") {
			return name, true
		}
	}
	return name, false
}

func (a *API) restore(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, maxRestoreTotal)
	blob, err := io.ReadAll(r.Body)
	if err != nil {
		fail(w, 400, "read body: %s", err)
		return
	}
	plain, err := decryptBackup(blob, r.Header.Get("X-Backup-Password"))
	if err != nil {
		fail(w, 400, "%s", err)
		return
	}
	gz, err := gzip.NewReader(bytes.NewReader(plain))
	if err != nil {
		fail(w, 400, "corrupt backup (bad archive after decrypt): %s", err)
		return
	}
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()

	tr := tar.NewReader(gz)
	restored := 0
	written := int64(0)
	var envelope []byte
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail(w, 400, "bad archive: %s", err)
			return
		}
		if hdr.Typeflag != tar.TypeReg {
			continue
		}
		name, ok := safeBackupPath(hdr.Name)
		if name == exportFile {
			// LimitReader caps the decompressed size, which the gzip header does not.
			envelope, err = io.ReadAll(io.LimitReader(tr, maxRestoreFile+1))
			if err != nil {
				fail(w, 400, "read %s: %s", exportFile, err)
				return
			}
			if int64(len(envelope)) > maxRestoreFile {
				fail(w, 413, "%s exceeds %d bytes", exportFile, maxRestoreFile)
				return
			}
			continue
		}
		if !ok {
			continue
		}
		dst := filepath.Join("/data", filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			fail(w, 500, "%s", err)
			return
		}
		f, err := os.Create(dst)
		if err != nil {
			fail(w, 500, "%s", err)
			return
		}
		// CopyN, not Copy: the gzip header does not bound the decompressed size.
		// A member shorter than the cap ends with io.EOF, which is the normal case.
		n, err := io.CopyN(f, tr, maxRestoreFile+1)
		f.Close()
		if err != nil && err != io.EOF {
			fail(w, 500, "%s", err)
			return
		}
		if n > maxRestoreFile {
			fail(w, 413, "%s exceeds %d bytes", name, maxRestoreFile)
			return
		}
		written += n
		if written > maxRestoreTotal {
			fail(w, 413, "archive expands past %d bytes", maxRestoreTotal)
			return
		}
		restored++
	}
	if envelope == nil {
		fail(w, 400, "archive has no %s (not a super-nginx backup)", exportFile)
		return
	}
	state, err := store.ParseExport(envelope)
	if err != nil {
		fail(w, 422, "%s", err)
		return
	}
	// adopt imported data through the current driver, then render + reload
	a.St.S = state
	if err := a.St.Save(); err != nil {
		fail(w, 500, "save imported state: %s", err)
		return
	}
	if err := a.applyLocked(); err != nil {
		fail(w, 422, "imported data renders invalid config: %s", err)
		return
	}
	a.audit(r)
	jsonOut(w, 200, map[string]any{"status": "ok", "files": restored})
}

// ---- audit log --------------------------------------------------------------

func (a *API) auditLog(w http.ResponseWriter, _ *http.Request) {
	raw, err := os.ReadFile("/data/logs/audit.log")
	if err != nil {
		jsonOut(w, 200, []string{})
		return
	}
	lines := strings.Split(strings.TrimSpace(string(raw)), "\n")
	if len(lines) > 200 {
		lines = lines[len(lines)-200:]
	}
	jsonOut(w, 200, lines)
}

// ---- nginx metrics (stub_status) --------------------------------------------

func (a *API) metrics(w http.ResponseWriter, _ *http.Request) {
	client := http.Client{Timeout: 2 * time.Second}
	res, err := client.Get("http://127.0.0.1:8090/stub_status")
	if err != nil {
		jsonOut(w, 200, map[string]any{"available": false})
		return
	}
	defer res.Body.Close()
	raw, _ := io.ReadAll(res.Body)
	var active, accepts, handled, requests, reading, writing, waiting int
	fmt.Sscanf(string(raw), "Active connections: %d \nserver accepts handled requests\n %d %d %d \nReading: %d Writing: %d Waiting: %d",
		&active, &accepts, &handled, &requests, &reading, &writing, &waiting)
	jsonOut(w, 200, map[string]any{
		"available": true,
		"active":    active,
		"accepts":   accepts,
		"handled":   handled,
		"requests":  requests,
		"reading":   reading,
		"writing":   writing,
		"waiting":   waiting,
	})
}

package api

import (
	"archive/tar"
	"compress/gzip"
	"crypto/sha1"
	"encoding/base64"
	"fmt"
	"io"
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
func shaHash(pw string) string {
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

// backup = tar.gz of everything needed to rebuild /data: state + certs + acme
// account. Rendered config is derived, so it is not included.
var backupRoots = []string{"db", "certs", "acme"}

func (a *API) backup(w http.ResponseWriter, _ *http.Request) {
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()

	w.Header().Set("Content-Type", "application/gzip")
	w.Header().Set("Content-Disposition",
		fmt.Sprintf(`attachment; filename="super-nginx-backup-%s.tar.gz"`, time.Now().Format("20060102-150405")))
	gz := gzip.NewWriter(w)
	tw := tar.NewWriter(gz)
	defer func() { tw.Close(); gz.Close() }()

	for _, root := range backupRoots {
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
}

func (a *API) restore(w http.ResponseWriter, r *http.Request) {
	gz, err := gzip.NewReader(r.Body)
	if err != nil {
		fail(w, 400, "not a gzip archive: %s", err)
		return
	}
	a.St.Mu.Lock()
	defer a.St.Mu.Unlock()

	tr := tar.NewReader(gz)
	restored := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			fail(w, 400, "bad archive: %s", err)
			return
		}
		name := filepath.ToSlash(filepath.Clean(hdr.Name))
		okPrefix := false
		for _, root := range backupRoots {
			if name == root || strings.HasPrefix(name, root+"/") {
				okPrefix = true
			}
		}
		if !okPrefix || strings.Contains(name, "..") || hdr.Typeflag != tar.TypeReg {
			continue
		}
		dst := filepath.Join("/data", name)
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			fail(w, 500, "%s", err)
			return
		}
		f, err := os.Create(dst)
		if err != nil {
			fail(w, 500, "%s", err)
			return
		}
		if _, err := io.Copy(f, tr); err != nil {
			f.Close()
			fail(w, 500, "%s", err)
			return
		}
		f.Close()
		restored++
	}
	if err := a.St.Reload(); err != nil {
		fail(w, 422, "restored state is corrupt: %s", err)
		return
	}
	if err := a.applyLocked(); err != nil {
		fail(w, 422, "restored state renders invalid config: %s", err)
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

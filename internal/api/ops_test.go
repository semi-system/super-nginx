package api

import "testing"

func TestSafeBackupPath(t *testing.T) {
	cases := []struct {
		in       string
		wantName string
		wantOK   bool
	}{
		{"certs/a.pem", "certs/a.pem", true},
		{"acme/account/key.json", "acme/account/key.json", true},
		// valid paths, but outside the blob roots — caller handles or skips them
		{exportFile, exportFile, false},
		{"db/state.json", "db/state.json", false},
		{".", ".", false},
		// rejected outright
		{"../../etc/passwd", "", false},
		{"certs/../../etc/passwd", "", false},
		{"/etc/passwd", "", false},
		{"certs/", "", false},
		{"certs//a.pem", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		name, ok := safeBackupPath(c.in)
		if ok != c.wantOK || name != c.wantName {
			t.Errorf("safeBackupPath(%q) = (%q, %v), want (%q, %v)",
				c.in, name, ok, c.wantName, c.wantOK)
		}
	}
}

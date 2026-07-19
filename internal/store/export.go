package store

import (
	"encoding/json"
	"fmt"
	"time"
)

// Portable, storage-independent data format. Any backing driver (the current
// JSON file, or a future postgres/mysql driver) exports to and imports from
// this envelope, so backups move between drivers unchanged. Certs and ACME
// account keys are file blobs handled separately by the backup archive — this
// envelope carries only the logical data model.
const (
	ExportKind    = "super-nginx-data"
	ExportVersion = 1
)

type Export struct {
	Kind       string    `json:"kind"`
	Version    int       `json:"version"`
	ExportedAt time.Time `json:"exported_at"`
	State      State     `json:"state"`
}

// Export snapshots the current state into the portable envelope.
func (s *State) Export() Export {
	return Export{Kind: ExportKind, Version: ExportVersion, ExportedAt: time.Now().UTC(), State: *s}
}

// Marshal renders the envelope as indented JSON.
func (s *State) MarshalExport() ([]byte, error) {
	e := s.Export()
	return json.MarshalIndent(&e, "", "  ")
}

// ParseExport reads an envelope, rejecting unknown kinds or newer versions a
// future driver wrote. Returns the contained State for the caller to adopt.
func ParseExport(raw []byte) (State, error) {
	var e Export
	if err := json.Unmarshal(raw, &e); err != nil {
		return State{}, fmt.Errorf("not a super-nginx export: %w", err)
	}
	if e.Kind != ExportKind {
		return State{}, fmt.Errorf("unexpected export kind %q (want %q)", e.Kind, ExportKind)
	}
	if e.Version > ExportVersion {
		return State{}, fmt.Errorf("export version %d newer than supported %d — upgrade super-nginx", e.Version, ExportVersion)
	}
	// older versions migrate here as the schema grows (none yet)
	return e.State, nil
}

package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

// real checkpoint data from log.sycamore.ct.letsencrypt.org/2026h1
const fixtureCheckpoint = "log.sycamore.ct.letsencrypt.org/2026h1\n" +
	"910004669\n" +
	"r4hBntWxgz2ver0Q24tx3uAt+XdpbZxZnyChZT2BHzc=\n" +
	"\n" +
	"— grease.invalid lbCd1oRYil3zhIcUyx7k+ANsprx2of9ipxX34IkV\n" +
	"— log.sycamore.ct.letsencrypt.org/2026h1 EEuevwAAAZ2l51g2BAMARjBEAiA1IgU345pEJwrn2mEJkZhOsA1fHEXEVcBT143riLTLxAIgJPDIrFTcKBoEwRTpRLAPm5ErEGAxewbHTT2/b7SJpec=\n"

const fixtureLogList = `{
      "version": "85.48",
      "log_list_timestamp": "2026-04-18T00:00:00Z",
      "operators": [{
          "name": "Let's Encrypt",
          "email": ["test@example.com"],
          "tiled_logs": [{
              "description": "Let's Encrypt 'Sycamore2026h1'",
              "log_id": "pcl4kl1XRheChw3YiWYLXFVki30AQPLsB2hR0YhpGfc=",
              "key": "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfEEe0JZknA91/c6eNl1aexgeKzuGQUMvRCXPXg9L227O5I4Pi++Abcpq6qxlVUKPYafAJelAnMfGzv3lHCc8gA==",
              "submission_url": "https://log.sycamore.ct.letsencrypt.org/2026h1/",
              "monitoring_url": "https://mon.sycamore.ct.letsencrypt.org/2026h1/",
              "state": {"usable": {"timestamp": "2024-09-30T22:19:27Z"}}
          }]
      }]
  }`

// --- parseSignedNotes ---

func TestParseSignedNotesOriginSignature(t *testing.T) {
	origin := "log.sycamore.ct.letsencrypt.org/2026h1"
	lines := []string{
		"— log.sycamore.ct.letsencrypt.org/2026h1 EEuevwAAAZ2l51g2BAMARjBEAiA1IgU345pEJwrn2mEJkZhOsA1fHEXEVcBT143riLTLxAIgJPDIrFTcKBoEwRTpRLAPm5ErEGAxewbHTT2/b7SJpec=",
	}

	notes, err := parseSignedNotes(lines, origin)
	if err != nil {
		t.Fatalf("parseSignedNotes() error = %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("got %d notes, want 1", len(notes))
	}
	if notes[0].KeyName != origin {
		t.Errorf("KeyName = %q, want %q", notes[0].KeyName, origin)
	}
	if notes[0].SignedNoteSignature.KeyId != "104b9ebf" {
		t.Errorf("KeyId = %q, want %q", notes[0].SignedNoteSignature.KeyId,
			"104b9ebf")
	}
	if notes[0].SignedNoteSignature.Signature == "" {
		t.Error("Signature is empty")
	}
}

func TestParseSignedNotesCosigner(t *testing.T) {
	origin := "log.sycamore.ct.letsencrypt.org/2026h1"
	lines := []string{
		"— grease.invalid lbCd1oRYil3zhIcUyx7k+ANsprx2of9ipxX34IkV",
	}

	notes, err := parseSignedNotes(lines, origin)
	if err != nil {
		t.Fatalf("parseSignedNotes() error = %v", err)
	}
	if len(notes) != 1 {
		t.Fatalf("got %d notes, want 1", len(notes))
	}
	if notes[0].KeyName != "grease.invalid" {
		t.Errorf("KeyName = %q, want %q", notes[0].KeyName, "grease.invalid")
	}
	if notes[0].SignedNoteSignature.Unknown == "" {
		t.Error("Unknown is empty")
	}
}

func TestParseSignedNotesMalformedSkipped(t *testing.T) {
	origin := "example.com/log"
	lines := []string{
		"— nospace",       // no space — skipped
		"— ",              // empty after prefix — skipped
		"not a note line", // no em dash prefix — skipped
	}

	notes, err := parseSignedNotes(lines, origin)
	if err != nil {
		t.Fatalf("parseSignedNotes() error = %v", err)
	}
	if len(notes) != 0 {
		t.Errorf("got %d notes, want 0", len(notes))
	}
}

func TestParseSignedNotesEmpty(t *testing.T) {
	notes, err := parseSignedNotes([]string{}, "example.com/log")
	if err != nil {
		t.Fatalf("parseSignedNotes() error = %v", err)
	}
	if len(notes) != 0 {
		t.Errorf("got %d notes, want 0", len(notes))
	}
}

// --- fetchCheckpoint ---

func TestFetchCheckpoint(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/checkpoint" {
			http.NotFound(w, r)
			return
		}
		fmt.Fprint(w, fixtureCheckpoint)
	}))
	defer server.Close()

	cp, err := fetchCheckpoint(&CachedLog{MonitoringUrl: server.URL + "/"})
	if err != nil {
		t.Fatalf("fetchCheckpoint() error = %v", err)
	}

	if cp.Origin != "log.sycamore.ct.letsencrypt.org/2026h1" {
		t.Errorf("Origin = %q", cp.Origin)
	}
	if cp.TreeSize != 910004669 {
		t.Errorf("TreeSize = %d, want 910004669", cp.TreeSize)
	}
	if cp.RootHash == "" {
		t.Error("RootHash is empty")
	}
	if len(cp.SignedNotes) != 2 {
		t.Errorf("got %d signed notes, want 2", len(cp.SignedNotes))
	}
}

func TestFetchCheckpointNonOK(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "rate limited", http.StatusTooManyRequests)
	}))
	defer server.Close()

	_, err := fetchCheckpoint(&CachedLog{MonitoringUrl: server.URL + "/"})
	if err == nil {
		t.Fatal("expected error for non-200 response, got nil")
	}
}

// --- fetchLogList ---

func TestFetchLogList(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		fmt.Fprint(w, fixtureLogList)
	}))
	defer server.Close()

	// temporarily override the log list URL
	original := logListUrl
	logListUrl = server.URL
	defer func() { logListUrl = original }()

	ll, err := fetchLogList()
	if err != nil {
		t.Fatalf("fetchLogList() error = %v", err)
	}
	if ll.Version != "85.48" {
		t.Errorf("Version = %q, want %q", ll.Version, "85.48")
	}
	if len(ll.Operators) != 1 {
		t.Fatalf("got %d operators, want 1", len(ll.Operators))
	}
	if len(ll.Operators[0].TiledLogs) != 1 {
		t.Fatalf("got %d tiled logs, want 1", len(ll.Operators[0].TiledLogs))
	}
}

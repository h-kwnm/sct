package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// sycamore2026h1 is a real log fixture with a known expected key ID,
// used to verify key ID derivation against a known-good value.
var sycamore2026h1 = TiledLog{
	Description:   "Let's Encrypt 'Sycamore2026h1'",
	LogId:         "pcl4kl1XRheChw3YiWYLXFVki30AQPLsB2hR0YhpGfc=",
	Key:           "MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEfEEe0JZknA91/c6eNl1aexgeKzuGQUMvRCXPXg9L227O5I4Pi++Abcpq6qxlVUKPYafAJelAnMfGzv3lHCc8gA==",
	SubmissionUrl: "https://log.sycamore.ct.letsencrypt.org/2026h1/",
	MonitoringUrl: "https://mon.sycamore.ct.letsencrypt.org/2026h1/",
	State:         LogStateUsable,
}

func sampleLogList() *LogList {
	return &LogList{
		Version:   "85.48",
		Timestamp: "2026-04-18T00:00:00Z",
		Operators: []Operator{
			{
				Name:      "Let's Encrypt",
				TiledLogs: []TiledLog{sycamore2026h1},
			},
		},
	}
}

func TestBuildLogCacheIdAssignment(t *testing.T) {
	ll := &LogList{
		Operators: []Operator{
			{
				Name:      "Operator A",
				TiledLogs: []TiledLog{sycamore2026h1, sycamore2026h1},
			},
			{
				Name:      "Operator B",
				TiledLogs: []TiledLog{sycamore2026h1},
			},
		},
	}
	cache, err := buildLogCache(ll)
	if err != nil {
		t.Fatalf("buildLogCache() error = %v", err)
	}
	if len(cache.Logs) != 3 {
		t.Fatalf("got %d logs, want 3", len(cache.Logs))
	}
	for i, l := range cache.Logs {
		if l.Id != i+1 {
			t.Errorf("logs[%d].Id = %d, want %d", i, l.Id, i+1)
		}
	}
}

func TestBuildLogCacheKeyID(t *testing.T) {
	cache, err := buildLogCache(sampleLogList())
	if err != nil {
		t.Fatalf("buildLogCache() error = %v", err)
	}
	if len(cache.Logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(cache.Logs))
	}
	got := cache.Logs[0].KeyId
	want := "104b9ebf"
	if got != want {
		t.Errorf("KeyId = %q, want %q", got, want)
	}
}

func TestBuildLogCacheOrigin(t *testing.T) {
	cache, err := buildLogCache(sampleLogList())
	if err != nil {
		t.Fatalf("buildLogCache() error = %v", err)
	}
	got := cache.Logs[0].Origin
	want := "log.sycamore.ct.letsencrypt.org/2026h1"
	if got != want {
		t.Errorf("Origin = %q, want %q", got, want)
	}
}

func TestSaveLoadLogCacheRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "logs.json")

	original := &LogCache{
		FetchedAt:      time.Date(2026, 4, 18, 0, 0, 0, 0, time.UTC),
		LogListVersion: "85.48",
		Logs: []CachedLog{
			{
				Id:          1,
				Operator:    "Let's Encrypt",
				Description: "Let's Encrypt 'Sycamore2026h1'",
				KeyId:       "104b9ebf",
				Origin:      "log.sycamore.ct.letsencrypt.org/2026h1",
				State:       LogStateUsable,
			},
		},
	}

	// save
	data, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	if err := os.WriteFile(path, data, 0644); err != nil {
		t.Fatalf("WriteFile error: %v", err)
	}

	// load
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile error: %v", err)
	}
	var loaded LogCache
	if err := json.Unmarshal(data, &loaded); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}

	if loaded.LogListVersion != original.LogListVersion {
		t.Errorf("LogListVersion = %q, want %q", loaded.LogListVersion,
			original.LogListVersion)
	}
	if len(loaded.Logs) != 1 {
		t.Fatalf("got %d logs, want 1", len(loaded.Logs))
	}
	if loaded.Logs[0].KeyId != original.Logs[0].KeyId {
		t.Errorf("KeyId = %q, want %q", loaded.Logs[0].KeyId,
			original.Logs[0].KeyId)
	}
	if loaded.Logs[0].State != LogStateUsable {
		t.Errorf("State = %q, want %q", loaded.Logs[0].State, LogStateUsable)
	}
}

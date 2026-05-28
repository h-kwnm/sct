package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// --- CT log list ---

// CT log list schema
// https://googlechrome.github.io/CertificateTransparency/log_lists.html
// https://www.gstatic.com/ct/log_list/v3/log_list_schema.json
// https://www.gstatic.com/ct/log_list/v3/log_list.json

type LogState string

const (
	LogStateUsable    LogState = "usable"
	LogStateReadonly  LogState = "readonly"
	LogStateRetired   LogState = "retired"
	LogStateQualified LogState = "qualified"
	LogStatePending   LogState = "pending"
	LogStateRejected  LogState = "rejected"
)

func (s *LogState) UnmarshalJSON(data []byte) error {
	// plain string from cache
	var str string
	if err := json.Unmarshal(data, &str); err == nil {
		*s = LogState(str)
		return nil
	}

	// object from Google log list
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(data, &obj); err != nil {
		return err
	}
	// check if log schema is not changed
	if len(obj) != 1 {
		return fmt.Errorf("unexpected log state object: expected exactly 1 key, got %d", len(obj)) // only 'usable' key expected
	}
	for key := range obj {
		*s = LogState(key)
		return nil
	}
	return fmt.Errorf("empty state object")
}

func (s LogState) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

type TemporalInterval struct {
	StartInclusive string `json:"start_inclusive"`
	EndExclusive   string `json:"end_exclusive"`
}
type Log struct {
	Description      string   `json:"description"`
	LogID            string   `json:"log_id"`
	Key              string   `json:"key"`
	URL              string   `json:"url"`
	State            LogState `json:"state"`
	TemporalInterval `json:"temporal_interval"`
}

type TiledLog struct {
	Description      string   `json:"description"`
	LogID            string   `json:"log_id"`
	Key              string   `json:"key"`
	SubmissionURL    string   `json:"submission_url"`
	MonitoringURL    string   `json:"monitoring_url"`
	State            LogState `json:"state"`
	TemporalInterval `json:"temporal_interval"`
}

type Operator struct {
	Name      string     `json:"name"`
	Logs      []Log      `json:"logs"`
	TiledLogs []TiledLog `json:"tiled_logs"`
}

type LogList struct {
	Version   string     `json:"version"`
	Timestamp string     `json:"log_list_timestamp"`
	Operators []Operator `json:"operators"`
}

// --- CT log cache ---

type APIType string

const (
	APITypeStaticCT APIType = "static"
	APITypeRFC6962  APIType = "rfc6962"
)

type CachedLog struct {
	ID             int       `json:"id"`
	Operator       string    `json:"operator"`
	Description    string    `json:"description"`
	LogID          string    `json:"log_id"`
	Key            string    `json:"key"`
	State          LogState  `json:"state"`
	APIType        APIType   `json:"api_type"`
	StartInclusive time.Time `json:"start_inclusive"`
	EndExclusive   time.Time `json:"end_exclusive"`
	// Static CT API
	KeyID         string `json:"key_id,omitempty"`
	Origin        string `json:"origin,omitempty"`
	MonitoringURL string `json:"monitoring_url,omitempty"`
	SubmissionURL string `json:"submission_url,omitempty"`
	// ---
	// RFC 6962
	URL string `json:"url,omitempty"`
	// ---
}

type LogCache struct {
	FetchedAt      time.Time   `json:"fetched_at"`
	LogListVersion string      `json:"log_list_version"`
	Logs           []CachedLog `json:"logs"`
}

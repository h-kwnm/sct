package main

import (
	"encoding/json"
	"testing"
)

func TestLogStateUnmarshalJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		want    LogState
		wantErr bool
	}{
		{
			name:  "object form from Google log list",
			input: `{"usable":{"timestamp":"2024-09-30T22:19:27Z"}}`,
			want:  LogStateUsable,
		},
		{
			name:  "plain string from cache",
			input: `"usable"`,
			want:  LogStateUsable,
		},
		{
			name:  "readonly state",
			input: `{"readonly":{"timestamp":"2024-01-01T00:00:00Z"}}`,
			want:  LogStateReadonly,
		},
		{
			name:    "empty object",
			input:   `{}`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var s LogState
			err := json.Unmarshal([]byte(tt.input), &s)
			if (err != nil) != tt.wantErr {
				t.Fatalf("UnmarshalJSON() error = %v, wantErr %v", err,
					tt.wantErr)
			}
			if !tt.wantErr && s != tt.want {
				t.Errorf("got %q, want %q", s, tt.want)
			}
		})
	}
}

func TestLogStateMarshalJSON(t *testing.T) {
	tests := []struct {
		name  string
		input LogState
		want  string
	}{
		{name: "usable", input: LogStateUsable, want: `"usable"`},
		{name: "retired", input: LogStateRetired, want: `"retired"`},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b, err := json.Marshal(tt.input)
			if err != nil {
				t.Fatalf("MarshalJSON() error = %v", err)
			}
			if string(b) != tt.want {
				t.Errorf("got %s, want %s", b, tt.want)
			}
		})
	}
}

func TestLogStateRoundTrip(t *testing.T) {
	// marshal to plain string, unmarshal back — verifies cache round-trip
	original := LogStateUsable
	b, err := json.Marshal(original)
	if err != nil {
		t.Fatalf("Marshal error: %v", err)
	}
	var result LogState
	if err := json.Unmarshal(b, &result); err != nil {
		t.Fatalf("Unmarshal error: %v", err)
	}
	if result != original {
		t.Errorf("round-trip: got %q, want %q", result, original)
	}
}

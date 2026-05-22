package main

import (
	"bytes"
	"crypto/x509"
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

// --- CTTimestamp ---

func TestCTTimestampMarshalJSON(t *testing.T) {
	// 1_700_000_000_000 ms = 2023-11-14T22:13:20Z
	ts := CTTimestamp(1_700_000_000_000)
	b, err := json.Marshal(ts)
	if err != nil {
		t.Fatalf("MarshalJSON() error = %v", err)
	}
	want := `"2023-11-14T22:13:20Z"`
	if string(b) != want {
		t.Errorf("got %s, want %s", b, want)
	}
}

// --- Precert.Marshal ---

func TestPrecertMarshal(t *testing.T) {
	var isk [32]byte
	for i := range isk {
		isk[i] = byte(i)
	}
	tbs := []byte{0x30, 0x05, 0x02, 0x03, 0x01, 0x02, 0x03}

	got := Precert{IssuerKeyHash: isk, RawTBSCertificate: tbs}.Marshal()

	wantLen := 32 + 3 + len(tbs)
	if len(got) != wantLen {
		t.Fatalf("len = %d, want %d", len(got), wantLen)
	}
	// first 32 bytes: issuer key hash
	if !bytes.Equal(got[:32], isk[:]) {
		t.Error("issuer key hash mismatch")
	}
	// 3-byte big-endian TBS length
	gotLen := int(got[32])<<16 | int(got[33])<<8 | int(got[34])
	if gotLen != len(tbs) {
		t.Errorf("TBS length field = %d, want %d", gotLen, len(tbs))
	}
	// TBS content
	if !bytes.Equal(got[35:], tbs) {
		t.Error("TBS content mismatch")
	}
}

// --- TimestampedEntry.Marshal ---

func TestTimestampedEntryMarshal(t *testing.T) {
	const ts = CTTimestamp(1_700_000_000_000)
	tbs := []byte{0xAA}
	entry := TimestampedEntry{
		Timestamp:    ts,
		LogEntryType: entryTypePrecert,
		Precert:      &Precert{IssuerKeyHash: [32]byte{}, RawTBSCertificate: tbs},
		CtExtensions: 0x0000,
	}

	got := entry.Marshal()

	// first 8 bytes: timestamp (big-endian uint64)
	var gotTs uint64
	for i := range 8 {
		gotTs = gotTs<<8 | uint64(got[i])
	}
	if gotTs != uint64(ts) {
		t.Errorf("timestamp = %d, want %d", gotTs, uint64(ts))
	}
	// bytes 8–9: entry_type
	gotType := uint16(got[8])<<8 | uint16(got[9])
	if gotType != entryTypePrecert {
		t.Errorf("entry_type = %d, want %d", gotType, entryTypePrecert)
	}
	// last 2 bytes: ct_extensions = 0x0000
	n := len(got)
	gotExt := uint16(got[n-2])<<8 | uint16(got[n-1])
	if gotExt != 0 {
		t.Errorf("ct_extensions = %d, want 0", gotExt)
	}
	// total length: 8 (ts) + 2 (type) + Precert.Marshal() + 2 (ext)
	wantLen := 8 + 2 + len(entry.Precert.Marshal()) + 2
	if len(got) != wantLen {
		t.Errorf("len = %d, want %d", len(got), wantLen)
	}
}

func TestTimestampedEntryMarshalX509(t *testing.T) {
	certDER := generateSelfSignedCert(t)
	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("ParseCertificate: %v", err)
	}

	const ts = CTTimestamp(1_700_000_000_000)
	entry := TimestampedEntry{
		Timestamp:    ts,
		LogEntryType: entryTypeX509,
		ASN1Cert:     ASN1Cert(*cert),
		CtExtensions: 0x0000,
	}

	got := entry.Marshal()

	// timestamp: bytes 0-7
	var gotTs uint64
	for i := range 8 {
		gotTs = gotTs<<8 | uint64(got[i])
	}
	if gotTs != uint64(ts) {
		t.Errorf("timestamp = %d, want %d", gotTs, uint64(ts))
	}

	// entry_type: bytes 8-9
	gotType := uint16(got[8])<<8 | uint16(got[9])
	if gotType != entryTypeX509 {
		t.Errorf("entry_type = %d, want %d", gotType, entryTypeX509)
	}

	// cert length: bytes 10-12 (3-byte big-endian uint24)
	gotCertLen := int(got[10])<<16 | int(got[11])<<8 | int(got[12])
	if gotCertLen != len(certDER) {
		t.Errorf("cert length = %d, want %d", gotCertLen, len(certDER))
	}

	// cert content
	if !bytes.Equal(got[13:13+gotCertLen], certDER) {
		t.Error("cert DER content mismatch")
	}

	// ct_extensions: last 2 bytes
	n := len(got)
	gotExt := uint16(got[n-2])<<8 | uint16(got[n-1])
	if gotExt != 0 {
		t.Errorf("ct_extensions = %d, want 0", gotExt)
	}

	// total length: 8 (ts) + 2 (type) + 3 (cert len) + len(certDER) + 2 (ext)
	wantLen := 8 + 2 + 3 + len(certDER) + 2
	if len(got) != wantLen {
		t.Errorf("len = %d, want %d", len(got), wantLen)
	}
}

// --- MerkleTreeLeaf.Marshal ---

func TestMerkleTreeLeafMarshal(t *testing.T) {
	leaf := MerkleTreeLeaf{
		Version:        0,
		MerkleLeafType: 0,
		TimestampedEntry: TimestampedEntry{
			Timestamp:    CTTimestamp(1_700_000_000_000),
			LogEntryType: entryTypePrecert,
			Precert:      &Precert{IssuerKeyHash: [32]byte{}, RawTBSCertificate: []byte{0xBB}},
			CtExtensions: 0x0000,
		},
	}

	got := leaf.Marshal()

	if got[0] != 0 {
		t.Errorf("version = %d, want 0", got[0])
	}
	if got[1] != 0 {
		t.Errorf("leaf_type = %d, want 0", got[1])
	}
	want := append([]byte{0, 0}, leaf.TimestampedEntry.Marshal()...)
	if !bytes.Equal(got, want) {
		t.Error("MerkleTreeLeaf.Marshal() content mismatch")
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

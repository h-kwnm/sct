package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"math/big"
	"testing"
	"time"
)

// --- readUint24 ---

func TestReadUint24(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint32
	}{
		{[]byte{0x00, 0x00, 0x00}, 0},
		{[]byte{0x00, 0x00, 0x01}, 1},
		{[]byte{0x01, 0x02, 0x03}, 0x010203},
		{[]byte{0xFF, 0xFF, 0xFF}, 0xFFFFFF},
	}
	for _, tc := range cases {
		got, err := readUint24(bytes.NewReader(tc.in))
		if err != nil {
			t.Errorf("readUint24(%x) error = %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("readUint24(%x) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestReadUint24EOF(t *testing.T) {
	_, err := readUint24(bytes.NewReader([]byte{0x01, 0x02})) // only 2 bytes
	if err == nil {
		t.Error("expected error on short read, got nil")
	}
}

// --- readUint40 ---

func TestReadUint40(t *testing.T) {
	cases := []struct {
		in   []byte
		want uint64
	}{
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x00}, 0},
		{[]byte{0x00, 0x00, 0x00, 0x00, 0x01}, 1},
		{[]byte{0x01, 0x02, 0x03, 0x04, 0x05}, 0x0102030405},
		{[]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF}, 0xFFFFFFFFFF},
	}
	for _, tc := range cases {
		got, err := readUint40(bytes.NewReader(tc.in))
		if err != nil {
			t.Errorf("readUint40(%x) error = %v", tc.in, err)
			continue
		}
		if got != tc.want {
			t.Errorf("readUint40(%x) = %d, want %d", tc.in, got, tc.want)
		}
	}
}

func TestReadUint40EOF(t *testing.T) {
	_, err := readUint40(bytes.NewReader([]byte{0x01, 0x02, 0x03, 0x04})) // only 4 bytes
	if err == nil {
		t.Error("expected error on short read, got nil")
	}
}

// --- parseDataTile helpers ---

// generateSelfSignedCert creates a minimal self-signed ECDSA certificate for use in tests.
func generateSelfSignedCert(t *testing.T) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		DNSNames:     []string{"test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	return der
}

// buildLeafIndexExt constructs the CT extension bytes for a leaf_index extension.
func buildLeafIndexExt(leafIndex uint64) []byte {
	var buf bytes.Buffer
	buf.WriteByte(extensionTypeLeafIndex)
	binary.Write(&buf, binary.BigEndian, uint16(5)) //nolint:errcheck
	buf.Write([]byte{
		byte(leafIndex >> 32),
		byte(leafIndex >> 24),
		byte(leafIndex >> 16),
		byte(leafIndex >> 8),
		byte(leafIndex),
	})
	return buf.Bytes()
}

// buildX509TileEntry constructs a single x509 TileLeaf binary entry.
func buildX509TileEntry(certDER []byte, tsMillis uint64, leafIndex uint64) []byte {
	var buf bytes.Buffer

	// timestamp: 8 bytes
	binary.Write(&buf, binary.BigEndian, tsMillis) //nolint:errcheck

	// entry_type x509: 2 bytes
	binary.Write(&buf, binary.BigEndian, uint16(entryTypeX509)) //nolint:errcheck

	// cert length: 3 bytes uint24
	n := uint32(len(certDER))
	buf.Write([]byte{byte(n >> 16), byte(n >> 8), byte(n)})

	// cert DER
	buf.Write(certDER)

	// ct extensions (leaf_index)
	ext := buildLeafIndexExt(leafIndex)
	binary.Write(&buf, binary.BigEndian, uint16(len(ext))) //nolint:errcheck
	buf.Write(ext)

	// fingerprints: none
	binary.Write(&buf, binary.BigEndian, uint16(0)) //nolint:errcheck

	return buf.Bytes()
}

// --- parseDataTile ---

func TestParseDataTileSingleX509Entry(t *testing.T) {
	certDER := generateSelfSignedCert(t)

	const tsMillis = uint64(1_700_000_000_000)
	const leafIndex = uint64(42)

	tile := buildX509TileEntry(certDER, tsMillis, leafIndex)

	entries, err := parseDataTile(tile)
	if err != nil {
		t.Fatalf("parseDataTile() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}

	e := entries[0]
	if e.EntryType != "x509" {
		t.Errorf("EntryType = %q, want x509", e.EntryType)
	}
	if e.LeafIndex != leafIndex {
		t.Errorf("LeafIndex = %d, want %d", e.LeafIndex, leafIndex)
	}
	wantTs := time.UnixMilli(int64(tsMillis)).UTC()
	if !e.Timestamp.Equal(wantTs) {
		t.Errorf("Timestamp = %v, want %v", e.Timestamp, wantTs)
	}
	if e.Certificate.Subject == "" {
		t.Error("Certificate.Subject is empty")
	}
	if len(e.Certificate.DNSNames) != 1 || e.Certificate.DNSNames[0] != "test.example.com" {
		t.Errorf("DNSNames = %v, want [test.example.com]", e.Certificate.DNSNames)
	}
}

func TestParseDataTileMultipleEntries(t *testing.T) {
	certDER := generateSelfSignedCert(t)

	const n = 3
	var tile []byte
	for i := uint64(0); i < n; i++ {
		tile = append(tile, buildX509TileEntry(certDER, 1_700_000_000_000+i*1000, i)...)
	}

	entries, err := parseDataTile(tile)
	if err != nil {
		t.Fatalf("parseDataTile() error = %v", err)
	}
	if len(entries) != n {
		t.Fatalf("got %d entries, want %d", len(entries), n)
	}
	for i, e := range entries {
		if e.LeafIndex != uint64(i) {
			t.Errorf("entries[%d].LeafIndex = %d, want %d", i, e.LeafIndex, i)
		}
	}
}

func TestParseDataTileEmpty(t *testing.T) {
	entries, err := parseDataTile([]byte{})
	if err != nil {
		t.Fatalf("parseDataTile() error = %v", err)
	}
	if len(entries) != 0 {
		t.Errorf("got %d entries, want 0", len(entries))
	}
}

func TestParseDataTileTruncated(t *testing.T) {
	certDER := generateSelfSignedCert(t)
	tile := buildX509TileEntry(certDER, 1_700_000_000_000, 0)

	_, err := parseDataTile(tile[:len(tile)/2])
	if err == nil {
		t.Error("expected error for truncated tile, got nil")
	}
}

func TestParseDataTileWithFingerprint(t *testing.T) {
	certDER := generateSelfSignedCert(t)

	var buf bytes.Buffer

	const tsMillis = uint64(1_700_000_000_000)
	const leafIndex = uint64(7)

	// timestamp
	binary.Write(&buf, binary.BigEndian, tsMillis) //nolint:errcheck
	// entry_type x509
	binary.Write(&buf, binary.BigEndian, uint16(entryTypeX509)) //nolint:errcheck
	// cert
	n := uint32(len(certDER))
	buf.Write([]byte{byte(n >> 16), byte(n >> 8), byte(n)})
	buf.Write(certDER)
	// ct extensions
	ext := buildLeafIndexExt(leafIndex)
	binary.Write(&buf, binary.BigEndian, uint16(len(ext))) //nolint:errcheck
	buf.Write(ext)
	// one fingerprint (32 bytes)
	fp := make([]byte, 32)
	for i := range fp {
		fp[i] = byte(i)
	}
	binary.Write(&buf, binary.BigEndian, uint16(32)) //nolint:errcheck
	buf.Write(fp)

	entries, err := parseDataTile(buf.Bytes())
	if err != nil {
		t.Fatalf("parseDataTile() error = %v", err)
	}
	if len(entries) != 1 {
		t.Fatalf("got %d entries, want 1", len(entries))
	}
	if len(entries[0].Fingerprints) != 1 {
		t.Errorf("got %d fingerprints, want 1", len(entries[0].Fingerprints))
	}
}

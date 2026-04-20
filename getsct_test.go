package main

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/pem"
	"math/big"
	"testing"
	"time"
)

// real letsencrypt.org certificate containing two SCTs:
//   - SCT 0: log cb38f715... (classic RFC 6962, no ct_extensions)
//   - SCT 1: log 717e95f3... (Static CT API, leaf_index = 187809721)
const fixtureLECertPEM = `-----BEGIN CERTIFICATE-----
MIIEQzCCA8mgAwIBAgISBiIQkC6Br+XUvmis7p44YFKFMAoGCCqGSM49BAMDMDIx
CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1MZXQncyBFbmNyeXB0MQswCQYDVQQDEwJF
ODAeFw0yNjAzMDgxNzA0MzBaFw0yNjA2MDYxNzA0MjlaMBoxGDAWBgNVBAMTD2xl
dHNlbmNyeXB0Lm9yZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBFaPZEsy5Vs
zGOYos4s8gc1biL2qfCqchzmM9/1z4GYVsEYGFJlBcf2ZWcQpjW+9/NZUG8qe3CW
ECkh4dG4rZujggLVMIIC0TAOBgNVHQ8BAf8EBAMCB4AwEwYDVR0lBAwwCgYIKwYB
BQUHAwEwDAYDVR0TAQH/BAIwADAdBgNVHQ4EFgQUGbo3pLEp0HFa9KjM2/G0NQOM
z40wHwYDVR0jBBgwFoAUjw0TovYuftFQbDMYOF1ZjiNykcowMgYIKwYBBQUHAQEE
JjAkMCIGCCsGAQUFBzAChhZodHRwOi8vZTguaS5sZW5jci5vcmcvMIHTBgNVHREE
gcswgciCEmNwLmxldHNlbmNyeXB0Lm9yZ4IaY3Aucm9vdC14MS5sZXRzZW5jcnlw
dC5vcmeCE2Nwcy5sZXRzZW5jcnlwdC5vcmeCG2Nwcy5yb290LXgxLmxldHNlbmNy
eXB0Lm9yZ4IJbGVuY3Iub3Jngg9sZXRzZW5jcnlwdC5jb22CD2xldHNlbmNyeXB0
Lm9yZ4INd3d3LmxlbmNyLm9yZ4ITd3d3LmxldHNlbmNyeXB0LmNvbYITd3d3Lmxl
dHNlbmNyeXB0Lm9yZzATBgNVHSAEDDAKMAgGBmeBDAECATAsBgNVHR8EJTAjMCGg
H6AdhhtodHRwOi8vZTguYy5sZW5jci5vcmcvNi5jcmwwggENBgorBgEEAdZ5AgQC
BIH+BIH7APkAdgDLOPcViXyEoURfW8Hd+8lu8ppZzUcKaQWFsMsUwxRY5wAAAZzO
neXnAAAEAwBHMEUCIB3UegX+9a4D9ABceFNduKf7Vn+L/6I/JXR2L1mlf58wAiEA
+42hZDroiyNB4cSjL9YYwH3eGye5dsuhFr9m3Mcpr8cAfwBxfpXzwjiKbbHjhEk9
MeFaqWIIdi1CAOAFDNBntaZh4gAAAZzOneaAAAgAAAUACzG/uQQDAEgwRgIhAMPT
OgCe6SAmY2FHMzMk8OIdUej2T+/RoJfFQbK6pcAzAiEAwsUHDp/oRItTNY1ghDIC
dVwzuOebfLmCrk7HF2YpeGEwCgYIKoZIzj0EAwMDaAAwZQIwHf8Cw0UoMPHkHDuk
mRWZ2f8wMiN/SY0aUVokjrVRw17QsV0eg5C7FrrJapqNYVcvAjEA0E0sB2GMngjI
CT1wywN+vSiRndKhz4pE15eqApt9Dfcpqr+xvYF9U0svyFRbXny5
-----END CERTIFICATE-----`

// buildSCTExtValue constructs a DER-encoded OCTET STRING containing a
// TLS-encoded SignedCertificateTimestampList with the given entries.
// leafIndex == 0 produces an SCT with empty CtExtensions (classic RFC 6962).
// leafIndex > 0 produces an SCT with a leaf_index extension (Static CT API).
func buildSCTExtValue(t *testing.T, entries []struct {
	logID     [32]byte
	tsMillis  uint64
	leafIndex uint64
}) []byte {
	t.Helper()

	var listBuf bytes.Buffer
	for _, e := range entries {
		var sctBuf bytes.Buffer

		sctBuf.WriteByte(0) // version v1
		sctBuf.Write(e.logID[:])
		binary.Write(&sctBuf, binary.BigEndian, e.tsMillis) //nolint:errcheck

		if e.leafIndex > 0 {
			// leaf_index extension: type(1) + dataLen(2) + uint40(5) = 8 bytes
			binary.Write(&sctBuf, binary.BigEndian, uint16(8)) //nolint:errcheck
			sctBuf.WriteByte(extensionTypeLeafIndex)
			binary.Write(&sctBuf, binary.BigEndian, uint16(5)) //nolint:errcheck
			sctBuf.Write([]byte{
				byte(e.leafIndex >> 32),
				byte(e.leafIndex >> 24),
				byte(e.leafIndex >> 16),
				byte(e.leafIndex >> 8),
				byte(e.leafIndex),
			})
		} else {
			binary.Write(&sctBuf, binary.BigEndian, uint16(0)) //nolint:errcheck
		}

		sctData := sctBuf.Bytes()
		binary.Write(&listBuf, binary.BigEndian, uint16(len(sctData))) //nolint:errcheck
		listBuf.Write(sctData)
	}

	listData := listBuf.Bytes()
	var outer bytes.Buffer
	binary.Write(&outer, binary.BigEndian, uint16(len(listData))) //nolint:errcheck
	outer.Write(listData)

	derValue, err := asn1.Marshal(outer.Bytes())
	if err != nil {
		t.Fatalf("marshaling SCT extension value: %v", err)
	}
	return derValue
}

// buildCertWithSCTs creates a minimal self-signed certificate carrying a
// crafted SCT list extension.
func buildCertWithSCTs(t *testing.T, entries []struct {
	logID     [32]byte
	tsMillis  uint64
	leafIndex uint64
}) []byte {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}

	extValue := buildSCTExtValue(t, entries)

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		ExtraExtensions: []pkix.Extension{
			{
				Id:    asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2},
				Value: extValue,
			},
		},
	}

	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}
	return der
}

// --- parseCertSCT ---

func TestParseCertSCTRealCert(t *testing.T) {
	block, _ := pem.Decode([]byte(fixtureLECertPEM))
	if block == nil {
		t.Fatal("failed to decode fixture PEM")
	}

	scts, err := parseCertSCT(block.Bytes)
	if err != nil {
		t.Fatalf("parseCertSCT() error = %v", err)
	}
	if len(scts) != 2 {
		t.Fatalf("got %d SCTs, want 2", len(scts))
	}

	// SCT 0: classic RFC 6962 log — no ct_extensions
	sct0 := scts[0]
	if sct0.LogId != "yzj3FYl8hKFEX1vB3fvJbvKaWc1HCmkFhbDLFMMUWOc=" {
		t.Errorf("SCT[0].LogId = %q", sct0.LogId)
	}
	if sct0.Timestamp.IsZero() {
		t.Error("SCT[0].Timestamp is zero")
	}
	if len(sct0.CtExtensions) != 0 {
		t.Errorf("SCT[0]: got %d ct_extensions, want 0", len(sct0.CtExtensions))
	}

	// SCT 1: Static CT API log — carries leaf_index extension
	sct1 := scts[1]
	if sct1.LogId != "cX6V88I4im2x44RJPTHhWqliCHYtQgDgBQzQZ7WmYeI=" {
		t.Errorf("SCT[1].LogId = %q", sct1.LogId)
	}
	if len(sct1.CtExtensions) != 1 {
		t.Fatalf("SCT[1]: got %d ct_extensions, want 1", len(sct1.CtExtensions))
	}
	if sct1.CtExtensions[0].ExtensionValue != 187809721 {
		t.Errorf("SCT[1] leaf_index = %d, want 187809721", sct1.CtExtensions[0].ExtensionValue)
	}
}

func TestParseCertSCTLeafIndex(t *testing.T) {
	var logID [32]byte
	logID[0] = 0xAB

	const wantLeafIndex = uint64(12345678)
	const wantTsMillis = uint64(1_700_000_000_000)

	der := buildCertWithSCTs(t, []struct {
		logID     [32]byte
		tsMillis  uint64
		leafIndex uint64
	}{
		{logID: logID, tsMillis: wantTsMillis, leafIndex: wantLeafIndex},
	})

	scts, err := parseCertSCT(der)
	if err != nil {
		t.Fatalf("parseCertSCT() error = %v", err)
	}
	if len(scts) != 1 {
		t.Fatalf("got %d SCTs, want 1", len(scts))
	}

	sct := scts[0]
	if sct.Version != 0 {
		t.Errorf("Version = %d, want 0", sct.Version)
	}
	wantTs := time.UnixMilli(int64(wantTsMillis)).UTC()
	if !sct.Timestamp.Equal(wantTs) {
		t.Errorf("Timestamp = %v, want %v", sct.Timestamp, wantTs)
	}
	if len(sct.CtExtensions) != 1 {
		t.Fatalf("got %d ct_extensions, want 1", len(sct.CtExtensions))
	}
	if sct.CtExtensions[0].ExtensionValue != wantLeafIndex {
		t.Errorf("leaf_index = %d, want %d", sct.CtExtensions[0].ExtensionValue, wantLeafIndex)
	}
}

func TestParseCertSCTEmptyExtensions(t *testing.T) {
	var logID [32]byte

	der := buildCertWithSCTs(t, []struct {
		logID     [32]byte
		tsMillis  uint64
		leafIndex uint64
	}{
		{logID: logID, tsMillis: 1_700_000_000_000, leafIndex: 0},
	})

	scts, err := parseCertSCT(der)
	if err != nil {
		t.Fatalf("parseCertSCT() error = %v", err)
	}
	if len(scts) != 1 {
		t.Fatalf("got %d SCTs, want 1", len(scts))
	}
	if len(scts[0].CtExtensions) != 0 {
		t.Errorf("got %d ct_extensions, want 0", len(scts[0].CtExtensions))
	}
}

func TestParseCertSCTMultipleSCTs(t *testing.T) {
	var logID1, logID2 [32]byte
	logID1[0] = 0x01
	logID2[0] = 0x02

	der := buildCertWithSCTs(t, []struct {
		logID     [32]byte
		tsMillis  uint64
		leafIndex uint64
	}{
		{logID: logID1, tsMillis: 1_700_000_000_000, leafIndex: 0},
		{logID: logID2, tsMillis: 1_700_000_001_000, leafIndex: 99},
	})

	scts, err := parseCertSCT(der)
	if err != nil {
		t.Fatalf("parseCertSCT() error = %v", err)
	}
	if len(scts) != 2 {
		t.Fatalf("got %d SCTs, want 2", len(scts))
	}
	if len(scts[0].CtExtensions) != 0 {
		t.Errorf("SCT[0]: got %d ct_extensions, want 0", len(scts[0].CtExtensions))
	}
	if len(scts[1].CtExtensions) != 1 || scts[1].CtExtensions[0].ExtensionValue != 99 {
		t.Errorf("SCT[1]: unexpected ct_extensions %v", scts[1].CtExtensions)
	}
}

func TestParseCertSCTNoSCTExtension(t *testing.T) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating certificate: %v", err)
	}

	scts, err := parseCertSCT(der)
	if err != nil {
		t.Fatalf("parseCertSCT() error = %v", err)
	}
	if len(scts) != 0 {
		t.Errorf("got %d SCTs, want 0", len(scts))
	}
}

func TestParseCertSCTInvalidDER(t *testing.T) {
	_, err := parseCertSCT([]byte("not a certificate"))
	if err == nil {
		t.Error("expected error for invalid DER, got nil")
	}
}

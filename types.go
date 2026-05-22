package main

import (
	"bytes"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"math/big"
	"time"
)

const (
	entryTypeX509    uint16 = 0
	entryTypePrecert uint16 = 1
)

// --- SCT ---

// https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#sct-extension
//
//	enum {
//		leaf_index(0), (255)
//	} ExtensionType;
//
//	struct {
//		ExtensionType extension_type;
//		opaque extension_data<0..2^16-1>;
//	} Extension;
//
// Extension CtExtensions<0..2^16-1>;
// uint8 uint40[5];
// uint40 LeafIndex;

type CtExtension struct {
	Type   uint8  `json:"extension_type"`
	Length uint16 `json:"extension_length"`
	Value  uint64 `json:"extension_value"`
}

type CTTimestamp uint64

func (t CTTimestamp) MarshalJSON() ([]byte, error) {
	s := time.UnixMilli(int64(t)).UTC()
	return json.Marshal(s)
}

type SCT struct {
	Version          uint8         `json:"version"`
	LogID            string        `json:"log_id"`
	LogIDDescription string        `json:"log_id_description"` // "description" the log in thelog list
	Timestamp        CTTimestamp   `json:"timestamp"`
	CtExtensions     []CtExtension `json:"ct_extensions,omitempty"`
}

// --- Common structure ---

type MerkleTreeLeaf struct {
	Version          uint8 // always 0(v1)
	MerkleLeafType   uint8 // always 0(timestamped_entry)
	TimestampedEntry TimestampedEntry
}

func (l MerkleTreeLeaf) Marshal() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, l.Version)
	binary.Write(&b, binary.BigEndian, l.MerkleLeafType)
	b.Write(l.TimestampedEntry.Marshal())
	return b.Bytes()
}

type TBSCertificate struct {
	Version              asn1.RawValue `asn1:"optional,explicit,tag:0"`
	SerialNumber         asn1.RawValue
	SignatureAlgorithm   asn1.RawValue
	Issuer               asn1.RawValue
	Validity             asn1.RawValue
	Subject              asn1.RawValue
	SubjectPublicKeyInfo asn1.RawValue
	Extensions           []pkix.Extension `asn1:"optional,explicit,tag:3"`
}

func (t TBSCertificate) MarshalJSON() ([]byte, error) {
	var version int
	if _, err := asn1.Unmarshal(t.Version.Bytes, &version); err != nil {
		return nil, err
	}

	serialNumber := new(big.Int).SetBytes(t.SerialNumber.Bytes)

	var sigAlg pkix.AlgorithmIdentifier
	if _, err := asn1.Unmarshal(t.SignatureAlgorithm.FullBytes, &sigAlg); err != nil {
		return nil, err
	}

	var issuer pkix.RDNSequence
	if _, err := asn1.Unmarshal(t.Issuer.FullBytes, &issuer); err != nil {
		return nil, err
	}

	var validity struct {
		NotBefore time.Time
		NotAfter  time.Time
	}
	if _, err := asn1.Unmarshal(t.Validity.FullBytes, &validity); err != nil {
		return nil, err
	}

	var subject pkix.RDNSequence
	if _, err := asn1.Unmarshal(t.Subject.FullBytes, &subject); err != nil {
		return nil, err
	}

	var spki struct {
		Algorithm pkix.AlgorithmIdentifier
		PublicKey asn1.BitString
	}
	if _, err := asn1.Unmarshal(t.SubjectPublicKeyInfo.FullBytes, &spki); err != nil {
		return nil, err
	}

	type ext struct {
		OID      string `json:"oid"`
		Critical bool   `json:"critical"`
		Value    string `json:"value"`
	}
	var exts []ext
	for _, ex := range t.Extensions {
		exts = append(exts, ext{
			OID:      ex.Id.String(),
			Critical: ex.Critical,
			Value:    base64.StdEncoding.EncodeToString(ex.Value),
		})
	}
	// TODO: parse in detail
	// for _, ext := range t.Extensions {
	// 	switch {
	// 	case ext.Id.Equal(oidExtensionSubjectAltName):
	// 		var names []asn1.RawValue
	// 		asn1.Unmarshal(ext.Value, &names)
	// 	case ext.Id.Equal(oidExtensionBasicConstraints):
	// 		var bc struct {
	// 			IsCA       bool `asn1:"optional"`
	// 			MaxPathLen int  `asn1:"optional,default:-1"`
	// 		}
	// 		asn1.Unmarshal(ext.Value, &bc)
	// 	case ext.Id.Equal(oidExtensionKeyUsage):
	// 		var usage asn1.BitString
	// 		asn1.Unmarshal(ext.Value, &usage)
	// 	}
	// }

	return json.Marshal(struct {
		Version              string    `json:"version"`
		SerialNumber         string    `json:"serial_number"`
		SignatureAlgorithm   string    `json:"signature_algorithm"`
		Issuer               string    `json:"issuer"`
		NotBefore            time.Time `json:"not_before"`
		NotAfter             time.Time `json:"not_after"`
		Subject              string    `json:"subject"`
		SubjectPublicKeyInfo struct {
			AlgorithmIdentifier string `json:"algorithm_identifier"`
			PublicKey           string `json:"public_key"`
		} `json:"subject_public_key_info"`
		Extensions []ext
	}{
		Version:            fmt.Sprintf("0x%02x", version),
		SerialNumber:       fmt.Sprintf("%x", serialNumber),
		SignatureAlgorithm: sigAlg.Algorithm.String(),
		Issuer:             issuer.String(),
		NotBefore:          validity.NotBefore,
		NotAfter:           validity.NotAfter,
		Subject:            subject.String(),
		SubjectPublicKeyInfo: struct {
			AlgorithmIdentifier string `json:"algorithm_identifier"`
			PublicKey           string `json:"public_key"`
		}{
			AlgorithmIdentifier: spki.Algorithm.Algorithm.String(),
			PublicKey:           base64.StdEncoding.EncodeToString(spki.PublicKey.Bytes),
		},
		Extensions: exts,
	})
}

type Precert struct {
	IssuerKeyHash     [32]byte `json:"issuer_key_hash"`
	RawTBSCertificate []byte   `json:"tbs_certificate"`
}

func (p Precert) Marshal() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, p.IssuerKeyHash[:])

	// TBSCertificate has 3 bytes length header as defined below.
	// opaque TBSCertificate<1..2^24-1>
	length := len(p.RawTBSCertificate)
	b.WriteByte(byte(length >> 16))
	b.WriteByte(byte(length >> 8))
	b.WriteByte(byte(length))
	b.Write(p.RawTBSCertificate)

	return b.Bytes()
}

func (pc Precert) MarshalJSON() ([]byte, error) {
	var zeroHash [32]byte
	if pc.IssuerKeyHash == zeroHash {
		return json.Marshal(struct {
			IssuerKeyHash     string `json:"issuer_key_hash"`
			RawTBSCertificate string `json:"tbs_certificate"`
		}{
			IssuerKeyHash:     "",
			RawTBSCertificate: "",
		})
	}

	isk := fmt.Sprintf("%x", pc.IssuerKeyHash)
	var tbs TBSCertificate
	_, err := asn1.Unmarshal(pc.RawTBSCertificate, &tbs)
	if err != nil {
		return nil, err
	}
	return json.Marshal(struct {
		IssuerKeyHash     string         `json:"issuer_key_hash"`
		RawTBSCertificate TBSCertificate `json:"tbs_certificate"`
	}{
		IssuerKeyHash:     isk,
		RawTBSCertificate: tbs,
	})
}

type Certificate struct {
	Raw            string     `json:"raw,omitempty"`
	ParseError     string     `json:"parse_error,omitempty"`
	Version        int        `json:"version,omitempty"`
	SerialNumber   string     `json:"serial,omitempty"`
	SignatureAlg   string     `json:"sig_alg,omitempty"`
	Issuer         string     `json:"issuer,omitempty"`
	NotBefore      time.Time  `json:"not_before"`
	NotAfter       time.Time  `json:"not_after"`
	Subject        string     `json:"subject,omitempty"`
	PublicKeyAlg   string     `json:"pubkey_alg,omitempty"`
	SubjectKeyId   string     `json:"ski,omitempty"`
	DNSNames       []string   `json:"dns_names,omitempty"`
	IPAddresses    []string   `json:"ip_addresses,omitempty"`
	AuthorityKeyId string     `json:"aki,omitempty"`
	Policies       []x509.OID `json:"policies,omitempty"`
	KeyUsage       []string   `json:"key_usage,omitempty"`
	ExtKeyUsage    []string   `json:"ext_key_usage,omitempty"`
}

type ASN1Cert x509.Certificate

func (ac ASN1Cert) MarshalJSON() ([]byte, error) {
	var ips []string
	for _, ip := range ac.IPAddresses {
		ips = append(ips, ip.String())
	}
	cert := Certificate{
		Version:        ac.Version,
		SerialNumber:   ac.SerialNumber.Text(16),
		SignatureAlg:   ac.SignatureAlgorithm.String(),
		Issuer:         ac.Issuer.String(),
		NotBefore:      ac.NotBefore.UTC(),
		NotAfter:       ac.NotAfter.UTC(),
		Subject:        ac.Subject.String(),
		PublicKeyAlg:   ac.PublicKeyAlgorithm.String(),
		SubjectKeyId:   fmt.Sprintf("%x", ac.SubjectKeyId),
		DNSNames:       ac.DNSNames,
		IPAddresses:    ips,
		AuthorityKeyId: fmt.Sprintf("%x", ac.AuthorityKeyId),
		Policies:       ac.Policies,
		KeyUsage:       parseKeyUsage(ac.KeyUsage),
		ExtKeyUsage:    parseExtKeyUsage(ac.ExtKeyUsage),
	}

	return json.Marshal(cert)
}

type TimestampedEntry struct {
	Timestamp    CTTimestamp `json:"timestamp"`
	LogEntryType uint16      `json:"entry_type"`
	ASN1Cert     ASN1Cert    `json:"asn1cert"`      // LogEntryType = 0(x509_entry)
	Precert      *Precert    `json:"precert"`       // LogEntryType = 1(precert_entry)
	CtExtensions uint16      `json:"ct_extensions"` // this types is only for RFC 6962, so always "0x0000"
	// "CtExtensions" should be "CTExtensions" to follow Go's convention
	// but I chose to honor RFC 6962's definition
	// https://www.rfc-editor.org/rfc/rfc6962#section-3.2
}

func (t TimestampedEntry) Marshal() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, t.Timestamp)
	binary.Write(&b, binary.BigEndian, t.LogEntryType)
	switch t.LogEntryType {
	case entryTypeX509:
		raw := x509.Certificate(t.ASN1Cert).Raw
		b.WriteByte(byte(len(raw) >> 16))
		b.WriteByte(byte(len(raw) >> 8))
		b.WriteByte(byte(len(raw)))
		b.Write(raw)
	case entryTypePrecert:
		b.Write(t.Precert.Marshal())
	}
	binary.Write(&b, binary.BigEndian, t.CtExtensions)
	return b.Bytes()
}

func (t TimestampedEntry) MarshalJSON() ([]byte, error) {
	switch t.LogEntryType {
	case entryTypeX509:
		tsX509 := struct {
			Timestamp    CTTimestamp `json:"timestamp"`
			LogEntryType uint16      `json:"entry_type"`
			ASN1Cert     ASN1Cert    `json:"asn1cert"`
			CtExtensions uint16      `json:"ct_extensions"`
		}{
			Timestamp:    t.Timestamp,
			LogEntryType: t.LogEntryType,
			ASN1Cert:     t.ASN1Cert,
			CtExtensions: t.CtExtensions,
		}
		return json.Marshal(tsX509)
	case entryTypePrecert:
		tsPrecert := struct {
			Timestamp    CTTimestamp `json:"timestamp"`
			LogEntryType uint16      `json:"entry_type"`
			Precert      Precert     `json:"precert"`
			CtExtensions uint16      `json:"ct_extensions"`
		}{
			Timestamp:    t.Timestamp,
			LogEntryType: t.LogEntryType,
			Precert:      *(t.Precert),
			CtExtensions: t.CtExtensions,
		}
		return json.Marshal(tsPrecert)
	}

	return nil, fmt.Errorf("unexpected log entry type=%d", t.LogEntryType)
}

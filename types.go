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

const (
	extensionTypeLeafIndex uint8 = 0
)

// -- Accepted root certificates ---

type GetRootsResponse struct {
	Certificates []string `json:"certificates"`
}

type RootCertificate struct {
	Raw            string     `json:"raw"`
	ParseError     string     `json:"parse_error,omitempty"`
	Version        int        `json:"version,omitempty"`
	SerialNumber   string     `json:"serial,omitempty"`
	SignatureAlg   string     `json:"sig_alg,omitempty"`
	Issuer         string     `json:"issuer,omitempty"`
	NotBefore      time.Time  `json:"not_before,omitempty"`
	NotAfter       time.Time  `json:"not_after,omitempty"`
	Subject        string     `json:"subject,omitempty"`
	PublicKeyAlg   string     `json:"pubkey_alg,omitempty"`
	SubjectKeyId   string     `json:"ski,omitempty"`
	AuthorityKeyId string     `json:"aki,omitempty"`
	Policies       []x509.OID `json:"policies,omitempty"`
	KeyUsage       []string   `json:"key_usage,omitempty"`
	ExtKeyUsage    []string   `json:"ext_key_usage,omitempty"`
}

type AcceptedRootCertificates struct {
	Certificates []RootCertificate `json:"certificates"`
}

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
	for key := range obj {
		*s = LogState(key)
		return nil
	}
	return fmt.Errorf("empty state object")
}

func (s LogState) MarshalJSON() ([]byte, error) {
	return json.Marshal(string(s))
}

type Log struct {
	Description string   `json:"description"`
	LogID       string   `json:"log_id"`
	Key         string   `json:"key"`
	URL         string   `json:"url"`
	State       LogState `json:"state"`
}

type TiledLog struct {
	Description   string   `json:"description"`
	LogID         string   `json:"log_id"`
	Key           string   `json:"key"`
	SubmissionURL string   `json:"submission_url"`
	MonitoringURL string   `json:"monitoring_url"`
	State         LogState `json:"state"`
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
	ID          int      `json:"id"`
	Operator    string   `json:"operator"`
	Description string   `json:"description"`
	LogID       string   `json:"log_id"`
	Key         string   `json:"key"`
	State       LogState `json:"state"`
	APIType     APIType  `json:"api_type"`
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

// --- Static CT API: Checkpoint ---

type Checkpoint struct {
	Origin      string       `json:"origin"`
	TreeSize    uint64       `json:"tree_size"`
	RootHash    string       `json:"root_hash"`
	SignedNotes []SignedNote `json:"signed_notes"`
}

type SignedNote struct {
	KeyName             string              `json:"key_name"`
	SignedNoteSignature SignedNoteSignature `json:"signature"`
}

type SignedNoteSignature struct {
	KeyID     string `json:"key_id,omitempty"`
	Signature string `json:"signature,omitempty"`
	Unknown   string `json:"unknown,omitempty"`
}

// --- Static CT API: Data tile ---

// TBSCertificate, PreCert format https://www.rfc-editor.org/rfc/rfc6962#section-3.2
// ---
// opaque TBSCertificate<1..2^24-1>; // 3 + a byte
//
// struct {
//   opaque issuer_key_hash[32]; // 32 byte
//   TBSCertificate tbs_certificate;
// } PreCert; // 32 + (3 + a) byte
//
// opaque CtExtensions<0..2^16-1>; // 2 + b byte

// TimestampedEntry format https://www.rfc-editor.org/rfc/rfc6962#section-3.4
// ---
// struct {
//   uint64 timestamp; // 8 byte
//   LogEntryType entry_type; // 2 byte (00 00: x509_entry, 00 01: precert_entry)
//   select(entry_type) {
//     case x509_entry: ASN.1Cert;
//     case precert_entry: PreCert;
//   } signed_entry;
//   CtExtensions extensions; // 2 + b byte
// } TimestampedEntry;
//   -> x509_entry   : 8 + 2 + (3 + c) + (2 + b) byte
//      precert_entry: 8 + 2 + (32 + (3 + a)) + (2 + b) byte
//
// opaque ASN.1Cert<1..2^24-1>; // 3 + c

// Data tile log entry format https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#log-entries
// ---
// struct {
// 	TimestampedEntry timestamped_entry;
// 	select (entry_type) {
// 		case x509_entry: Empty;
// 		case precert_entry: ASN.1Cert pre_certificate; // 3 + d byte
// 	};
// 	Fingerprint certificate_chain<0..2^16-1>; // 2 + e byte (e is multiple of 32)
// } TileLeaf;
//   -> x509_entry   : 8 + 2 + (3 + c) + (2 + b) + (2 + e) byte
//      precert_entry: 8 + 2 + (32 + (3 + a)) + (2 + b) + (3 + d) + (2 + e) byte
//
// opaque Fingerprint[32]; // 32 byte

type CertEntry struct {
	Subject        string    `json:"subject"`
	Issuer         string    `json:"issuer"`
	Serial         string    `json:"serial"`
	NotBefore      time.Time `json:"not_before"`
	NotAfter       time.Time `json:"not_after"`
	DNSNames       []string  `json:"dns_names"`
	IPAddresses    []string  `json:"ip_addresses"`
	SubjectKeyId   string    `json:"ski"`
	AuthorityKeyId string    `json:"aki"`
	SignatureAlg   string    `json:"sig_alg"`
	PublicKeyAlg   string    `json:"pubkey_alg"`
	Policies       []string  `json:"policies"`
	// TODO:
	// KeyUsage
	// Extensions
	// ExtraExtensions
	// UnhandledCriticalExtensions
	// ExtKeyUsage
	// UnknownExtKeyUsage
	// PolicyIdentifiers
	// Policies
}

type DataEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	EntryType     string    `json:"entry_type"`
	LeafIndex     uint64    `json:"leaf_index"`
	IssuerKeyHash string    `json:"issuer_key_hash"`
	Fingerprints  []string  `json:"fps_chain"`
	Certificate   CertEntry `json:"certificate"`
}

type DataTile struct {
	MonitoringURL string      `json:"monitoring_url"`
	TileIndexPath string      `json:"tile_index_path"`
	FetchedAt     time.Time   `json:"fetched_time"`
	Entries       []DataEntry `json:"entries"`
}

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

// --- Merkle tree ---

// inclusion proof verification
// https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#merkle-tree
// <monitoring prefix>/tile/<L>/<N>[.p/<W>]
type HashRange struct {
	Start uint64 `json:"start"`
	End   uint64 `json:"end"`
}

type AuditPath struct {
	LeafIndex uint64      `json:"leaf_index"` // leaf node to be verified
	TreeSize  uint64      `json:"tree_size"`
	Nodes     []HashRange `json:"nodes"`
}

type AuditTile struct {
	LeafIndex uint64                  `json:"leaf_index"` // leaf node to be verified
	TreeSize  uint64                  `json:"tree_size"`
	Tiles     map[string][]IndexRange `json:"tiles"`
}

type Tile struct {
	Hashes [][32]byte
}

// IndexRange describes a contiguous slice of hashes read from one tile:
// hashes[Offset : Offset+Count].
type IndexRange struct {
	Offset int `json:"offset"`
	Count  int `json:"count"`
}

type TileAccess struct {
	Path    string       `json:"path"`
	Indices []IndexRange `json:"indices"`
}

type AuditResult struct {
	Timestamp           time.Time    `json:"timestamp"`
	Origin              string       `json:"origin"`
	VerificationSuccess bool         `json:"verification_success"`
	AuditPath           AuditPath    `json:"audit_path"`
	Tiles               []TileAccess `json:"tiles"`
}

// --- RFC 6962 data structures ---

type SignedTreeHead struct {
	TreeSize          uint64      `json:"tree_size"`
	Timestamp         CTTimestamp `json:"timestamp"`
	RootHash          string      `json:"sha256_root_hash"`
	TreeHeadSignature string      `json:"tree_head_signature"`
}

type RFC6962Proof struct {
	LeafIndex uint64   `json:"leaf_index"`
	AuditPath []string `json:"audit_path"`
}

type RFC6962ProofResult struct {
	FetchedAt           time.Time    `json:"fetched_at"`
	VerificationSuccess bool         `json:"verification_success"`
	Log                 *CachedLog   `json:"log"`
	TreeSize            uint64       `json:"tree_size"`
	RootHash            string       `json:"root_hash"`
	LeafHash            string       `json:"leaf_hash"`
	Proof               RFC6962Proof `json:"audit_proof"`
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
		Critical bool   `json:"critial"`
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

type LeafCertificate struct {
	// Raw            string     `json:"raw"`
	Version        int        `json:"version,omitempty"`
	SerialNumber   string     `json:"serial,omitempty"`
	SignatureAlg   string     `json:"sig_alg,omitempty"`
	Issuer         string     `json:"issuer,omitempty"`
	NotBefore      time.Time  `json:"not_before"`
	NotAfter       time.Time  `json:"not_after"`
	Subject        string     `json:"subject,omitempty"`
	PublicKeyAlg   string     `json:"pubkey_alg,omitempty"`
	DNSNames       []string   `json:"dns_names,omitempty"`
	IPAddresses    []string   `json:"ip_addresses,omitempty"`
	SubjectKeyId   string     `json:"ski,omitempty"`
	AuthorityKeyId string     `json:"aki,omitempty"`
	Policies       []x509.OID `json:"policies,omitempty"`
	KeyUsage       []string   `json:"key_usage,omitempty"`
	ExtKeyUsage    []string   `json:"ext_key_usage,omitempty"`
}

type ASN1Cert x509.Certificate

func (ac ASN1Cert) MarshalJSON() ([]byte, error) {
	leafCert := LeafCertificate{
		Version:        ac.Version,
		SerialNumber:   fmt.Sprintf("%x", ac.SerialNumber),
		SignatureAlg:   ac.SignatureAlgorithm.String(),
		Issuer:         ac.Issuer.String(),
		NotBefore:      ac.NotBefore,
		NotAfter:       ac.NotAfter,
		Subject:        ac.Subject.String(),
		PublicKeyAlg:   ac.PublicKeyAlgorithm.String(),
		SubjectKeyId:   fmt.Sprintf("%x", ac.SubjectKeyId),
		AuthorityKeyId: fmt.Sprintf("%x", ac.AuthorityKeyId),
		Policies:       ac.Policies,
		KeyUsage:       parseKeyUsage(ac.KeyUsage),
		ExtKeyUsage:    parseExtKeyUsage(ac.ExtKeyUsage),
	}

	return json.Marshal(leafCert)
}

type TimestampedEntry struct {
	Timestamp    CTTimestamp `json:"timestamp"`
	LogEntryType uint16      `json:"entry_type"`
	ASN1Cert     ASN1Cert    `json:"asn1cert"`      // LogEntryType = 0(x509_entry)
	Precert      Precert     `json:"precert"`       // LogEntryType = 1(precert_entry)
	CtExtensions uint16      `json:"ct_extensions"` // this types is only for RFC 6962, so always "0x0000"
}

func (t TimestampedEntry) Marshal() []byte {
	var b bytes.Buffer
	binary.Write(&b, binary.BigEndian, t.Timestamp)
	binary.Write(&b, binary.BigEndian, t.LogEntryType)
	b.Write(t.Precert.Marshal())
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
			Precert:      t.Precert,
			CtExtensions: t.CtExtensions,
		}
		return json.Marshal(tsPrecert)
	}

	return nil, fmt.Errorf("unexpected log entry type=%d", t.LogEntryType)
}

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

type GetEntriesResponse struct {
	Entries []struct {
		LeafInput []byte `json:"leaf_input"`
		ExtraData []byte `json:"extra_data"`
	} `json:"entries"`
}

type GetEntriesResult struct {
	Log     *CachedLog
	Entries []struct {
		LeafIndex uint64         `json:"leaf_index"`
		LeafInput MerkleTreeLeaf `json:"leaf_input"`
		// TODO: extra_data
	}
}

package main

import (
	"encoding/json"
	"fmt"
	"time"
)

// CT log

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
	LogId       string   `json:"log_id"`
	Key         string   `json:"key"`
	Url         string   `json:"url"`
	State       LogState `json:"state"`
}

type TiledLog struct {
	Description   string   `json:"description"`
	LogId         string   `json:"log_id"`
	Key           string   `json:"key"`
	SubmissionUrl string   `json:"submission_url"`
	MonitoringUrl string   `json:"monitoring_url"`
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

// checkpoint

type Checkpoint struct {
	Origin      string       `json:"origin"`
	TreeSize    int64        `json:"tree_size"`
	RootHash    string       `json:"root_hash"`
	SignedNotes []SignedNote `json:"signed_notes"`
}

type SignedNote struct {
	KeyName             string              `json:"key_name"`
	SignedNoteSignature SignedNoteSignature `json:"signature"`
}

type SignedNoteSignature struct {
	KeyId     string `json:"key_id,omitempty"`
	Signature string `json:"signature,omitempty"`
	Unknown   string `json:"unknown,omitempty"`
}

// log cache

type CachedLog struct {
	Id            int      `json:"id"`
	Operator      string   `json:"operator"`
	Description   string   `json:"description"`
	LogId         string   `json:"log_id"`
	Key           string   `json:"key"`
	KeyId         string   `json:"key_id"`
	Origin        string   `json:"origin"`
	MonitoringUrl string   `json:"monitoring_url"`
	SubmissionUrl string   `json:"submission_url"`
	State         LogState `json:"state"`
}

type LogCache struct {
	FetchedAt      time.Time   `json:"fetched_at"`
	LogListVersion string      `json:"log_list_version"`
	Logs           []CachedLog `json:"logs"`
}

// data tile

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

// TimestamedEntry format https://www.rfc-editor.org/rfc/rfc6962#section-3.4
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
	MonitoringUrl string      `json:"monitoring_url"`
	TileIndexPath string      `json:"tile_index_path"`
	FetchedAt     time.Time   `json:"fetched_time"`
	Entries       []DataEntry `json:"entries"`
}

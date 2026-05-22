package main

import "time"

const (
	extensionTypeLeafIndex uint8 = 0
)

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

type DataEntry struct {
	Timestamp     time.Time `json:"timestamp"`
	EntryType     string    `json:"entry_type"`
	LeafIndex     uint64    `json:"leaf_index"`
	IssuerKeyHash string    `json:"issuer_key_hash,omitempty"`
	Fingerprints  []string  `json:"fps_chain"`
	Certificate   ASN1Cert  `json:"certificate"`
}

type DataTile struct {
	MonitoringURL string      `json:"monitoring_url"`
	TileIndexPath string      `json:"tile_index_path"`
	FetchedAt     time.Time   `json:"fetched_at"`
	Entries       []DataEntry `json:"entries"`
}

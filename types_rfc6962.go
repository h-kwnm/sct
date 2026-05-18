package main

import (
	"crypto/x509"
	"time"
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
		ExtraData []ASN1Cert     `json:"extra_data"`
	}
}

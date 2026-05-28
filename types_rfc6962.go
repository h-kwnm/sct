package main

import (
	"time"
)

// -- Accepted root certificates ---

type GetRootsResponse struct {
	Certificates []string `json:"certificates"`
}

type AcceptedRootCertificates struct {
	Certificates []Certificate `json:"certificates"`
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
	Log     *CachedLog `json:"log"`
	Entries []struct {
		LeafIndex uint64         `json:"leaf_index"`
		LeafInput MerkleTreeLeaf `json:"leaf_input"`
		ExtraData []ASN1Cert     `json:"extra_data"`
	}
}

type GetEntryAndProofResponse struct {
	LeafInput []byte   `json:"leaf_input"`
	ExtraData []byte   `json:"extra_data"`
	AuditPath []string `json:"audit_path"`
}

type EntryWithProof struct {
	LeafInput MerkleTreeLeaf `json:"leaf_input"`
	ExtraData []ASN1Cert     `json:"extra_data"`
	AuditPath []string       `json:"audit_path"`
}

type GetEntryAndProofResult struct {
	FetchedAt time.Time  `json:"fetched_at"`
	Log       *CachedLog `json:"log"`
	// LeafHash is not included in raw response.
	// it is derived from the LeafInput under EntryWithProof
	// so put at this level, out of EntryWithProof.
	LeafHash       string `json:"leaf_hash"`
	EntryWithProof `json:"response"`
}

type AddChainBody struct {
	Chain []string `json:"chain"`
}

type AddChainResponse struct {
	SCTVersion int    `json:"sct_version"`
	ID         string `json:"id"`
	Timestamp  uint64 `json:"timestamp"`
	Extensions []byte `json:"extensions"`
	Signature  string `json:"signature"`
}

type SignedCertificateTimestamp struct {
	SCTVersion int          `json:"sct_version"`
	ID         string       `json:"id"`
	Timestamp  CTTimestamp  `json:"timestamp"`
	Extensions *CtExtension `json:"extensions,omitempty"`
	Signature  string       `json:"signature"`
}

type AddChainResult struct {
	AddedAt                    time.Time  `json:"added_at"`
	Log                        *CachedLog `json:"log"`
	SignedCertificateTimestamp `json:"response"`
}

package main

import "time"

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

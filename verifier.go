package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/bits"
	"slices"
	"time"
)

const tileBitWidth = 8              // 8
const tileWidth = 1 << tileBitWidth // 256

func getAuditPath(m uint64, n uint64) AuditPath {

	if m >= n || n == 0 {
		return AuditPath{} // tree size(n) must be greater than leaf index(m)
	}

	nodes := []HashRange{}
	var lo uint64 = 0
	var hi uint64 = n
	for hi-lo > 1 {
		var k uint64 = 1 << (bits.Len64(hi-lo-1) - 1)
		mid := lo + k
		slog.Debug("getAuditPath", "n", n, "m", m, "hi", hi, "mid", mid, "lo", lo, "k", k)
		if m < mid { // right branch
			nodes = append(nodes, HashRange{Start: mid, End: hi})
			hi = mid
		} else { // left branch
			nodes = append(nodes, HashRange{Start: lo, End: mid})
			lo = mid
		}
	}
	slices.Reverse(nodes)

	return AuditPath{
		LeafIndex: m,
		TreeSize:  n,
		Nodes:     nodes,
	}
}

func buildTileIndex(tileIndex uint64, level int, treeSize uint64) string {
	maxTileIndex := (treeSize - 1) / (tileWidth << (tileBitWidth * level))
	var partialIndex uint64 = 0
	if tileIndex == maxTileIndex {
		partialIndex = (treeSize >> uint(tileBitWidth*level)) % tileWidth
	}

	indexStr := formatTileString(tileIndex, partialIndex)
	if indexStr == "" {
		return ""
	}

	return fmt.Sprintf("tile/%d/%s", level, indexStr)
}

func collectNodeTileAccesses(start, end, n uint64, accesses map[string][]IndexRange) {
	size := end - start
	if size == 1 {
		p := buildTileIndex(start/tileWidth, 0, n)
		accesses[p] = append(accesses[p], IndexRange{Offset: int(start % tileWidth), Count: 1})
		return
	}
	h := bits.Len64(size - 1)
	if size == 1<<h {
		level := h / tileBitWidth
		nodeIndex := start >> (tileBitWidth * level)
		tileIndex := nodeIndex / tileWidth
		p := buildTileIndex(tileIndex, level, n)
		count := 1 << (h % tileBitWidth)
		offset := int(nodeIndex % tileWidth)
		accesses[p] = append(accesses[p], IndexRange{Offset: offset, Count: count})
		return
	}
	k := uint64(1) << (h - 1)
	collectNodeTileAccesses(start, start+k, n, accesses)
	collectNodeTileAccesses(start+k, end, n, accesses)
}

func merkleHash(left, right [32]byte) [32]byte {
	var buf [65]byte
	buf[0] = 0x01
	copy(buf[1:33], left[:])
	copy(buf[33:65], right[:])
	return sha256.Sum256(buf[:])
}

func computeMth(hashes [][32]byte) [32]byte {
	l := len(hashes)
	if l == 1 {
		return hashes[0]
	}

	return merkleHash(computeMth(hashes[:l/2]), computeMth(hashes[l/2:]))
}

// computeNodeHash returns the Merkle hash of the subtree [start, end) using
// the already-fetched tiles map. It recursively decomposes non-power-of-2
// ranges so every tile read covers an exact complete subtree.
func computeNodeHash(start, end, n uint64, tiles map[string]Tile) [32]byte {
	size := end - start
	if size == 1 {
		tileIndex := start / tileWidth
		p := buildTileIndex(tileIndex, 0, n)
		return tiles[p].Hashes[start%tileWidth]
	}
	h := bits.Len64(size - 1)
	if size == 1<<h {
		level := h / tileBitWidth
		nodeIndex := start >> (tileBitWidth * level)
		tileIndex := nodeIndex / tileWidth
		p := buildTileIndex(tileIndex, level, n)
		count := 1 << (h % tileBitWidth)
		offset := int(nodeIndex % tileWidth)
		return computeMth(tiles[p].Hashes[offset : offset+count])
	}
	k := uint64(1) << (h - 1)
	return merkleHash(computeNodeHash(start, start+k, n, tiles), computeNodeHash(start+k, end, n, tiles))
}

func verifyInclusion(ap AuditPath, tiles map[string]Tile, accesses map[string][]IndexRange, cp Checkpoint) (AuditResult, error) {
	current := computeNodeHash(ap.LeafIndex, ap.LeafIndex+1, ap.TreeSize, tiles)

	for _, node := range ap.Nodes {
		sibling := computeNodeHash(node.Start, node.End, ap.TreeSize, tiles)
		if ap.LeafIndex < node.Start {
			current = merkleHash(current, sibling)
		} else {
			current = merkleHash(sibling, current)
		}
	}

	tileAccesses := make([]TileAccess, 0, len(accesses))
	for path, ranges := range accesses {
		tileAccesses = append(tileAccesses, TileAccess{Path: path, Indices: ranges})
	}

	rootHash, err := base64.StdEncoding.DecodeString(cp.RootHash)
	if err != nil {
		return AuditResult{}, err
	}
	return AuditResult{
		Timestamp:           time.Now().UTC(),
		Origin:              cp.Origin,
		VerificationSuccess: current == [32]byte(rootHash),
		AuditPath:           ap,
		Tiles:               tileAccesses,
	}, nil
}

func buildTileAccesses(ap AuditPath) map[string][]IndexRange {
	accesses := map[string][]IndexRange{}
	collectNodeTileAccesses(ap.LeafIndex, ap.LeafIndex+1, ap.TreeSize, accesses)
	for _, node := range ap.Nodes {
		collectNodeTileAccesses(node.Start, node.End, ap.TreeSize, accesses)
	}

	return accesses
}

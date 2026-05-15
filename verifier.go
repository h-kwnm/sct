package main

import (
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"log/slog"
	"math/bits"
	"slices"
	"strconv"
	"time"
)

// --- Static CT API ---

const tileBitWidth = 8              // 8
const tileWidth = 1 << tileBitWidth // 256

func getAuditPath(leafIndex, treeSize uint64) AuditPath {
	if leafIndex >= treeSize || treeSize == 0 {
		return AuditPath{} // tree size(n) must be greater than leaf index(m)
	}

	m := leafIndex
	n := treeSize
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

func formatTileString(index uint64, partialIndex uint64) (string, error) {
	s := ""
	const k = 1000 // tile path group unit
	if index < k {
		s = fmt.Sprintf("%03d", index)
	} else if index < k*k {
		s = fmt.Sprintf("x%03d/%03d", index/k, index%k)
	} else if index < k*k*k {
		s = fmt.Sprintf("x%03d/x%03d/%03d", index/(k*k), (index/k)%k, index%k)
	} else if index < k*k*k*k {
		s = fmt.Sprintf("x%03d/x%03d/x%03d/%03d", index/(k*k*k), (index/(k*k))%k, (index/k)%k, index%k)
	} else {
		return "", fmt.Errorf("invalid index %d", index)
	}

	if partialIndex != 0 {
		s += ".p/" + strconv.FormatUint(partialIndex, 10)
	}

	return s, nil
}

func buildIndex(leafIndex uint64, treeSize uint64) (string, error) {
	tileIndex := leafIndex / tileWidth
	maxTileIndex := (treeSize - 1) / tileWidth
	var partialIndex uint64 = 0
	if tileIndex == maxTileIndex {
		partialIndex = treeSize % tileWidth
	}
	if tileIndex > maxTileIndex {
		return "", fmt.Errorf("invalid index(tile index %d is greater than tree size %d)", tileIndex, maxTileIndex)
	}

	slog.Debug("buildIndex", "leaf_index", leafIndex, "tile_index", tileIndex, "partial_index", partialIndex)

	// <monitoring prefix>/tile/data/<N>[.p/<W>]
	// https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#log-entries
	indexPath, err := formatTileString(tileIndex, partialIndex)
	if err != nil {
		return "", err
	}
	slog.Debug("buildIndex", "tile_index_path", indexPath)

	return indexPath, nil
}

func buildTileIndex(tileIndex uint64, level int, treeSize uint64) (string, error) {
	maxTileIndex := (treeSize - 1) / (tileWidth << (tileBitWidth * level))
	var partialIndex uint64 = 0
	if tileIndex == maxTileIndex {
		partialIndex = (treeSize >> uint(tileBitWidth*level)) % tileWidth
	}

	indexStr, err := formatTileString(tileIndex, partialIndex)
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("tile/%d/%s", level, indexStr), nil
}

func collectNodeTileAccesses(start, end, n uint64, accesses map[string][]IndexRange) {
	size := end - start
	if size == 1 {
		p, err := buildTileIndex(start/tileWidth, 0, n)
		if err != nil {
			panic(err)
		}
		accesses[p] = append(accesses[p], IndexRange{Offset: int(start % tileWidth), Count: 1})
		return
	}
	h := bits.Len64(size - 1)
	if size == 1<<h {
		level := h / tileBitWidth
		nodeIndex := start >> (tileBitWidth * level)
		tileIndex := nodeIndex / tileWidth
		p, err := buildTileIndex(tileIndex, level, n)
		if err != nil {
			panic(err)
		}
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

func computeMTH(hashes [][32]byte) [32]byte {
	l := len(hashes)
	if l == 1 {
		return hashes[0]
	}

	return merkleHash(computeMTH(hashes[:l/2]), computeMTH(hashes[l/2:]))
}

// computeNodeHash returns the Merkle hash of the subtree [start, end) using
// the already-fetched tiles map. It recursively decomposes non-power-of-2
// ranges so every tile read covers an exact complete subtree.
func computeNodeHash(start, end, n uint64, tiles map[string]Tile) [32]byte {
	size := end - start
	if size == 1 {
		tileIndex := start / tileWidth
		p, err := buildTileIndex(tileIndex, 0, n)
		if err != nil {
			panic(err)
		}
		return tiles[p].Hashes[start%tileWidth]
	}
	h := bits.Len64(size - 1)
	if size == 1<<h {
		level := h / tileBitWidth
		nodeIndex := start >> (tileBitWidth * level)
		tileIndex := nodeIndex / tileWidth
		p, err := buildTileIndex(tileIndex, level, n)
		if err != nil {
			panic(err)
		}
		count := 1 << (h % tileBitWidth)
		offset := int(nodeIndex % tileWidth)
		return computeMTH(tiles[p].Hashes[offset : offset+count])
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

func getAuditTiles(leafIndex, treeSize uint64) AuditTile {
	ap := getAuditPath(leafIndex, treeSize)

	accesses := buildTileAccesses(ap)

	return AuditTile{
		Tiles:     accesses,
		LeafIndex: leafIndex,
		TreeSize:  treeSize,
	}
}

// --- RFC 6962 ---

// Verify audit path returned by get-proof-by-hash, following the steps in RFC 9162
// https://www.rfc-editor.org/rfc/rfc9162#name-verifying-an-inclusion-proo
func verifyInclusionRFC6962(pr *RFC6962ProofResult) error {
	ap := pr.Proof.AuditPath

	if len(ap) == 0 {
		pr.VerificationSuccess = (pr.LeafHash == pr.RootHash)
		return nil
	}

	lh, err := base64.StdEncoding.DecodeString(pr.LeafHash)
	if err != nil {
		return fmt.Errorf("failed to base64-decode leaf hash: %w", err)
	}
	if len(lh) != 32 {
		return fmt.Errorf("unexpected leaf hash length %d", len(lh))
	}
	current := [32]byte(lh)
	fn := pr.Proof.LeafIndex
	sn := pr.TreeSize - 1

	for i, b64Hash := range ap {
		if sn == 0 {
			return fmt.Errorf("verification failed, unexpected sn==0")
		}
		node, err := base64.StdEncoding.DecodeString(b64Hash)
		if err != nil {
			return fmt.Errorf("failed to base64-decode audit path node hash at %d: %w", i, err)
		}
		if len(node) != 32 {
			return fmt.Errorf("unexpected node hash length %d", len(node))
		}
		nodeHash := [32]byte(node)

		if fn&1 == 1 || fn == sn {
			current = merkleHash(nodeHash, current)
			for fn != 0 && fn&1 == 0 {
				fn >>= 1
				sn >>= 1
			}
		} else {
			current = merkleHash(current, nodeHash)
		}
		fn >>= 1
		sn >>= 1
	}

	if sn != 0 {
		return fmt.Errorf("verification failed, unexpected sn!=0")
	}

	h := base64.StdEncoding.EncodeToString(current[:])

	pr.VerificationSuccess = (pr.RootHash == h)

	return nil
}

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"slices"
	"sync"
	"time"
)

const tileBitWidth = 8              // 8
const tileWidth = 1 << tileBitWidth // 256

func getAuditPath(m uint64, n uint64) AuditPath {

	if m >= n || n == 0 {
		return AuditPath{} // tree size(n) must be greater than leaf index(m)
	}

	nodes := []MthNode{}
	var lo uint64 = 0
	var hi uint64 = n
	for hi-lo > 1 {
		var k uint64 = 1 << (bits.Len64(hi-lo-1) - 1)
		mid := lo + k
		if m < mid { // right branch
			nodes = append(nodes, MthNode{Start: mid, End: hi})
			hi = mid
		} else { // left branch
			nodes = append(nodes, MthNode{Start: lo, End: mid})
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

// collectNodeTilePaths adds to pathSet all tile paths needed to compute the
// hash of the subtree [start, end) in a tree of size n.
func collectNodeTilePaths(start, end, n uint64, pathSet map[string]bool) {
	size := end - start
	if size == 1 {
		p := buildTileIndex(start/tileWidth, 0, n)
		pathSet[p] = true
		return
	}
	h := bits.Len64(size - 1)
	if size == 1<<h {
		// complete subtree: one tile entry at level h/tileBitWidth
		level := h / tileBitWidth
		tileIndex := (start >> (tileBitWidth * level)) / tileWidth
		p := buildTileIndex(tileIndex, level, n)
		pathSet[p] = true
		return
	}
	// non-power-of-2: split into complete left half and smaller right half
	k := uint64(1) << (h - 1)
	collectNodeTilePaths(start, start+k, n, pathSet)
	collectNodeTilePaths(start+k, end, n, pathSet)
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

func getTilePaths(ap AuditPath) []string {
	pathSet := map[string]bool{}
	collectNodeTilePaths(ap.LeafIndex, ap.LeafIndex+1, ap.TreeSize, pathSet)
	for _, node := range ap.Nodes {
		collectNodeTilePaths(node.Start, node.End, ap.TreeSize, pathSet)
	}
	var paths []string
	for p := range pathSet {
		paths = append(paths, p)
	}
	return paths
}

func fetchTile(url string) ([]byte, error) {
	cache, err := loadTileCache(url)
	if err != nil {
		return nil, fmt.Errorf("failed to load cache: %w", err)
	}
	if cache != nil {
		return cache, nil
	}

	req, err := http.NewRequestWithContext(context.Background(), "GET", url, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create a request: %s, %w", url, err)
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to fetch a tile: %s, %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected response status code: %s, %d", url, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 16<<10))
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %s, %w", url, err)
	}

	// intentionally cache partial tiles although it is not recommended.
	// partial tiles are not used since relevant tiles are identified during each invocations.
	saveTileCache(url, body)

	return body, nil
}

func parseTile(r io.Reader) (Tile, error) {
	tile := Tile{}
	for {
		var h = [32]byte{}
		n, err := io.ReadFull(r, h[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			return Tile{}, fmt.Errorf("failed to read a tile at %d: %w", n, err)
		}
		tile.Hashes = append(tile.Hashes, h)
	}

	return tile, nil
}

type tileResult struct {
	path string
	data []byte
	err  error
}

func fetchTiles(ap AuditPath, log *CachedLog) (map[string]Tile, error) {
	paths := getTilePaths(ap)

	results := make([]tileResult, len(paths))
	var wg sync.WaitGroup

	for i, p := range paths {
		url := log.MonitoringUrl + p

		wg.Add(1)
		go func(i int, url string) {
			defer wg.Done()
			data, err := fetchTile(url)
			results[i] = tileResult{p, data, err}
		}(i, url)
	}
	wg.Wait()

	tiles := make(map[string]Tile, len(results))
	for _, res := range results {
		if res.err != nil {
			return nil, res.err
		}
		reader := bytes.NewReader(res.data)

		tile, err := parseTile(reader)
		if err != nil {
			return nil, fmt.Errorf("fetchTiles: %s, %w", res.path, err)
		}
		tiles[res.path] = tile
	}

	return tiles, nil
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

func verifyInclusion(ap AuditPath, tiles map[string]Tile, cp Checkpoint) (AuditResult, error) {
	current := computeNodeHash(ap.LeafIndex, ap.LeafIndex+1, ap.TreeSize, tiles)

	for _, node := range ap.Nodes {
		sibling := computeNodeHash(node.Start, node.End, ap.TreeSize, tiles)
		if ap.LeafIndex < node.Start {
			current = merkleHash(current, sibling)
		} else {
			current = merkleHash(sibling, current)
		}
	}

	accesses := map[string][]IndexRange{}
	collectNodeTileAccesses(ap.LeafIndex, ap.LeafIndex+1, ap.TreeSize, accesses)
	for _, node := range ap.Nodes {
		collectNodeTileAccesses(node.Start, node.End, ap.TreeSize, accesses)
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

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/bits"
	"net/http"
	"slices"
	"strconv"
	"sync"
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
			h := bits.Len64(hi - mid - 1)
			level := h / tileBitWidth
			count := 1 << (h % tileBitWidth)
			nodeIndex := mid >> (tileBitWidth * level)
			tileIndex := nodeIndex / tileWidth

			var size uint64 = 1 << (tileBitWidth * level)
			offset := (mid / size) % tileWidth
			nodes = append(nodes, MthNode{
				Start:         mid,
				End:           hi,
				Level:         level,
				NodeIndex:     nodeIndex,
				NodeTileIndex: tileIndex,
				Offset:        offset,
				Count:         count,
				NodeTilePath:  buildTileIndex(tileIndex, level, n),
			})
			hi = mid
		} else { //left branch
			h := bits.Len64(mid - lo - 1)
			level := h / tileBitWidth
			count := 1 << (h % tileBitWidth)
			nodeIndex := lo >> (tileBitWidth * level)
			tileIndex := nodeIndex / tileWidth

			var size uint64 = 1 << (tileBitWidth * level)
			offset := (lo / size) % tileWidth
			nodes = append(nodes, MthNode{
				Start:         lo,
				End:           mid,
				Level:         level,
				NodeIndex:     nodeIndex,
				NodeTileIndex: tileIndex,
				Offset:        offset,
				Count:         count,
				NodeTilePath:  buildTileIndex(tileIndex, level, n),
			})
			lo = mid
		}
	}
	slices.Reverse(nodes)

	return AuditPath{
		LeafIndex:    m,
		LeafTilePath: buildTileIndex(m/tileWidth, 0, n),
		Offset:       m % tileWidth,
		TreeSize:     n,
		Nodes:        nodes,
	}
}

func buildTileIndex(tileIndex uint64, level int, treeSize uint64) string {
	indexStr := fmt.Sprintf("tile/%d", level)

	maxTileIndex := (treeSize - 1) / (tileWidth << (tileBitWidth * level))
	var partialIndex uint64 = 0
	if tileIndex == maxTileIndex {
		partialIndex = (treeSize >> uint(tileBitWidth*level)) % tileWidth
	}

	var d uint64 = 1000
	if tileIndex < d {
		indexStr = fmt.Sprintf("%s/%03d", indexStr, tileIndex)
	} else if tileIndex < d*d {
		indexStr = fmt.Sprintf("%s/x%03d/%03d", indexStr, tileIndex/d, tileIndex%d)
	} else if tileIndex < d*d*d {
		indexStr = fmt.Sprintf("%s/x%03d/x%03d/%03d", indexStr, tileIndex/(d*d), (tileIndex/d)%d, tileIndex%d)
	} else {
		return ""
	}

	if partialIndex != 0 {
		indexStr += ".p/" + strconv.FormatUint(partialIndex, 10)
	}

	return indexStr
}

func getTilePaths(ap AuditPath) []string {
	t := map[string]bool{}
	var paths []string

	t[ap.LeafTilePath] = true
	paths = append(paths, ap.LeafTilePath)
	for _, node := range ap.Nodes {
		if _, ok := t[node.NodeTilePath]; !ok {
			t[node.NodeTilePath] = true
			paths = append(paths, node.NodeTilePath)
		}
	}

	return paths
}

func fetchTile(url string) ([]byte, error) {
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

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read HTTP response body: %s, %w", url, err)
	}

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

	j, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Println(string(j))
	}

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

func verifyInclusion(ap AuditPath, tiles map[string]Tile, cp Checkpoint) (bool, error) {
	current := tiles[ap.LeafTilePath].Hashes[ap.Offset]
	fmt.Printf("[debug] leaf hash: %x\n", current)

	for i, node := range ap.Nodes {
		p := node.NodeTilePath
		offset := int(node.Offset)
		count := node.Count
		slice := tiles[p].Hashes[offset : offset+count]
		sibling := computeMth(slice)

		var dir string
		if ap.LeafIndex < node.Start {
			current = merkleHash(current, sibling)
			dir = "current|sibling"
		} else {
			current = merkleHash(sibling, current)
			dir = "sibling|current"
		}
		fmt.Printf("[debug] step %d: [%d,%d) level=%d count=%d dir=%s → %x\n",
			i, node.Start, node.End, node.Level, count, dir, current)
	}

	rootHash, err := base64.StdEncoding.DecodeString(cp.RootHash)
	if err != nil {
		return false, err
	}

	fmt.Printf("[debug] computed: %x\n", current)
	fmt.Printf("[debug] expected: %x\n", rootHash)
	return current == [32]byte(rootHash), nil
}

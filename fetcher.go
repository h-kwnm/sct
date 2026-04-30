package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

var logListUrl = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

// Some log operators could apply request rate limits. for example, Geomys's log has such a limit.
// Customize User-Agent to include an email address to mitigate such limits when needed.
// https://groups.google.com/a/chromium.org/g/ct-policy/c/KCzYEIIZSxg/m/zD26fYw4AgAJ
// Following is example of such User-Agent value.
//
//	sct/0.1 (your@email.com)
//	sct/0.1 (+https://github.com/h-kwnm/sct)
//	sct/0.1 (github.com/h-kwnm/sct)
const userAgent = "sct/" + version + " (github.com/h-kwnm/sct)"

func fetchLogList() (*LogList, error) {
	resp, err := httpClient.Get(logListUrl)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failure: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d, url: %s, body: %s", resp.StatusCode, logListUrl, string(body))
	}

	var logList LogList
	if err := json.Unmarshal(body, &logList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal log list JSON: %w", err)
	}

	return &logList, nil
}

func parseSignedNotes(lines []string, origin string) ([]SignedNote, error) {
	var signedNotes []SignedNote
	for _, line := range lines {
		if !strings.HasPrefix(line, "— ") {
			continue
		}
		trimmed := strings.TrimPrefix(line, "— ")
		tuple := strings.SplitN(trimmed, " ", 2)
		if len(tuple) == 2 {
			var sn SignedNote
			if tuple[0] == origin {
				sn.KeyName = origin
				raw, err := base64.StdEncoding.DecodeString(tuple[1])
				if err != nil {
					return nil, err
				}
				r := bytes.NewReader(raw)
				var keyId uint32
				if err := binary.Read(r, binary.BigEndian, &keyId); err != nil {
					return nil, err
				}
				rawSig, err := io.ReadAll(r)
				if err != nil {
					return nil, err
				}
				sig := base64.StdEncoding.EncodeToString(rawSig)
				sn.SignedNoteSignature = SignedNoteSignature{
					KeyId:     fmt.Sprintf("%x", keyId),
					Signature: sig,
				}
			} else {
				sn.KeyName = tuple[0]
				sn.SignedNoteSignature = SignedNoteSignature{
					Unknown: tuple[1],
				}
			}

			signedNotes = append(signedNotes, sn)
		}
	}

	return signedNotes, nil
}

func fetchCheckpoint(log *CachedLog) (Checkpoint, error) {
	// https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#checkpoints
	checkpointEndpoint := log.MonitoringUrl + "checkpoint"

	slog.Debug("fetchCheckpoint", "url", checkpointEndpoint)

	req, err := http.NewRequestWithContext(context.Background(), "GET", checkpointEndpoint, nil)
	if err != nil {
		return Checkpoint{}, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("HTTP request failure: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
	if err != nil {
		return Checkpoint{}, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != 200 {
		return Checkpoint{}, fmt.Errorf("unexpected status code: %d, url: %s, body: %s", resp.StatusCode, checkpointEndpoint, string(body))
	}

	parts := strings.Split(string(body), "\n")
	if len(parts) < 4 {
		return Checkpoint{}, fmt.Errorf("invalid response body, too short lines: %d lines", len(parts))
	}

	origin := parts[0]
	if len(origin) > 1024 {
		return Checkpoint{}, fmt.Errorf("origin is too long: %d", len(parts[0]))
	}

	treeSize, err := strconv.ParseUint(parts[1], 10, 64)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("invalid tree size: %w", err)
	}

	if len(parts[2]) > 512 {
		return Checkpoint{}, fmt.Errorf("root hash is too long: %d", len(parts[2]))
	}

	signedNotes, err := parseSignedNotes(parts[4:], origin)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("failed to parse signed notes: %w", err)
	}

	return Checkpoint{
		Origin:      origin,
		TreeSize:    treeSize,
		RootHash:    parts[2],
		SignedNotes: signedNotes,
	}, nil
}

func formatTileString(index uint64, partialIndex uint64) string {
	s := ""
	const k = 1000
	if index < k {
		s = fmt.Sprintf("%03d", index)
	} else if index < k*k {
		s = fmt.Sprintf("x%03d/%03d", index/k, index%k)
	} else if index < k*k*k {
		s = fmt.Sprintf("x%03d/x%03d/%03d", index/(k*k), (index/k)%k, index%k)
	} else if index < k*k*k*k {
		s = fmt.Sprintf("x%03d/x%03d/x%03d/%03d", index/(k*k*k), (index/(k*k))%k, (index/k)%k, index%k)
	} else {
		return ""
	}

	if partialIndex != 0 {
		s += ".p/" + strconv.FormatUint(partialIndex, 10)
	}

	return s
}

func buildIndex(leafIndex uint64, treeSize uint64) string {
	tileIndex := leafIndex / tileWidth
	maxTileIndex := (treeSize - 1) / tileWidth
	var partialIndex uint64 = 0
	if tileIndex == maxTileIndex {
		partialIndex = treeSize % tileWidth
	}
	if tileIndex > maxTileIndex {
		return ""
	}

	slog.Debug("buildIndex", "leaf_index", leafIndex, "tile_index", tileIndex, "partial_index", partialIndex)

	// <monitoring prefix>/tile/data/<N>[.p/<W>]
	// https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#log-entries
	indexPath := formatTileString(tileIndex, partialIndex)
	slog.Debug("buildIndex", "tile_index_path", indexPath)

	return indexPath
}

func fetchDataTile(leafIndex uint64, log *CachedLog) ([]byte, string, error) {
	cp, err := fetchCheckpoint(log)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch checkpoint: %w", err)
	}
	tileIndexPath := buildIndex(leafIndex, cp.TreeSize)
	if tileIndexPath == "" {
		return nil, "", fmt.Errorf("failed to determine index path: leafIndex=%d, treeSize=%d", leafIndex, cp.TreeSize)
	}

	dataTileEndpoint := fmt.Sprintf("%stile/data/%s", log.MonitoringUrl, tileIndexPath)
	slog.Debug("fetchDataTile", "url", dataTileEndpoint)

	req, err := http.NewRequestWithContext(context.Background(), "GET", dataTileEndpoint, nil)
	if err != nil {
		return nil, "", err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("HTTP request failure: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 10<<20)) // 10MB max
	if err != nil {
		return nil, "", fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, "", fmt.Errorf("unexpected status code: %d, url: %s, body: %s", resp.StatusCode, dataTileEndpoint, string(body))
	}

	return body, tileIndexPath, nil
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

type tileResult struct {
	path string
	data []byte
	err  error
}

func fetchTiles(accesses map[string][]IndexRange, log *CachedLog) (map[string]Tile, error) {
	results := make([]tileResult, len(accesses))
	var wg sync.WaitGroup

	i := 0
	for k := range accesses {
		url := log.MonitoringUrl + k

		wg.Add(1)
		go func(i int, url string) {
			defer wg.Done()
			data, err := fetchTile(url)
			results[i] = tileResult{k, data, err}
		}(i, url)
		i++
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

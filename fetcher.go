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
	"time"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

const logListUrl = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

// Some log operators could apply request rate limits. for example, Geomys's log has such a limit.
// Cuustomize User-Agent to include an email address to mitigate such limits when needed.
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
		trimmed := strings.TrimPrefix(line, "— ")
		tuple := strings.Split(trimmed, " ")
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

func fetchCheckpoint(monitoringUrl string) (Checkpoint, error) {
	// https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#checkpoints
	checkpointEndpoint := monitoringUrl + "checkpoint"

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

	treeSize, err := strconv.ParseInt(parts[1], 10, 64)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("invalid tree size: %w", err)
	}
	if treeSize < 0 {
		return Checkpoint{}, fmt.Errorf("invalid tree size: %d", treeSize)
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

func buildIndex(leafIndex int64, tileLogUrl string) (string, error) {
	if leafIndex <= 0 {
		return "", fmt.Errorf("invalid leaf index: %d", leafIndex)
	}

	cp, err := fetchCheckpoint(tileLogUrl)
	if err != nil {
		return "", err
	}

	tileIndex := (leafIndex - 1) / 256
	maxTileIndex := (cp.TreeSize - 1) / 256
	var partialIndex int64 = 0
	if tileIndex == maxTileIndex {
		partialIndex = leafIndex % 256
	}
	if tileIndex > maxTileIndex {
		return "", fmt.Errorf("invalid index size %d (greater than current tree size %d)", leafIndex, cp.TreeSize)
	}

	slog.Debug("buildIndex", "leaf_index", leafIndex, "tile_index", tileIndex, "partial_index", partialIndex)

	// <monitoring prefix>/tile/data/<N>[.p/<W>]
	// https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#log-entries
	indexPath := ""
	if tileIndex < 1000 {
		indexPath = fmt.Sprintf("%03d", tileIndex)
	} else if tileIndex < 1000*1000 {
		indexPath = fmt.Sprintf("x%03d/%03d", tileIndex/1000, tileIndex%1000)
	} else if tileIndex < 1000*1000*1000 {
		indexPath = fmt.Sprintf("x%03d/x%03d/%03d", tileIndex/(1000*1000), (tileIndex/1000)%1000, tileIndex%1000)
	} else {
		return "", fmt.Errorf("failed to translate leaf index into index path, tile_index: %d", tileIndex)
	}

	if partialIndex != 0 {
		indexPath += ".p/" + strconv.FormatInt(partialIndex, 10)
	}
	slog.Debug("buildIndex", "tile_index_path", indexPath)

	return indexPath, nil
}

func fetchDataTile(leafIndex int64, tileLogUrl string) ([]byte, string, error) {
	tileIndexPath, err := buildIndex(leafIndex, tileLogUrl)
	if err != nil {
		return nil, "", fmt.Errorf("failed to get index path: %w", err)
	}

	dataTileEndpoint := tileLogUrl + "tile/data/" + tileIndexPath
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

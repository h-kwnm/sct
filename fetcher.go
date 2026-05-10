package main

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

var logListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

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
	resp, err := httpClient.Get(logListURL)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failure: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d, url: %s, body: %s", resp.StatusCode, logListURL, string(body))
	}

	var logList LogList
	if err := json.Unmarshal(body, &logList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal log list JSON: %w", err)
	}

	return &logList, nil
}

func fetchCheckpoint(log *CachedLog) (Checkpoint, error) {
	// https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#checkpoints
	checkpointEndpoint := log.MonitoringURL + "checkpoint"

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

func fetchDataTile(leafIndex uint64, log *CachedLog) ([]byte, string, error) {
	cp, err := fetchCheckpoint(log)
	if err != nil {
		return nil, "", fmt.Errorf("failed to fetch checkpoint: %w", err)
	}
	tileIndexPath, err := buildIndex(leafIndex, cp.TreeSize)
	if err != nil {
		return nil, "", fmt.Errorf("failed to build index path: %w", err)
	}
	if tileIndexPath == "" {
		return nil, "", fmt.Errorf("failed to determine index path: leafIndex=%d, treeSize=%d", leafIndex, cp.TreeSize)
	}

	dataTileEndpoint := fmt.Sprintf("%stile/data/%s", log.MonitoringURL, tileIndexPath)
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
		url := log.MonitoringURL + k

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

func fetchServerCertificate(endpoint string) ([]*x509.Certificate, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint URL %s: %w", endpoint, err)
	}
	var address string
	if u.Port() == "" {
		address = fmt.Sprintf("%s:443", u.Hostname())
	} else {
		address = fmt.Sprintf("%s:%s", u.Hostname(), u.Port())
	}

	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true, // no verification since the result do not matter here
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", endpoint, err)
	}

	certs := conn.ConnectionState().PeerCertificates

	return certs, nil
}

func fetchSth(log *CachedLog) (SignedTreeHead, error) {
	u := strings.TrimSuffix(log.URL, "/")
	endpoint := fmt.Sprintf("%s/ct/v1/get-sth", u)

	req, err := http.NewRequestWithContext(context.Background(), "GET", endpoint, nil)
	if err != nil {
		return SignedTreeHead{}, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return SignedTreeHead{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return SignedTreeHead{}, fmt.Errorf("unexpected response status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
	if err != nil {
		return SignedTreeHead{}, err
	}

	var data SignedTreeHead
	err = json.Unmarshal(body, &data)
	if err != nil {
		return SignedTreeHead{}, err
	}

	return data, nil
}

func fetchProofByHash(h string, log *CachedLog) (RFC6962ProofResult, error) {
	sth, err := fetchSth(log)
	if err != nil {
		return RFC6962ProofResult{}, err
	}

	u := strings.TrimSuffix(log.URL, "/")
	params := url.Values{}
	params.Set("hash", h)
	params.Set("tree_size", strconv.FormatUint(sth.TreeSize, 10))

	endpoint := fmt.Sprintf("%s/ct/v1/get-proof-by-hash?%s", u, params.Encode())

	req, err := http.NewRequestWithContext(context.Background(), "GET", endpoint, nil)
	if err != nil {
		return RFC6962ProofResult{}, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return RFC6962ProofResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return RFC6962ProofResult{}, fmt.Errorf("unexpected response status code: %d", resp.StatusCode)
	}

	ts := time.Now().UTC()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return RFC6962ProofResult{}, err
	}

	var p RFC6962Proof
	if err := json.Unmarshal(body, &p); err != nil {
		return RFC6962ProofResult{}, err
	}

	return RFC6962ProofResult{
		FetchedAt: ts,
		Log:       log,
		Hash:      h,
		TreeSize:  sth.TreeSize,
		Proof:     p,
	}, nil
}

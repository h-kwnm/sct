package main

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"sync"
)

func fetchCheckpoint(log *CachedLog) (Checkpoint, error) {
	// https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#checkpoints
	checkpointEndpoint := log.MonitoringURL + "checkpoint"

	slog.Debug("fetchCheckpoint", "url", checkpointEndpoint)

	body, err := httpGet(context.Background(), checkpointEndpoint, 64<<10)
	if err != nil {
		return Checkpoint{}, fmt.Errorf("fetching from %s: %w", checkpointEndpoint, err)
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

	body, err := httpGet(context.Background(), dataTileEndpoint, 10<<20) // 10MB max
	if err != nil {
		return nil, "", fmt.Errorf("fetching from %s: %w", dataTileEndpoint, err)
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

	body, err := httpGet(context.Background(), url, 16<<10)
	if err != nil {
		return nil, fmt.Errorf("fetching from %s: %w", url, err)
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

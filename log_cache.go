package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func cacheFilePath() (string, error) {
	base, err := os.UserCacheDir()
	if err != nil {
		return "", err
	}

	dir := filepath.Join(base, "sct")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	return filepath.Join(dir, "logs.json"), nil
}

func loadLogCache() (*LogCache, error) {
	path, err := cacheFilePath()
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(path)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	var cache LogCache
	if err := json.Unmarshal(data, &cache); err != nil {
		return nil, err
	}
	return &cache, nil
}

func saveLogCache(cache *LogCache) error {
	path, err := cacheFilePath()
	if err != nil {
		return err
	}
	data, err := json.Marshal(cache)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0644)
}

func buildLogCache(logList *LogList) (*LogCache, error) {
	cache := &LogCache{
		FetchedAt:      time.Now().UTC(),
		LogListVersion: logList.Version,
	}

	id := 1
	for _, operator := range logList.Operators {
		for _, log := range operator.Logs {
			cache.Logs = append(cache.Logs, CachedLog{
				ID:          id,
				Operator:    operator.Name,
				Description: log.Description,
				LogID:       log.LogID,
				Key:         log.Key,
				URL:         log.URL,
				State:       log.State,
				APIType:     APITypeRFC6962,
			})
			id++
		}
		for _, tiledLog := range operator.TiledLogs {
			// this part intentionally assumes that "origin", "key name", and schema-less submission URL are the same.
			// however this is not always true. according to the specification, "origin" SHOULD be schema-less URL
			// and "origin" SHOULD match key name. they are only recommendation.
			// https://github.com/C2SP/C2SP/blob/main/tlog-checkpoint.md#note-text
			u, err := url.Parse(tiledLog.SubmissionURL)
			if err != nil {
				return nil, err
			}
			origin := u.Host + strings.TrimSuffix(u.Path, "/")

			// derive key id for the keys included in the log_list.json.
			// it is used for TreeHeadSignature.
			// https://github.com/C2SP/C2SP/blob/main/signed-note.md#signatures
			// https://github.com/C2SP/C2SP/blob/main/static-ct-api.md
			// > The Signed Tree Head signature and timestamp are encoded as a note signature.
			// > The key name of the signature line MUST match the checkpoint origin line.
			// > The key ID MUST be the first four bytes (interpreted in big-endian order) of
			// > the SHA-256 hash of the following sequence: the key name, a newline character (0x0A),
			// > the signature type identifier byte 0x05, and the 32-byte RFC 6962 LogID.
			logIDBytes, err := base64.StdEncoding.DecodeString(tiledLog.LogID)
			if err != nil {
				return nil, err
			}
			var kbuf bytes.Buffer
			kbuf.Write([]byte(origin))
			kbuf.Write([]byte{0x0a})
			kbuf.Write([]byte{0x05}) // 0x05 - static ct api signature type
			kbuf.Write(logIDBytes)
			khash := sha256.Sum256(kbuf.Bytes())
			keyID := khash[0:4]

			cache.Logs = append(cache.Logs, CachedLog{
				ID:            id,
				Operator:      operator.Name,
				Description:   tiledLog.Description,
				LogID:         tiledLog.LogID,
				Key:           tiledLog.Key,
				KeyID:         fmt.Sprintf("%x", keyID),
				Origin:        origin,
				MonitoringURL: tiledLog.MonitoringURL,
				SubmissionURL: tiledLog.SubmissionURL,
				State:         tiledLog.State,
				APIType:       APITypeStaticCT,
			})
			id++
		}
	}

	return cache, nil
}

func logByID(id int, apiType APIType) (*CachedLog, error) {
	cache, err := loadLogCache()
	if err != nil {
		return nil, fmt.Errorf("failed to load log cache: %w", err)
	}
	if cache == nil {
		return nil, fmt.Errorf("no log cache found, run 'sct logs' first")
	}
	for i := range cache.Logs {
		if cache.Logs[i].ID == id {
			if cache.Logs[i].APIType != apiType {
				return nil, fmt.Errorf("unexpected log was specified(invalid API type: expected %s, but the log %d is %s type)", apiType, id, cache.Logs[i].APIType)
			}
			return &cache.Logs[i], nil
		}
	}
	return nil, fmt.Errorf("no log with id %d", id)
}

func logByLogID(logID string) (*CachedLog, error) {
	cache, err := loadLogCache()
	if err != nil {
		return nil, fmt.Errorf("failed to load log cache: %w", err)
	}
	if cache == nil {
		return nil, fmt.Errorf("no log cache found, run 'sct logs' first")
	}
	for i := range cache.Logs {
		// note: this is under assumption that the same key(log id) is not shared among multiple logs
		if cache.Logs[i].LogID == logID {
			return &cache.Logs[i], nil
		}
	}
	return nil, fmt.Errorf("no log with log id %s", logID)
}

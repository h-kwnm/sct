package main

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
)

func temporaryFilePath(url string) (string, error) {
	base := os.TempDir() // use temporary dir, not cache dir to save storage

	dir := filepath.Join(base, "sct")
	if err := os.MkdirAll(dir, 0755); err != nil {
		return "", err
	}

	h := sha256.Sum256([]byte(url))
	fname := fmt.Sprintf("%x.tile", h[:4])

	return filepath.Join(dir, fname), nil
}

func loadTileCache(url string) ([]byte, error) {
	fpath, err := temporaryFilePath(url)
	if err != nil {
		return nil, fmt.Errorf("failed to locate temporary file path: %v", err)
	}

	data, err := os.ReadFile(fpath)
	if errors.Is(err, fs.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}

	return data, nil
}

func saveTileCache(url string, data []byte) error {
	fpath, err := temporaryFilePath(url)
	if err != nil {
		return fmt.Errorf("failed to locate temporary file path: %v", err)
	}

	if err := os.WriteFile(fpath, data, 0644); err != nil {
		return fmt.Errorf("failed to save tile cache: %w", err)
	}

	return nil
}

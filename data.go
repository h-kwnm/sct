package main

import (
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

func runData(args []string) {
	fs := flag.NewFlagSet("data", flag.ExitOnError)
	logId := fs.Int("log", 0, "log id (see 'sct logs')")
	index := fs.Int64("index", 0, "leaf index")
	outpath := fs.String("out", "", "data tile entries output location")
	fs.Parse(args)

	if *logId == 0 {
		fmt.Fprintln(os.Stderr, "usage: sct data --log <id> --index <n>")
		os.Exit(1)
	}

	log, err := logById(*logId)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	tile, tileIndexPath, err := fetchDataTile(*index, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch data tile: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("fetched %d bytes from %s\n", len(tile), log.MonitoringUrl)

	p, err := saveDataTileEntries(tile, log.MonitoringUrl, tileIndexPath, *outpath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to save data tile entries to file: %v\n", err)
		os.Exit(1)
	}

	fmt.Printf("data tile entries saved to file: %s\n", p)
}

func buildDataOutputPath(outpath string, url string) (string, error) {
	hash := sha256.Sum256([]byte(url))
	unixEpoch := time.Now().UTC().Unix()
	filename := fmt.Sprintf("data_%x_%d.json", hash[:8], unixEpoch)
	var dataTileFilepath string = ""
	if outpath == "" {
		userCachePath, err := os.UserCacheDir()
		if err != nil {
			return "", err
		}
		dataTileFilepath = filepath.Join(userCachePath, "sct", filename)
	} else {
		dataTileFilepath = filepath.Join(outpath, filename)
	}

	return dataTileFilepath, nil
}

func saveDataTileEntries(data []byte, url string, tilePath string, outpath string) (string, error) {
	entries, err := parseDataTile(data)
	if err != nil {
		return "", err
	}

	result := DataTile{
		MonitoringUrl: url,
		TileIndexPath: tilePath,
		FetchedAt:     time.Now().UTC(),
		Entries:       entries,
	}

	j, err := json.Marshal(result)
	if err != nil {
		return "", err
	}

	dataTileFilepath, err := buildDataOutputPath(outpath, url)
	if err != nil {
		return "", fmt.Errorf("failed to build output file name: %w", err)
	}

	err = os.WriteFile(dataTileFilepath, j, 0644)
	if err != nil {
		return "", err
	}

	return dataTileFilepath, nil
}

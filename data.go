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
	index := fs.Uint64("index", 0, "leaf index")
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

	entries, err := parseDataTile(tile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse data tile: %v\n", err)
		os.Exit(1)
	}

	found := false
	for _, e := range entries {
		if e.LeafIndex == *index {
			b, err := json.MarshalIndent(e, "", "  ")
			if err != nil {
				fmt.Fprintf(os.Stderr, "failed to marshal entry: %v\n", err)
			}
			fmt.Println(string(b))
			found = true
			break
		}
	}
	if !found {
		fmt.Fprintf(os.Stderr, "leaf index %d not found in tile. note that the latest leaf index is (treeSize - 1) since tree size is 1-based and leaf index is 0-based\n", *index)
	}

	if *outpath != "" {
		p, err := saveDataTileEntries(entries, log.MonitoringUrl, tileIndexPath, *outpath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to save data tile entries to file: %v\n", err)
			os.Exit(1)
		}

		fmt.Fprintf(os.Stderr, "data tile entries saved to file: %s\n", p)
	}

}

func buildDataOutputPath(outpath string, url string) (string, error) {
	hash := sha256.Sum256([]byte(url))
	unixEpoch := time.Now().UTC().Unix()
	filename := fmt.Sprintf("data_%x_%d.json", hash[:8], unixEpoch)

	return filepath.Join(outpath, filename), nil
}

func saveDataTileEntries(entries []DataEntry, url string, tilePath string, outpath string) (string, error) {
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

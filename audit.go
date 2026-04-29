package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func runAudit(args []string) {
	fs := flag.NewFlagSet("audit", flag.ExitOnError)
	logId := fs.Int("log", 0, "log id")
	index := fs.Uint64("index", 0, "leaf index")
	fs.Parse(args)

	if *logId == 0 {
		fmt.Fprintln(os.Stderr, "usage: sct audit --log <id> --index <n>")
		os.Exit(1)
	}

	log, err := logById(*logId)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	cp, err := fetchCheckpoint(log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch checkpoint: %v\n", err)
		os.Exit(1)
	}

	auditPath := getAuditPath(*index, cp.TreeSize)

	accesses := buildTileAccesses(auditPath)

	tiles, err := fetchTiles(accesses, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch tiles: %v\n", err)
		os.Exit(1)
	}

	res, err := verifyInclusion(auditPath, tiles, accesses, cp)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error during verification: %v\n", err)
		os.Exit(1)
	}

	j, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal audit verification result: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(j))
}

func runAuditPath(args []string) {
	fs := flag.NewFlagSet("audit-path", flag.ExitOnError)
	index := fs.Uint64("index", 0, "leaf index")
	size := fs.Uint64("size", 1, "tree size")
	fs.Parse(args)

	path := getAuditPath(*index, *size)

	j, err := json.MarshalIndent(path, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal mth nodes: %v\n", err)
		os.Exit(1)
	}
	fmt.Println(string(j))
}

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func runGetEntryAndProof(args []string) {
	fs := flag.NewFlagSet("get-entry-and-proof", flag.ExitOnError)
	logID := fs.Int("log", 0, "log id (see 'sct logs --type rfc6962')")
	leafIndex := fs.Uint64("index", 0, "the index of the desired entry")
	treeSize := fs.Uint64("size", 1, "the tree size of the tree for which the proof is desired")
	fs.Parse(args)

	log, err := logByID(*logID, APITypeRFC6962)
	if err != nil {
		fmt.Fprintf(os.Stderr, "log %d (type %s) not found: %v\n", *logID, APITypeRFC6962, err)
		os.Exit(1)
	}

	res, err := fetchEntryAndProof(*leafIndex, *treeSize, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch entry and proof: %v", err)
		os.Exit(1)
	}

	j, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal get-entry-and-proof result JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(j))
}

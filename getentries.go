package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func runGetEntries(args []string) {
	fs := flag.NewFlagSet("get-entries", flag.ExitOnError)
	logID := fs.Int("log", 0, "log id (see 'sct logs --type rfc6962')")
	index := fs.Uint64("index", 0, "start leaf index to fetch")
	offset := fs.Uint64("count", 0, "offset between start and end index")
	fs.Parse(args)

	log, err := logByID(*logID, APITypeRFC6962)
	if err != nil {
		fmt.Fprintf(os.Stderr, "no log found with ID=%d, type=%s\n", *logID, APITypeRFC6962)
		os.Exit(1)
	}
	entries, err := fetchEntries(*index, *offset, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch entries: %v\n", err)
	}

	j, err := json.MarshalIndent(entries, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal entries JSON: %v\n", err)
	}

	fmt.Println(string(j))
}

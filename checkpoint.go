package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func runCheckpoint(args []string) {
	fs := flag.NewFlagSet("checkpoint", flag.ExitOnError)
	logId := fs.Int("log", 0, "log id (see 'sct logs')")
	fs.Parse(args)

	if *logId == 0 {
		fmt.Fprintln(os.Stderr, "usage: sct checkpoint --log <id>")
		os.Exit(1)
	}

	log, err := logById(*logId)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error: %v\n", err)
		os.Exit(1)
	}

	cp, err := fetchCheckpoint(log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "error fetching checkpoint: %v\n", err)
		os.Exit(1)
	}

	b, err := json.MarshalIndent(cp, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "error marshaling JSON-formatted checkpoint : %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Checkpoint: %s\n", string(b))
}

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func runGetRoots(args []string) {
	fs := flag.NewFlagSet("get-roots", flag.ExitOnError)
	logID := fs.Int("log", 0, "log id (see 'sct logs')")
	fs.Parse(args)

	log, err := logByIDAny(*logID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "log %d not found: %v\n", *logID, err)
		os.Exit(1)
	}

	ar, err := fetchAcceptedRootCertificate(log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch accepted root certificates: %v\n", err)
		os.Exit(1)
	}

	j, err := json.MarshalIndent(ar, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal accepted root certificates JSON: %v", err)
		os.Exit(1)
	}

	fmt.Println(string(j))
}

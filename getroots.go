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
	// apiType := fs.String("type", "", "filter by API type (static, rfc6962)")
	fs.Parse(args)

	// log lookup here is confusing, but leave it for now since I want to make it clear
	// that get-roots operation is common in both Static CT API and RFC 6962
	var log *CachedLog
	var e1, e2 error
	log, e1 = logByID(*logID, APITypeRFC6962)
	if e1 != nil {
		log, e2 = logByID(*logID, APITypeStaticCT)
		if e2 != nil {
			fmt.Fprintf(os.Stderr, "log with ID=%d not found in both static and rfc6962 type: %v, %v\n", *logID, e1, e2)
			os.Exit(1)
		}
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

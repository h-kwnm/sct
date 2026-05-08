package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func runGetSth(args []string) {
	fs := flag.NewFlagSet("get-sth", flag.ExitOnError)
	logId := fs.Int("log", 0, "log id (see 'sct logs --type rfc6962')")
	fs.Parse(args)

	log, err := logById(*logId, APITypeRFC6962)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to load log cache %d of type %s: %v\n", *logId, APITypeRFC6962, err)
		os.Exit(1)
	}

	sth, err := fetchSth(log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to fetch signed tree head from %s: %v\n", log.Url, err)
		os.Exit(1)
	}

	j, err := json.MarshalIndent(sth, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal json: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(j))

}

package main

import (
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

func runGetSct(args []string) {
	fs := flag.NewFlagSet("get-sct", flag.ExitOnError)
	pemFile := fs.String("pem", "", "PEM-formatted certificate file")
	fs.Parse(args)

	if *pemFile == "" {
		fmt.Fprintln(os.Stderr, "usage: sct get-sct --pem <pem_file_path>")
		os.Exit(1)
	}

	pemData, err := os.ReadFile(*pemFile)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to open pem file: %v\n", err)
		os.Exit(1)
	}
	block, _ := pem.Decode(pemData)
	if block == nil {
		fmt.Fprintf(os.Stderr, "failed to decode pem file: %v", *pemFile)
	}

	sct, err := parseCertSCT(block.Bytes)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to parse SCTs: %v\n", err)
		os.Exit(1)
	}

	j, err := json.MarshalIndent(sct, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal SCTs into JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(j))
}

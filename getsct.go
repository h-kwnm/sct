package main

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

func runGetSct(args []string) {
	fs := flag.NewFlagSet("get-sct", flag.ExitOnError)
	pemFile := fs.String("pem", "", "PEM-formatted certificate file")
	url := fs.String("url", "", "URL to fetch server certificate")
	fs.Parse(args)

	if *pemFile == "" && *url == "" {
		fmt.Fprintln(os.Stderr, "usage: sct get-sct [--pem <pem_file_path> | --url <url>]")
		os.Exit(1)
	}

	var cert *x509.Certificate
	var err error
	if *pemFile != "" {
		pemData, err := os.ReadFile(*pemFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to open pem file: %v\n", err)
			os.Exit(1)
		}
		block, _ := pem.Decode(pemData)
		if block == nil {
			fmt.Fprintf(os.Stderr, "failed to decode pem file: %v\n", *pemFile)
			os.Exit(1)
		}

		cert, err = x509.ParseCertificate(block.Bytes)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse input certificate: %v\n", err)
			os.Exit(1)
		}
	} else { // --url <url>
		cert, err = fetchServerCertificate(*url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch server certificate from %s: %v\n", *url, err)
			os.Exit(1)
		}
	}

	sct, err := parseCertSCT(cert)
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

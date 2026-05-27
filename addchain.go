package main

import (
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func runAddChain(args []string) {
	fs := flag.NewFlagSet("add-chain", flag.ExitOnError)
	logID := fs.Int("log", 0, "log id (see 'sct logs')")
	url := fs.String("url", "", "URL to fetch server certificate with its chain")
	insecure := fs.Bool("insecure", false, "skip verification of the endpoint's server certificate")
	// TODO: pass cert and chain by files
	// pem := ...
	// issCert := ...
	fs.Parse(args)

	log, err := logByIDAny(*logID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "log %d not found: %v\n", *logID, err)
		os.Exit(1)
	}

	certs, err := fetchServerCertificate(*url, *insecure)
	if err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}

	var fullChain AddChainBody
	for _, cert := range certs {
		b64Cert := base64.StdEncoding.EncodeToString(cert.Raw)
		fullChain.Chain = append(fullChain.Chain, b64Cert)
	}

	result, err := addChainToLog(fullChain, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to add certificate chain fetched from %s: %v\n", *url, err)
		os.Exit(1)
	}

	j, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal add-chain result JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(j))
}

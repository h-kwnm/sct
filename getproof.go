package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"os"
)

func runGetProofByHash(args []string) {
	fs := flag.NewFlagSet("get-proof-by-hash", flag.ExitOnError)
	pemFile := fs.String("pem", "", "PEM-formatted certificate file")
	issFile := fs.String("iss", "", "PEM-formatted issuer certificate")
	logID := fs.Int("?log", 0, "log id (see 'sct logs --type rfc6962')")
	url := fs.String("url", "", "URL to fetch server certificate")
	fs.Parse(args)

	if *url == "" && (*pemFile == "" || *issFile == "") {
		fmt.Fprintln(os.Stderr, "usage: sct get-proof-by-hash [--pem <pem_file_path> --iss <ssuer-cert>|--url <url>]")
		os.Exit(1)
	}

	var cert, issCert *x509.Certificate
	var err error
	if *url != "" {
		chain, err := fetchServerCertificate(*url)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch certificates from %s: %v\n", *url, err)
			os.Exit(1)
		}
		if len(chain) < 2 {
			fmt.Fprintf(os.Stderr, "endpoint %s did not send issuer certificate(len=%d):%v\n", *url, len(chain), err)
			os.Exit(1)
		}
		cert = chain[0]
		issCert = chain[1]
	} else {
		cert, err = readCertFile(*pemFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse input certificate: %v\n", err)
			os.Exit(1)
		}

		issCert, err = readCertFile(*issFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse input certificate: %v\n", err)
			os.Exit(1)
		}
	}

	leaves, logs, err := buildMerkleTreeLeaves(cert, issCert)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to build merkle tree leaf: %v\n", err)
		os.Exit(1)
	}

	results := make([]RFC6962ProofResult, len(leaves))
	for i, leaf := range leaves {
		leafBytes := leaf.Marshal()
		h := sha256.Sum256(append([]byte{0x00}, leafBytes...))
		b64Hash := base64.StdEncoding.EncodeToString(h[:])

		results[i], err = fetchProofByHash(b64Hash, logs[i])
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch audit proof from log %d: %v\n", *logID, err)
			os.Exit(1)
		}

	}

	j, err := json.MarshalIndent(results, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal audit proof result JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(j))

}

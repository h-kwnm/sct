package main

import (
	"crypto/x509"
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

	pemFile := fs.String("pem", "", "PEM-formatted certificate file")
	chainFile := fs.String("chain", "", "PEM-formatted certificate chain file")

	fs.Parse(args)

	usageMsg := "usage: sct add-chain --log <id> [--pem <pem_file_path> --chain <cert-chain>|--url <url>]"
	if *logID == 0 {
		fmt.Fprintln(os.Stderr, usageMsg)
		os.Exit(1)
	}

	if *url == "" && (*pemFile == "" || *chainFile == "") {
		fmt.Fprintln(os.Stderr, usageMsg)
		os.Exit(1)
	}

	log, err := logByIDAny(*logID)
	if err != nil {
		fmt.Fprintf(os.Stderr, "log %d not found: %v\n", *logID, err)
		os.Exit(1)
	}

	var certs []*x509.Certificate
	if *url != "" {
		certs, err = fetchServerCertificate(*url, *insecure)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to fetch certificates from %s: %v\n", *url, err)
			os.Exit(1)
		}
		if len(certs) < 2 {
			fmt.Fprintf(os.Stderr, "endpoint %s did not send intermediate certificates: %d\n", *url, len(certs))
			os.Exit(1)
		}
	} else {
		leafCert, err := readCertFile(*pemFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse input certificate file: %v\n", err)
			os.Exit(1)
		}
		certs = append(certs, leafCert)

		chainCerts, err := readCertChainFile(*chainFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "failed to parse input certificate chain file: %v\n", err)
			os.Exit(1)
		}
		certs = append(certs, chainCerts...)
	}

	var fullChain AddChainBody
	for _, cert := range certs {
		b64Cert := base64.StdEncoding.EncodeToString(cert.Raw)
		fullChain.Chain = append(fullChain.Chain, b64Cert)
	}

	result, err := addChainToLog(fullChain, log)
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to add certificate chain: %v\n", err)
		os.Exit(1)
	}

	j, err := json.MarshalIndent(result, "", "  ")
	if err != nil {
		fmt.Fprintf(os.Stderr, "failed to marshal add-chain result JSON: %v\n", err)
		os.Exit(1)
	}

	fmt.Println(string(j))
}

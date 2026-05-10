package main

import (
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"os"
)

func readCertFile(fname string) (*x509.Certificate, error) {
	certData, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certData)
	if certBlock == nil {
		return nil, fmt.Errorf("no PEM block found in %s", fname)
	}

	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}

	return cert, nil
}

func runGetProofByHash(args []string) {
	fs := flag.NewFlagSet("get-proof-by-hash", flag.ExitOnError)
	pemFile := fs.String("pem", "", "PEM-formatted certificate file")
	issFile := fs.String("iss", "", "PEM-formatted issuer certificate")
	logId := fs.Int("?log", 0, "log id (see 'sct logs --type rfc6962')")
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
			fmt.Fprintf(os.Stderr, "failed to fetch audit proof from log %d: %v\n", *logId, err)
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

func trimSctExtension(rawTbs []byte) ([]byte, error) {
	sctListOID := asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}

	var tbs TbsCertificate
	if _, err := asn1.Unmarshal(rawTbs, &tbs); err != nil {
		return nil, err
	}

	filtered := tbs.Extensions[:0]
	for _, ext := range tbs.Extensions {
		if !ext.Id.Equal(sctListOID) {
			filtered = append(filtered, ext)
		}
	}
	tbs.Extensions = filtered

	return asn1.Marshal(tbs)
}

func buildMerkleTreeLeaves(cert, issCert *x509.Certificate) ([]MerkleTreeLeaf, []*CachedLog, error) {
	// build Precert
	// - isk (32 bytes)
	// - tbs
	tbs, err := trimSctExtension(cert.RawTBSCertificate)
	if err != nil {
		return []MerkleTreeLeaf{}, nil, fmt.Errorf("failed to trim SCT extension from TbsCertificate: %w", err)
	}
	isk := sha256.Sum256(issCert.RawSubjectPublicKeyInfo)
	precert := Precert{RawTbsCertificate: tbs, IssuerKeyHash: isk}

	// build TimestampedEntry
	// - timestamp (8 bytes)
	// - entry_type (2 bytes) -> always 0(timestamped_entry)
	// - Precert -> for now, ignore "x509_entry" pattern
	// - CtExtensions -> this is for RFC 6962, so always 0x0000
	scts, err := parseCertSCT(cert)
	if err != nil {
		return []MerkleTreeLeaf{}, nil, err
	}

	var logIds []string
	var tsEntries []TimestampedEntry
	for _, sct := range scts {
		if sct.CtExtensions == nil {
			logIds = append(logIds, sct.LogId)
			tsEntries = append(tsEntries, TimestampedEntry{
				Timestamp:    sct.Timestamp,
				LogEntryType: entryTypePrecert,
				Precert:      precert,
				CtExtensions: 0x0000,
			})
		}
	}

	// build MekleTreeLeaf
	// - version (1 byte) -> always 0(v1)
	// - leaf_type (1 byte) -> always 0(timestamped_entry)
	// - timestamped_entry
	leaves := make([]MerkleTreeLeaf, len(tsEntries))
	logs := make([]*CachedLog, len(logIds))
	for i, ts := range tsEntries {
		leaves[i] = MerkleTreeLeaf{
			Version:          0,
			MerkleLeafType:   0,
			TimestampedEntry: ts,
		}

		l, err := logByLogId(logIds[i])
		if err != nil {
			return []MerkleTreeLeaf{}, nil, err
		}
		logs[i] = l
	}

	return leaves, logs, nil
}

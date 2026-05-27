package main

import (
	"crypto/x509"
	"encoding/pem"
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

func readCertChainFile(fname string) ([]*x509.Certificate, error) {
	certsData, err := os.ReadFile(fname)
	if err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for {
		var block *pem.Block
		block, certsData = pem.Decode(certsData)
		if block == nil {
			break
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			return nil, err
		}
		certs = append(certs, cert)
	}
	if len(certs) == 0 {
		return nil, fmt.Errorf("no PEM block found in %s", fname)
	}

	return certs, nil
}

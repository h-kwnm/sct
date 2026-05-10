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

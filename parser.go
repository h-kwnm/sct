package main

import (
	"encoding/asn1"
	"fmt"
	"io"
)

const maxCertSize = 1 << 20 // 1MB

const maxCtExtSize = 1 << 10

var (
	oidExtensionSubjectKeyId          = asn1.ObjectIdentifier{2, 5, 29, 14}
	oidExtensionKeyUsage              = asn1.ObjectIdentifier{2, 5, 29, 15}
	oidExtensionSubjectAltName        = asn1.ObjectIdentifier{2, 5, 29, 17}
	oidExtensionBasicConstraints      = asn1.ObjectIdentifier{2, 5, 29, 19}
	oidExtensionCRLDistributionPoints = asn1.ObjectIdentifier{2, 5, 29, 31}
	oidExtensionCertificatePolicies   = asn1.ObjectIdentifier{2, 5, 29, 32}
	oidExtensionAuthorityKeyId        = asn1.ObjectIdentifier{2, 5, 29, 35}
	oidExtensionExtendedKeyUsage      = asn1.ObjectIdentifier{2, 5, 29, 37}
	oidExtensionAuthorityInfoAccess   = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 1, 1}
	oidExtensionSCTList               = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 11129, 2, 4, 2}
)

func readUint24(r io.Reader) (uint32, error) {
	var b [3]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("reading 3 bytes: %w", err)
	}

	return uint32(b[0])<<16 | uint32(b[1])<<8 | uint32(b[2]), nil
}

func readUint40(r io.Reader) (uint64, error) {
	var b [5]byte
	if _, err := io.ReadFull(r, b[:]); err != nil {
		return 0, fmt.Errorf("reading 5 bytes: %w", err)
	}

	return uint64(b[0])<<32 | uint64(b[1])<<24 | uint64(b[2])<<16 | uint64(b[3])<<8 | uint64(b[4]), nil
}

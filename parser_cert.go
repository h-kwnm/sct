package main

import (
	"crypto/x509"
	"fmt"
)

func parseKeyUsage(ku x509.KeyUsage) []string {
	var usages []string
	// https://pkg.go.dev/crypto/x509#KeyUsage
	for _, f := range []struct {
		bit  x509.KeyUsage
		name string
	}{
		{x509.KeyUsageDigitalSignature, "digitalSignature"},
		{x509.KeyUsageContentCommitment, "contentCommitment"},
		{x509.KeyUsageKeyEncipherment, "keyEncipherment"},
		{x509.KeyUsageDataEncipherment, "dataEncipherment"},
		{x509.KeyUsageKeyAgreement, "keyAgreement"},
		{x509.KeyUsageCertSign, "keyCertSign"},
		{x509.KeyUsageCRLSign, "cRLSign"},
		{x509.KeyUsageEncipherOnly, "encipherOnly"},
		{x509.KeyUsageDecipherOnly, "decipherOnly"},
	} {
		if ku&f.bit != 0 {
			usages = append(usages, fmt.Sprintf("%s(%08b)", f.name, f.bit))
		}
	}

	return usages
}

func parseExtKeyUsage(eku []x509.ExtKeyUsage) []string {
	type ekuEntry struct {
		name string
		oid  string
	}
	// https://pkg.go.dev/crypto/x509#ExtKeyUsage
	// https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.12
	ekuMap := map[x509.ExtKeyUsage]ekuEntry{
		x509.ExtKeyUsageAny:                            {"anyExtendedKeyUsage", "2.5.29.37.0"},
		x509.ExtKeyUsageServerAuth:                     {"serverAuth", "1.3.6.1.5.5.7.3.1"},
		x509.ExtKeyUsageClientAuth:                     {"clientAuth", "1.3.6.1.5.5.7.3.2"},
		x509.ExtKeyUsageCodeSigning:                    {"codeSigning", "1.3.6.1.5.5.7.3.3"},
		x509.ExtKeyUsageEmailProtection:                {"emailProtection", "1.3.6.1.5.5.7.3.4"},
		x509.ExtKeyUsageIPSECEndSystem:                 {"ipsecEndSystem", "1.3.6.1.5.5.7.3.5"},
		x509.ExtKeyUsageIPSECTunnel:                    {"ipsecTunnel", "1.3.6.1.5.5.7.3.6"},
		x509.ExtKeyUsageIPSECUser:                      {"ipsecUser", "1.3.6.1.5.5.7.3.7"},
		x509.ExtKeyUsageTimeStamping:                   {"timeStamping", "1.3.6.1.5.5.7.3.8"},
		x509.ExtKeyUsageOCSPSigning:                    {"OCSPSigning", "1.3.6.1.5.5.7.3.9"},
		x509.ExtKeyUsageMicrosoftServerGatedCrypto:     {"msSGC", "1.3.6.1.4.1.311.10.3.3"},
		x509.ExtKeyUsageNetscapeServerGatedCrypto:      {"nsSGC", "2.16.840.1.113730.4.1"},
		x509.ExtKeyUsageMicrosoftCommercialCodeSigning: {"msCodeCom", "1.3.6.1.4.1.311.2.1.22"},
		x509.ExtKeyUsageMicrosoftKernelCodeSigning:     {"msKernelCode", "1.3.6.1.4.1.311.61.1.1"},
		// other examples of EKU, which might be supported in future
		// https://docs.openssl.org/master/man5/x509v3_config/#extended-key-usage
		// https://www.rfc-editor.org/rfc/rfc9809.html
	}

	var usages []string
	for _, u := range eku {
		if v, ok := ekuMap[u]; ok {
			usages = append(usages, fmt.Sprintf("%s(%s)", v.name, v.oid))
		} else {
			usages = append(usages, fmt.Sprintf("unknown(%d)", u))
		}
	}

	return usages
}

package main

import (
	"bytes"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"time"
)

const (
	entryTypeX509    uint16 = 0
	entryTypePrecert uint16 = 1
)

const (
	extensionTypeLeafIndex uint8 = 0
)

const maxCertSize = 1 << 20 // 1MB

const maxCtExtSize = 1 << 10

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

func parseSignedEntry(r *bytes.Reader, de *DataEntry, entryType uint16) ([]byte, error) {
	switch entryType {
	case entryTypeX509:
		de.EntryType = "x509"
	case entryTypePrecert:
		de.EntryType = "precert"
		var issuerKeyHash [32]byte // 32 bytes issuer key hash
		if _, err := io.ReadFull(r, issuerKeyHash[:]); err != nil {
			return nil, fmt.Errorf("reading issuer key hash: %w", err)
		}
		de.IssuerKeyHash = fmt.Sprintf("%x", issuerKeyHash)

		slog.Debug("parseSignedEntry", "iskLen", 32)
	default:
		return nil, fmt.Errorf("unknown entry type: %d", entryType)
	}

	derLen, err := readUint24(r) // 3 bytes length header
	if err != nil {
		return nil, fmt.Errorf("reading certificate length: %w", err)
	}
	if derLen > maxCertSize {
		return nil, fmt.Errorf("invalid certificate size: %d", derLen)
	}

	certDer := make([]byte, derLen)

	// ASN.1 x509 entry
	if _, err := io.ReadFull(r, certDer); err != nil {
		return nil, fmt.Errorf("reading ASN.1 X509 entry: %w", err)
	}

	slog.Debug("parseSignedEntry", "headerLen", 3, "derLen", derLen)

	return certDer, nil
}

func parseCtExtensions(r *bytes.Reader, de *DataEntry) error {
	// parse ct extensions. only leaf_index(0) is defined at this time.
	// https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#sct-extension
	var extLen uint16 // 2 bytes length header
	if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
		return fmt.Errorf("reading ct extension length: %w", err)
	}
	if extLen > maxCtExtSize {
		return fmt.Errorf("too long ct extension length: %d", extLen)
	}

	slog.Debug("parseCtExtensions", "headerLen", 2, "extLen", extLen)

	if extLen > 0 {
		extData := make([]byte, extLen)
		if _, err := io.ReadFull(r, extData); err != nil {
			return fmt.Errorf("reading ct extensions: %w", err)
		}
		extReader := bytes.NewReader(extData)

		var extType uint8
		if err := binary.Read(extReader, binary.BigEndian, &extType); err != nil {
			return fmt.Errorf("reading ct extension type: %w", err)
		}

		switch extType {
		case extensionTypeLeafIndex:
			var leafIndexLen uint16
			if err := binary.Read(extReader, binary.BigEndian, &leafIndexLen); err != nil {
				return fmt.Errorf("reading leaf index ct extension length: %w", err)
			}
			if leafIndexLen != 5 {
				return fmt.Errorf("invalid leaf index length: %d", leafIndexLen)
			}

			leafIndex, err := readUint40(extReader)
			if err != nil {
				return fmt.Errorf("reading leaf index in ct extension type %d: %w", extensionTypeLeafIndex, err)
			}
			de.LeafIndex = leafIndex

			slog.Debug("parseCtExtensions", "extType", extType, "leafIndex", leafIndex)
		default:
			return fmt.Errorf("unknown ct extension type: %d", extType)
		}

		if extReader.Len() > 0 {
			return fmt.Errorf("ct extension has %d unexpected trailing bytes", extReader.Len())
		}
	}

	return nil
}

func parseTimestampedEntry(r *bytes.Reader, de *DataEntry) ([]byte, uint16, error) {
	// timestamp (8 bytes) - TimestampedEntry.timestamp
	var ts uint64
	if err := binary.Read(r, binary.BigEndian, &ts); err != nil {
		return nil, 0, fmt.Errorf("reading timestamp: %w", err)
	}
	timestamp := time.UnixMilli(int64(ts)).UTC()
	de.Timestamp = timestamp

	slog.Debug("parseTimestampedEntry", "fixedLen", 8, "timestamp", timestamp)

	// entry_type (2 bytes) - TimestampedEntry.entry_type
	var entryType uint16
	if err := binary.Read(r, binary.BigEndian, &entryType); err != nil {
		return nil, 0, fmt.Errorf("reading entry type: %w", err)
	}

	slog.Debug("parseTimestampedEntry", "fixedLen", 2, "entryType", entryType)

	// signed_entry - TimestampedEntry.signed_entry
	certDer, err := parseSignedEntry(r, de, entryType)
	if err != nil {
		return nil, 0, fmt.Errorf("parsing signed_entry: %w", err)
	}

	// extensions - TimestampedEntry.extensions
	if err := parseCtExtensions(r, de); err != nil {
		return nil, 0, fmt.Errorf("parsing ct extensions: %w", err)
	}

	return certDer, entryType, nil
}

func parseTileLeaf(r *bytes.Reader) (DataEntry, error) {
	certEntry := CertEntry{
		DNSNames:    []string{},
		IPAddresses: []string{},
		Policies:    []string{},
	}

	entry := DataEntry{
		Certificate:  certEntry,
		Fingerprints: []string{},
	}

	certDer, entryType, err := parseTimestampedEntry(r, &entry)
	if err != nil {
		return DataEntry{}, fmt.Errorf("parsing timestampedentry: %w", err)
	}

	// ASN.1Cert for precert entry. empty in case of x509 entry.
	if entryType == entryTypePrecert {
		precertLen, err := readUint24(r) // 3 bytes length header
		if err != nil {
			return DataEntry{}, fmt.Errorf("reading precert length: %w", err)
		}
		if precertLen > maxCertSize {
			return DataEntry{}, fmt.Errorf("invalid certificate size: %d", precertLen)
		}

		certDer = make([]byte, precertLen)
		if _, err := io.ReadFull(r, certDer); err != nil {
			return DataEntry{}, fmt.Errorf("reading precert entry: %w", err)
		}
		slog.Debug("parseTileLeaf", "headerLen", 3, "precertLen", precertLen)
	}

	// Parse fingerprints
	var fpLen uint16 // 2 bytes header length
	if err := binary.Read(r, binary.BigEndian, &fpLen); err != nil {
		return DataEntry{}, fmt.Errorf("reading fingerprint chain length: %w", err)
	}
	if fpLen%32 != 0 {
		return DataEntry{}, fmt.Errorf("fingerprint chain must be a multiple of 32: %d", fpLen)
	}

	if fpLen > 0 {
		fps := make([]byte, fpLen)
		_, err := io.ReadFull(r, fps)
		if err != nil {
			return DataEntry{}, fmt.Errorf("reading fingerprints: %w", err)
		}

		fpsReader := bytes.NewReader(fps)
		for fpsReader.Len() > 0 {
			var fp [32]byte
			_, err := io.ReadFull(fpsReader, fp[:])
			if err != nil {
				return DataEntry{}, fmt.Errorf("reading fingerprint: %w", err)
			}

			entry.Fingerprints = append(entry.Fingerprints, fmt.Sprintf("%x", fp))
		}
	}

	slog.Debug("parseTileLeaf", "headerLen", 2, "fpLen", fpLen)

	if cert, err := x509.ParseCertificate(certDer); err == nil {
		entry.Certificate.Subject = cert.Subject.String()
		entry.Certificate.Issuer = cert.Issuer.String()
		entry.Certificate.Serial = cert.SerialNumber.Text(16) // convert big int to hex string
		entry.Certificate.NotBefore = cert.NotBefore.UTC()
		entry.Certificate.NotAfter = cert.NotAfter.UTC()

		// SubjectKeyIdentifer is NOT RECOMMENDED in CA/B Forum BR, so this value could be empty.
		// 7.1.2.7.6 Subscriber Certificate Extensions
		// https://cabforum.org/working-groups/server/baseline-requirements/documents/CA-Browser-Forum-TLS-BR-2.2.6.pdf
		// As an example, Let's Encrypt seems to follow this policy in a newer profile.
		// https://community.letsencrypt.org/t/request-for-feedback-do-you-use-the-subject-key-identifier-field-of-our-certificates/222108
		entry.Certificate.SubjectKeyId = fmt.Sprintf("%x", cert.SubjectKeyId)

		// TODO: is it preferrable to add ski value calculated from "cert.PublicKey" when it is absent?

		entry.Certificate.AuthorityKeyId = fmt.Sprintf("%x", cert.AuthorityKeyId)
		entry.Certificate.SignatureAlg = cert.SignatureAlgorithm.String()
		entry.Certificate.PublicKeyAlg = cert.PublicKeyAlgorithm.String()

		entry.Certificate.DNSNames = append(entry.Certificate.DNSNames, cert.DNSNames...)

		for _, ip := range cert.IPAddresses {
			entry.Certificate.IPAddresses = append(entry.Certificate.IPAddresses, ip.String())
		}

		// Policy OID reference https://cabforum.org/resources/object-registry/
		for _, oid := range cert.Policies {
			entry.Certificate.Policies = append(entry.Certificate.Policies, oid.String())
		}
	} else {
		slog.Error("failed to parse ASN.1", "err", err)
		return DataEntry{}, fmt.Errorf("parsing x509 certificate: %w", err)
	}

	return entry, nil
}

func parseDataTile(data []byte) ([]DataEntry, error) {
	r := bytes.NewReader(data)
	var entries []DataEntry

	for r.Len() > 0 {
		slog.Debug("data tile", "entry_index", len(entries))
		entry, err := parseTileLeaf(r)
		if err != nil {
			return nil, fmt.Errorf("parsing a leaf certificate in data tile: %w", err)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

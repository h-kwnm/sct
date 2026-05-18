package main

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
)

func parseTile(r io.Reader) (Tile, error) {
	tile := Tile{}
	for {
		var h = [32]byte{}
		n, err := io.ReadFull(r, h[:])
		if err == io.EOF {
			break
		}
		if err != nil {
			return Tile{}, fmt.Errorf("failed to read a tile at %d: %w", n, err)
		}
		tile.Hashes = append(tile.Hashes, h)
	}

	return tile, nil
}

func parseSignedEntry(r *bytes.Reader, de *DataEntry, entryType uint16) ([]byte, error) {
	switch entryType {
	case entryTypeX509:
		de.EntryType = "x509"
	case entryTypePrecert:
		de.EntryType = "precert"
		var issuerKeyHash [32]byte // 32 bytes issuer key hash, only in case of precert
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

func parseCtExtension(r *bytes.Reader) (CtExtension, error) {
	// parse ct extension. only leaf_index(0) is defined at this time.
	// https://github.com/C2SP/C2SP/blob/main/static-ct-api.md#sct-extension
	var ctExt CtExtension

	var extLen uint16 // 2 bytes length header
	if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
		return CtExtension{}, fmt.Errorf("reading ct extension length: %w", err)
	}
	if extLen > maxCtExtSize {
		return CtExtension{}, fmt.Errorf("too long ct extension length: %d", extLen)
	}
	ctExt.Length = extLen

	slog.Debug("parseCtExtension", "headerLen", 2, "extLen", extLen)

	if extLen > 0 {
		extData := make([]byte, extLen)
		if _, err := io.ReadFull(r, extData); err != nil {
			return CtExtension{}, fmt.Errorf("reading ct extensions: %w", err)
		}
		extReader := bytes.NewReader(extData)

		var extType uint8
		if err := binary.Read(extReader, binary.BigEndian, &extType); err != nil {
			return CtExtension{}, fmt.Errorf("reading ct extension type: %w", err)
		}
		ctExt.Type = extType

		switch extType {
		case extensionTypeLeafIndex:
			var leafIndexLen uint16
			if err := binary.Read(extReader, binary.BigEndian, &leafIndexLen); err != nil {
				return CtExtension{}, fmt.Errorf("reading leaf index ct extension length: %w", err)
			}
			if leafIndexLen != 5 {
				return CtExtension{}, fmt.Errorf("invalid leaf index length: %d", leafIndexLen)
			}

			leafIndex, err := readUint40(extReader)
			if err != nil {
				return CtExtension{}, fmt.Errorf("reading leaf index in ct extension type %d: %w", extensionTypeLeafIndex, err)
			}
			ctExt.Value = leafIndex

			slog.Debug("parseCtExtension", "extType", extType, "leafIndex", leafIndex)
		default:
			// just ignore unknown extension for now, as specified in static-ct-api specification.
			// currently "leaf_index" is the only extension type.
			// return CtExtension{}, fmt.Errorf("unknown ct extension type: %d", extType)
			var unknownTypeLen uint16
			if err := binary.Read(extReader, binary.BigEndian, &unknownTypeLen); err != nil {
				return CtExtension{}, fmt.Errorf("failed to read unknown type ct extension length: %w", err)
			}

			unknownTypeValue := make([]byte, unknownTypeLen)
			if _, err := io.ReadFull(extReader, unknownTypeValue); err != nil {
				return CtExtension{}, fmt.Errorf("failed to read unknown type ct extension value: %w", err)
			}

			slog.Debug("parseCtExtension", "extType", extType, "unknownCtTypeValue", fmt.Sprintf("%x", unknownTypeValue))

			return ctExt, nil
		}
	}

	return ctExt, nil
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
	ext, err := parseCtExtension(r)
	if err != nil {
		return nil, 0, fmt.Errorf("parsing ct extensions: %w", err)
	}
	if ext.Length == 0 {
		// SCT CtExtensions MUST include "leaf_index" type ct extension.
		return nil, 0, fmt.Errorf("invalid empty ct extension(it must include leaf_index extension)")
	} else {
		de.LeafIndex = ext.Value
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
		slog.Debug("data tile", "entryIndex", len(entries))
		entry, err := parseTileLeaf(r)
		if err != nil {
			return nil, fmt.Errorf("parsing a leaf certificate in data tile: %w", err)
		}

		entries = append(entries, entry)
	}

	return entries, nil
}

func parseSignedNotes(lines []string, origin string) ([]SignedNote, error) {
	var signedNotes []SignedNote
	for _, line := range lines {
		if !strings.HasPrefix(line, "— ") {
			continue
		}
		trimmed := strings.TrimPrefix(line, "— ")
		tuple := strings.SplitN(trimmed, " ", 2)
		if len(tuple) == 2 {
			var sn SignedNote
			if tuple[0] == origin {
				sn.KeyName = origin
				raw, err := base64.StdEncoding.DecodeString(tuple[1])
				if err != nil {
					return nil, err
				}
				r := bytes.NewReader(raw)
				var keyID uint32
				if err := binary.Read(r, binary.BigEndian, &keyID); err != nil {
					return nil, err
				}
				rawSig, err := io.ReadAll(r)
				if err != nil {
					return nil, err
				}
				sig := base64.StdEncoding.EncodeToString(rawSig)
				sn.SignedNoteSignature = SignedNoteSignature{
					KeyID:     fmt.Sprintf("%x", keyID),
					Signature: sig,
				}
			} else {
				sn.KeyName = tuple[0]
				sn.SignedNoteSignature = SignedNoteSignature{
					Unknown: tuple[1],
				}
			}

			signedNotes = append(signedNotes, sn)
		}
	}

	return signedNotes, nil
}

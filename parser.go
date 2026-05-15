package main

import (
	"bytes"
	"crypto/sha256"
	"crypto/x509"
	"encoding/asn1"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"
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

// x.509 cert sct extensions

func trimSCTExtension(rawTBS []byte) ([]byte, error) {
	var tbs TBSCertificate
	if _, err := asn1.Unmarshal(rawTBS, &tbs); err != nil {
		return nil, err
	}

	filtered := tbs.Extensions[:0]
	for _, ext := range tbs.Extensions {
		if !ext.Id.Equal(oidExtensionSCTList) {
			filtered = append(filtered, ext)
		}
	}
	tbs.Extensions = filtered

	return asn1.Marshal(tbs)
}

func parseCertSCT(cert *x509.Certificate) ([]SCT, error) {
	var sctListBytes []byte
	var scts []SCT
	for _, ext := range cert.Extensions {
		// https://www.rfc-editor.org/rfc/rfc6962#section-3.3
		//
		//  opaque SerializedSCT<1..2^16-1>;
		//  struct {
		//      SerializedSCT sct_list <1..2^16-1>;
		//  } SignedCertificateTimestampList;
		//
		// https://www.rfc-editor.org/rfc/rfc6962#section-3.2
		//
		//	struct {
		//	    Version sct_version; // 1 byte
		//	    LogID id; // 32 bytes
		//	    uint64 timestamp; // 8 bytes
		//	    CtExtensions extensions;
		//	    digitally-signed struct {
		//	        Version sct_version;
		//	        SignatureType signature_type = certificate_timestamp;
		//	        uint64 timestamp;
		//	        LogEntryType entry_type;
		//	        select(entry_type) {
		//	            case x509_entry: ASN.1Cert;
		//	            case precert_entry: PreCert;
		//	        } signed_entry;
		//	       CtExtensions extensions;
		//	    };
		//	} SignedCertificateTimestamp;
		if ext.Id.Equal(oidExtensionSCTList) {
			_, err := asn1.Unmarshal(ext.Value, &sctListBytes)
			if err != nil {
				return nil, fmt.Errorf("failed to parse SCT extension value: %w", err)
			}

			r := bytes.NewReader(sctListBytes)

			var totalSCTLen uint16
			if err := binary.Read(r, binary.BigEndian, &totalSCTLen); err != nil {
				return nil, fmt.Errorf("failed to read SCT list length: %v", err)
			}
			sctListData := make([]byte, totalSCTLen)
			_, err = io.ReadFull(r, sctListData)
			if err != nil {
				return nil, fmt.Errorf("failed to read sct extension list: %v", err)
			}

			sctReader := bytes.NewReader(sctListData)

			for sctReader.Len() > 0 {
				var sct SCT

				var sctLen uint16
				if err := binary.Read(sctReader, binary.BigEndian, &sctLen); err != nil {
					return nil, fmt.Errorf("failed to read SCT extension length: %w", err)
				}

				sctData := make([]byte, sctLen)
				_, err := io.ReadFull(sctReader, sctData[:])
				if err != nil {
					return nil, fmt.Errorf("failed to read SCT extension data: %w", err)
				}
				sr := bytes.NewReader(sctData)

				var sctVersion uint8
				if err := binary.Read(sr, binary.BigEndian, &sctVersion); err != nil {
					return nil, fmt.Errorf("failed to read SCT version: %w", err)
				}
				sct.Version = sctVersion

				var logID [32]byte
				if err := binary.Read(sr, binary.BigEndian, logID[:]); err != nil {
					return nil, fmt.Errorf("failed to read log id: %w", err)
				}
				// align the same format with "log_id" field in log_list.json
				sct.LogID = base64.StdEncoding.EncodeToString(logID[:])
				log, err := logByLogID(sct.LogID)
				if err != nil {
					slog.Warn("log not found for log id", "log_id", sct.LogID, "err", err)
				} else {
					sct.LogIDDescription = log.Description
				}

				var ts uint64
				if err := binary.Read(sr, binary.BigEndian, &ts); err != nil {
					return nil, fmt.Errorf("failed to read timestamp: %w", err)
				}
				sct.Timestamp = CTTimestamp(ts)

				ctExt, err := parseCtExtension(sr)
				if err != nil {
					return nil, fmt.Errorf("failed to parse ct extension: %w", err)
				}
				if ctExt.Length != 0 {
					sct.CtExtensions = append(sct.CtExtensions, ctExt)
				}

				scts = append(scts, sct)
			}
		}
	}

	return scts, nil
}

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

func buildMerkleTreeLeaves(cert, issCert *x509.Certificate) ([]MerkleTreeLeaf, []*CachedLog, error) {
	// build Precert
	// - isk (32 bytes)
	// - tbs
	tbs, err := trimSCTExtension(cert.RawTBSCertificate)
	if err != nil {
		return []MerkleTreeLeaf{}, nil, fmt.Errorf("failed to trim SCT extension from TBSCertificate: %w", err)
	}
	isk := sha256.Sum256(issCert.RawSubjectPublicKeyInfo)
	precert := Precert{RawTBSCertificate: tbs, IssuerKeyHash: isk}

	// build TimestampedEntry
	// - timestamp (8 bytes)
	// - entry_type (2 bytes) -> always 0(timestamped_entry)
	// - Precert -> for now, ignore "x509_entry" pattern
	// - CtExtensions -> this is for RFC 6962, so always 0x0000
	scts, err := parseCertSCT(cert)
	if err != nil {
		return []MerkleTreeLeaf{}, nil, err
	}

	var logIDs []string
	var tsEntries []TimestampedEntry
	for _, sct := range scts {
		if sct.CtExtensions == nil {
			logIDs = append(logIDs, sct.LogID)
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
	logs := make([]*CachedLog, len(logIDs))
	for i, ts := range tsEntries {
		leaves[i] = MerkleTreeLeaf{
			Version:          0,
			MerkleLeafType:   0,
			TimestampedEntry: ts,
		}

		l, err := logByLogID(logIDs[i])
		if err != nil {
			return []MerkleTreeLeaf{}, nil, err
		}
		logs[i] = l
	}

	return leaves, logs, nil
}

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

func parseTimestampedEntryRFC6962(r *bytes.Reader) (TimestampedEntry, error) {
	var tsEntry TimestampedEntry

	var timestamp uint64
	if err := binary.Read(r, binary.BigEndian, &timestamp); err != nil {
		return TimestampedEntry{}, err
	}
	tsEntry.Timestamp = CTTimestamp(timestamp)

	var entryType uint16
	if err := binary.Read(r, binary.BigEndian, &entryType); err != nil {
		return TimestampedEntry{}, err
	}
	tsEntry.LogEntryType = entryType

	switch entryType {
	case entryTypeX509:
		asn1CertLen, err := readUint24(r)
		if err != nil {
			return TimestampedEntry{}, err
		}
		asn1CertData := make([]byte, asn1CertLen)
		_, err = io.ReadFull(r, asn1CertData)
		if err != nil {
			return TimestampedEntry{}, err
		}
		cert, err := x509.ParseCertificate(asn1CertData)
		if err != nil {
			return TimestampedEntry{}, fmt.Errorf("parsing ASN.1Cert: %w", err)
		}
		tsEntry.ASN1Cert = ASN1Cert(*cert)
	case entryTypePrecert:
		var precert Precert
		var isk [32]byte
		if err := binary.Read(r, binary.BigEndian, &isk); err != nil {
			return TimestampedEntry{}, err
		}
		precert.IssuerKeyHash = isk

		_, err := readUint24(r) // skip 3 bytes of TBSCertificate length header
		if err != nil {
			return TimestampedEntry{}, err
		}

		tbsData, err := io.ReadAll(r)
		if err != nil {
			return TimestampedEntry{}, err
		}
		precert.RawTBSCertificate = tbsData

		tsEntry.Precert = precert
	}

	return tsEntry, nil
}

func parseMerkleTreeLeaf(r *bytes.Reader) (MerkleTreeLeaf, error) {
	var mkl MerkleTreeLeaf
	var version, leafType uint8
	err := binary.Read(r, binary.BigEndian, &version)
	if err != nil {
		return MerkleTreeLeaf{}, err
	}
	err = binary.Read(r, binary.BigEndian, &leafType)
	if err != nil {
		return MerkleTreeLeaf{}, err
	}
	mkl.Version = version
	mkl.MerkleLeafType = leafType

	tsData, err := io.ReadAll(r)
	if err != nil {
		return MerkleTreeLeaf{}, err
	}

	tsReader := bytes.NewReader(tsData)
	tsEntry, err := parseTimestampedEntryRFC6962(tsReader)
	if err != nil {
		return MerkleTreeLeaf{}, fmt.Errorf("parsing RFC 6962 TimestampedEntry: %w", err)
	}

	mkl.TimestampedEntry = tsEntry

	return mkl, nil
}

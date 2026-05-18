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
)

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
					slog.Warn("log not found for log id", "logId", sct.LogID, "err", err)
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
				Precert:      &precert,
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

		tsEntry.Precert = &precert
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

// parse certificate chain in LogEntry struct defined in RFC 6962.
// in case of entryTypeX509, X509ChainEntry.certificate_chain is passed by the reader.
// in case of entryTypePrecert, whole PrecertChainEntry is passed.
//
//	struct {
//	    LogEntryType entry_type;
//	    select (entry_type) {
//	        case x509_entry: X509ChainEntry;
//	        case precert_entry: PrecertChainEntry;
//	    } entry;
//	} LogEntry;
//	opaque ASN.1Cert<1..2^24-1>;
//	struct {
//	    ASN.1Cert leaf_certificate;  // this is NOT included in extra_data
//	    ASN.1Cert certificate_chain<0..2^24-1>;
//	} X509ChainEntry;
//	struct {
//	    ASN.1Cert pre_certificate;
//	    ASN.1Cert precertificate_chain<0..2^24-1>;
//	} PrecertChainEntry;
func parseCertChain(r *bytes.Reader, entryType uint16) ([]ASN1Cert, error) {
	var certs []ASN1Cert

	// read PrecertChainEntry.pre_certificate
	if entryType == entryTypePrecert {
		precertLen, err := readUint24(r)
		if err != nil {
			return nil, fmt.Errorf("reading precert length: %w", err)
		}
		preCertData := make([]byte, precertLen)
		if _, err := io.ReadFull(r, preCertData); err != nil {
			return nil, fmt.Errorf("reading precert data: %w", err)
		}
		precert, err := x509.ParseCertificate(preCertData)
		if err != nil {
			return nil, fmt.Errorf("parsing precert data as x509 certificate: %w", err)
		}
		certs = append(certs, ASN1Cert(*precert))
	}

	certChainLen, err := readUint24(r)
	if err != nil {
		return nil, fmt.Errorf("reading certificate chain length: %w", err)
	}
	slog.Debug("parseCertChain", "certChainLen", certChainLen)

	certChainData := make([]byte, certChainLen)
	if _, err := io.ReadFull(r, certChainData); err != nil {
		return nil, fmt.Errorf("reading certificate chain data: %w", err)
	}

	chainReader := bytes.NewReader(certChainData)

	for chainReader.Len() > 0 {
		certLen, err := readUint24(chainReader)
		if err != nil {
			return nil, fmt.Errorf("reading certificate chain entry length: %w", err)
		}
		slog.Debug("parseCertChain", "certLen", certLen)
		certData := make([]byte, certLen)
		if _, err := io.ReadFull(chainReader, certData); err != nil {
			return nil, fmt.Errorf("reading certificate chain entry data: %w", err)
		}
		cert, err := x509.ParseCertificate(certData)
		if err != nil {
			return nil, fmt.Errorf("parsing certificate chain entry data as x509 certificate: %w", err)
		}
		certs = append(certs, ASN1Cert(*cert))
	}

	return certs, nil
}

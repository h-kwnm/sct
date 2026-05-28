package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"
	"time"
)

func addChainToLog(fullChain AddChainBody, log *CachedLog) (AddChainResult, error) {
	var u string
	switch log.APIType {
	case APITypeRFC6962:
		u = strings.TrimSuffix(log.URL, "/")
	case APITypeStaticCT:
		u = strings.TrimSuffix(log.SubmissionURL, "/")
	}

	endpoint := fmt.Sprintf("%s/ct/v1/add-chain", u)
	slog.Debug("addChainToLog", "endpoint", endpoint)

	postBody, err := json.Marshal(fullChain)
	if err != nil {
		return AddChainResult{}, fmt.Errorf("failed to marshal certificate chain: %w", err)
	}
	slog.Debug("addChainToLog", "postBody", string(postBody))

	r := bytes.NewReader(postBody)
	ts := time.Now().UTC()
	respBody, err := httpPost(context.Background(), endpoint, 1<<20, r)
	if err != nil {
		return AddChainResult{}, fmt.Errorf("add-chain request to %s failed: %w", endpoint, err)
	}
	slog.Debug("addChainToLog", "respBody", string(respBody))

	var response AddChainResponse
	if err := json.Unmarshal(respBody, &response); err != nil {
		return AddChainResult{}, err
	}

	var ext *CtExtension
	if len(response.Extensions) > 0 {
		ext, err = parseLeafIndex(response.Extensions)
		if err != nil {
			return AddChainResult{}, fmt.Errorf("failed to parse leaf index: %w", err)
		}
	}

	return AddChainResult{
		AddedAt: ts,
		Log:     log,
		SignedCertificateTimestamp: SignedCertificateTimestamp{
			SCTVersion: response.SCTVersion,
			ID:         response.ID,
			Timestamp:  CTTimestamp(response.Timestamp),
			Extensions: ext,
			Signature:  response.Signature,
		},
	}, nil
}

// parse leaf index type in the following format of []byte
// [0x00]     : ExtensionType
// [0x00 0x05]: extension_data length
// [5 bytes]  : leaf_index (uint40)
func parseLeafIndex(rawLeafIndexExt []byte) (*CtExtension, error) {
	if len(rawLeafIndexExt) < 8 {
		return nil, fmt.Errorf("leaf index extension must be 8 bytes, but %d bytes", len(rawLeafIndexExt))
	}

	r := bytes.NewReader(rawLeafIndexExt)

	var extType uint8
	if err := binary.Read(r, binary.BigEndian, &extType); err != nil {
		return nil, err
	}
	if extType != extensionTypeLeafIndex {
		return nil, fmt.Errorf("unexpected extension type %d, want %d", extType, extensionTypeLeafIndex)
	}

	var extLen uint16
	if err := binary.Read(r, binary.BigEndian, &extLen); err != nil {
		return nil, err
	}
	if extLen != 5 {
		return nil, fmt.Errorf("unexpected extension length %d, want %d", extLen, 5)
	}

	leafIndex, err := readUint40(r)
	if err != nil {
		return nil, err
	}

	return &CtExtension{
		Type:   extType,
		Length: extLen,
		Value:  leafIndex,
	}, nil
}

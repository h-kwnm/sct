package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func fetchSTH(log *CachedLog) (SignedTreeHead, error) {
	u := strings.TrimSuffix(log.URL, "/")
	endpoint := fmt.Sprintf("%s/ct/v1/get-sth", u)

	body, err := httpGet(context.Background(), endpoint, 1<<12)
	if err != nil {
		return SignedTreeHead{}, fmt.Errorf("fetching from %s: %w", endpoint, err)
	}

	var data SignedTreeHead
	err = json.Unmarshal(body, &data)
	if err != nil {
		return SignedTreeHead{}, fmt.Errorf("unmarshalling STH of log %s: %w", endpoint, err)
	}

	return data, nil
}

func fetchProofByHash(h string, log *CachedLog) (RFC6962ProofResult, error) {
	sth, err := fetchSTH(log)
	if err != nil {
		return RFC6962ProofResult{}, err
	}

	u := strings.TrimSuffix(log.URL, "/")
	params := url.Values{}
	params.Set("hash", h)
	params.Set("tree_size", strconv.FormatUint(sth.TreeSize, 10))

	endpoint := fmt.Sprintf("%s/ct/v1/get-proof-by-hash?%s", u, params.Encode())

	ts := time.Now().UTC()
	body, err := httpGet(context.Background(), endpoint, 1<<20)
	if err != nil {
		return RFC6962ProofResult{}, fmt.Errorf("fetching from %s: %w", endpoint, err)
	}
	slog.Debug("fetchProofByHash", "endpoint", endpoint)

	var p RFC6962Proof
	if err := json.Unmarshal(body, &p); err != nil {
		return RFC6962ProofResult{}, err
	}

	return RFC6962ProofResult{
		FetchedAt: ts,
		Log:       log,
		RootHash:  sth.RootHash,
		LeafHash:  h,
		TreeSize:  sth.TreeSize,
		Proof:     p,
	}, nil
}

func fetchEntries(index, offset uint64, log *CachedLog) (GetEntriesResult, error) {
	sth, err := fetchSTH(log)
	if err != nil {
		return GetEntriesResult{}, err
	}
	if index+offset >= sth.TreeSize {
		return GetEntriesResult{}, fmt.Errorf("invalid index/offset(index+offset=%d must be less than tree size=%d)", index+offset, sth.TreeSize)
	}

	u := strings.TrimSuffix(log.URL, "/")
	params := url.Values{}
	params.Set("start", strconv.FormatUint(index, 10))
	params.Set("end", strconv.FormatUint(index+offset, 10))
	endpoint := fmt.Sprintf("%s/ct/v1/get-entries?%s", u, params.Encode())

	body, err := httpGet(context.Background(), endpoint, 1<<24)
	if err != nil {
		return GetEntriesResult{}, fmt.Errorf("fetching from %s: %w", endpoint, err)
	}
	slog.Debug("fetchEntries", "endpoint", endpoint)

	var entries GetEntriesResponse
	if err := json.Unmarshal(body, &entries); err != nil {
		return GetEntriesResult{}, err
	}

	var result GetEntriesResult
	result.Log = log
	for i, entry := range entries.Entries {
		r := bytes.NewReader(entry.LeafInput)
		mkl, err := parseMerkleTreeLeaf(r)
		if err != nil {
			return GetEntriesResult{}, err
		}

		cr := bytes.NewReader(entry.ExtraData)
		certs, err := parseCertChain(cr, mkl.TimestampedEntry.LogEntryType)
		if err != nil {
			return GetEntriesResult{}, err
		}
		result.Entries = append(result.Entries, struct {
			LeafIndex uint64         `json:"leaf_index"`
			LeafInput MerkleTreeLeaf `json:"leaf_input"`
			ExtraData []ASN1Cert     `json:"extra_data"`
		}{
			LeafIndex: index + uint64(i),
			LeafInput: mkl,
			ExtraData: certs,
		})
	}
	return result, nil

}

func fetchEntryAndProof(index, size uint64, log *CachedLog) (GetEntryAndProofResult, error) {
	if index >= size {
		return GetEntryAndProofResult{}, fmt.Errorf("unexpected leaf index or tree size. leaf index(%d) must be less than tree size(%d)", index, size)
	}

	sth, err := fetchSTH(log)
	if err != nil {
		return GetEntryAndProofResult{}, fmt.Errorf("fetching STH from log %d: %w", log.ID, err)
	}
	if size > sth.TreeSize {
		return GetEntryAndProofResult{}, fmt.Errorf("invalid tree size: %d is greater than the latest size %d", size, sth.TreeSize)
	}

	u := strings.TrimSuffix(log.URL, "/")
	params := url.Values{}
	params.Set("leaf_index", strconv.FormatUint(index, 10))
	params.Set("tree_size", strconv.FormatUint(size, 10))
	endpoint := fmt.Sprintf("%s/ct/v1/get-entry-and-proof?%s", u, params.Encode())

	body, err := httpGet(context.Background(), endpoint, 1<<20)
	if err != nil {
		return GetEntryAndProofResult{}, fmt.Errorf("fetching from %s: %w", endpoint, err)
	}
	slog.Debug("fetchEntryAndProof", "endpoint", endpoint)

	var response GetEntryAndProofResponse
	if err := json.Unmarshal(body, &response); err != nil {
		return GetEntryAndProofResult{}, err
	}

	r := bytes.NewReader(response.LeafInput)
	mkl, err := parseMerkleTreeLeaf(r)
	if err != nil {
		return GetEntryAndProofResult{}, err
	}
	cr := bytes.NewReader(response.ExtraData)
	certs, err := parseCertChain(cr, mkl.TimestampedEntry.LogEntryType)
	if err != nil {
		return GetEntryAndProofResult{}, err
	}

	leafBytes := mkl.Marshal()
	h := sha256.Sum256(append([]byte{0x00}, leafBytes...))
	b64Hash := base64.StdEncoding.EncodeToString(h[:])

	return GetEntryAndProofResult{
		FetchedAt: time.Now().UTC(),
		Log:       log,
		LeafHash:  b64Hash,
		LeafInput: mkl,
		ExtraData: certs,
		AuditPath: response.AuditPath,
	}, nil
}

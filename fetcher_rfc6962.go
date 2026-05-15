package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

func fetchSTH(log *CachedLog) (SignedTreeHead, error) {
	u := strings.TrimSuffix(log.URL, "/")
	endpoint := fmt.Sprintf("%s/ct/v1/get-sth", u)

	req, err := http.NewRequestWithContext(context.Background(), "GET", endpoint, nil)
	if err != nil {
		return SignedTreeHead{}, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return SignedTreeHead{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return SignedTreeHead{}, fmt.Errorf("unexpected response status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<12))
	if err != nil {
		return SignedTreeHead{}, err
	}

	var data SignedTreeHead
	err = json.Unmarshal(body, &data)
	if err != nil {
		return SignedTreeHead{}, err
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

	req, err := http.NewRequestWithContext(context.Background(), "GET", endpoint, nil)
	if err != nil {
		return RFC6962ProofResult{}, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return RFC6962ProofResult{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return RFC6962ProofResult{}, fmt.Errorf("unexpected response status code: %d", resp.StatusCode)
	}

	ts := time.Now().UTC()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return RFC6962ProofResult{}, err
	}

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

	req, err := http.NewRequestWithContext(context.Background(), "GET", endpoint, nil)
	if err != nil {
		return GetEntriesResult{}, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return GetEntriesResult{}, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return GetEntriesResult{}, fmt.Errorf("unexpected response status code: %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<24))
	if err != nil {
		return GetEntriesResult{}, err
	}

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
		result.Entries = append(result.Entries, struct {
			LeafIndex uint64         "json:\"leaf_index\""
			LeafInput MerkleTreeLeaf "json:\"leaf_input\""
		}{
			LeafIndex: index + uint64(i),
			LeafInput: mkl,
		})
	}
	return result, nil

}

package main

import (
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

func fetchSth(log *CachedLog) (SignedTreeHead, error) {
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
	sth, err := fetchSth(log)
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

	body, err := io.ReadAll(resp.Body)
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

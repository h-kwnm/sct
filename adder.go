package main

import (
	"bytes"
	"context"
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

	return AddChainResult{
		AddedAt:    ts,
		Log:        log,
		SCTVersion: response.SCTVersion,
		ID:         response.ID,
		Timestamp:  CTTimestamp(response.Timestamp),
		Extensions: response.Extensions,
		Signature:  response.Signature,
	}, nil
}

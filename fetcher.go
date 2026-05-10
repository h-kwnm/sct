package main

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"time"
)

var httpClient = &http.Client{Timeout: 30 * time.Second}

var logListURL = "https://www.gstatic.com/ct/log_list/v3/log_list.json"

// Some log operators could apply request rate limits. for example, Geomys's log has such a limit.
// Customize User-Agent to include an email address to mitigate such limits when needed.
// https://groups.google.com/a/chromium.org/g/ct-policy/c/KCzYEIIZSxg/m/zD26fYw4AgAJ
// Following is example of such User-Agent value.
//
//	sct/0.1 (your@email.com)
//	sct/0.1 (+https://github.com/h-kwnm/sct)
//	sct/0.1 (github.com/h-kwnm/sct)
const userAgent = "sct/" + version + " (github.com/h-kwnm/sct)"

func fetchLogList() (*LogList, error) {
	resp, err := httpClient.Get(logListURL)
	if err != nil {
		return nil, fmt.Errorf("HTTP request failure: %w", err)
	}

	defer resp.Body.Close()

	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))

	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %w", err)
	}

	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("unexpected status code: %d, url: %s, body: %s", resp.StatusCode, logListURL, string(body))
	}

	var logList LogList
	if err := json.Unmarshal(body, &logList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal log list JSON: %w", err)
	}

	return &logList, nil
}

func fetchServerCertificate(endpoint string) ([]*x509.Certificate, error) {
	u, err := url.Parse(endpoint)
	if err != nil {
		return nil, fmt.Errorf("invalid endpoint URL %s: %w", endpoint, err)
	}
	var address string
	if u.Port() == "" {
		address = fmt.Sprintf("%s:443", u.Hostname())
	} else {
		address = fmt.Sprintf("%s:%s", u.Hostname(), u.Port())
	}

	conn, err := tls.Dial("tcp", address, &tls.Config{
		InsecureSkipVerify: true, // no verification since the result do not matter here
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", endpoint, err)
	}

	certs := conn.ConnectionState().PeerCertificates

	return certs, nil
}

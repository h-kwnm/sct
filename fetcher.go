package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
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

func httpGet(ctx context.Context, url string, limit int64) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgent)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status %d from %s: %s", resp.StatusCode, url, body)
	}
	return body, nil
}

func fetchLogList() (*LogList, error) {

	body, err := httpGet(context.Background(), logListURL, 1<<20)
	if err != nil {
		return nil, fmt.Errorf("fetching %s: %w", logListURL, err)
	}

	var logList LogList
	if err := json.Unmarshal(body, &logList); err != nil {
		return nil, fmt.Errorf("failed to unmarshal log list JSON: %w", err)
	}

	return &logList, nil
}

func fetchAcceptedRootCertificate(log *CachedLog) (*AcceptedRootCertificates, error) {
	var u string
	switch log.APIType {
	case APITypeRFC6962:
		u = log.URL
	case APITypeStaticCT:
		u = log.SubmissionURL
	default:
		return nil, fmt.Errorf("unexpected API type %s", log.APIType)
	}
	u = strings.TrimSuffix(u, "/")
	endpoint := fmt.Sprintf("%s/ct/v1/get-roots", u)

	body, err := httpGet(context.Background(), endpoint, 1<<24)
	if err != nil {
		return nil, fmt.Errorf("fetching from %s: %w", endpoint, err)
	}

	var res GetRootsResponse
	if err := json.Unmarshal(body, &res); err != nil {
		return nil, fmt.Errorf("failed to unmarshal response body to JSON: %w", err)
	}

	var roots []Certificate
	for i, root := range res.Certificates {
		d, err := base64.StdEncoding.DecodeString(root)
		if err != nil {
			return &AcceptedRootCertificates{}, fmt.Errorf("failed to decode base64-encoded root certificate at %d: %w", i, err)
		}
		cert, err := x509.ParseCertificate(d)
		if err != nil {
			// it is known that parsing some legacy root certificates prodeces an error because of RFC 5280 violation
			// example errors:
			// - "x509: negative serial number"
			// - "x509: invalid RDNSequence: invalid attribute value: unsupported string type: 3"
			slog.Warn("failed to parse root certificate, skipped", "location", i, "err", err, "cert", root)
			roots = append(roots, Certificate{
				Raw:        root,
				ParseError: err.Error(),
			})
			continue
		}
		roots = append(roots, Certificate{
			Raw:            root,
			Version:        cert.Version,
			SerialNumber:   fmt.Sprintf("%x", cert.SerialNumber),
			SignatureAlg:   cert.SignatureAlgorithm.String(),
			Issuer:         cert.Issuer.String(),
			NotBefore:      cert.NotBefore,
			NotAfter:       cert.NotAfter,
			Subject:        cert.Subject.String(),
			PublicKeyAlg:   cert.PublicKeyAlgorithm.String(),
			SubjectKeyId:   fmt.Sprintf("%x", cert.SubjectKeyId),
			AuthorityKeyId: fmt.Sprintf("%x", cert.AuthorityKeyId),
			Policies:       cert.Policies,
			KeyUsage:       parseKeyUsage(cert.KeyUsage),
			ExtKeyUsage:    parseExtKeyUsage(cert.ExtKeyUsage),
		})
	}

	ar := AcceptedRootCertificates{Certificates: roots}

	return &ar, nil
}

func fetchServerCertificate(endpoint string, insecure bool) ([]*x509.Certificate, error) {
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
		InsecureSkipVerify: insecure,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to connect to %s: %w", endpoint, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates

	return certs, nil
}

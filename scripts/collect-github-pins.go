// Command collect-github-pins obtains build-time TLS SPKI pins from all
// required GitHub endpoints. It relies on the system root CA store and respects
// HTTPS_PROXY. Failure to verify any endpoint fails the entire build.
package main

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

var requiredHosts = []string{
	"api.github.com",
	"github.com",
	"release-assets.githubusercontent.com",
	"objects.githubusercontent.com",
}

func pinsForChains(chains [][]*x509.Certificate) ([]string, error) {
	if len(chains) == 0 {
		return nil, errors.New("TLS certificate chain was not CA-verified")
	}
	var pins []string
	seen := make(map[string]bool)
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		// Pin the leaf and verified intermediates, but never the root CA.
		limit := len(chain) - 1
		if limit < 1 {
			limit = 1
		}
		for _, cert := range chain[:limit] {
			hash := sha256.Sum256(cert.RawSubjectPublicKeyInfo)
			pin := base64.StdEncoding.EncodeToString(hash[:])
			if !seen[pin] {
				pins = append(pins, pin)
				seen[pin] = true
			}
		}
	}
	if len(pins) == 0 {
		return nil, errors.New("no TLS public keys in verified chains")
	}
	return pins, nil
}

func collectHost(ctx context.Context, host string) ([]string, error) {
	var verified [][]*x509.Certificate
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{
		MinVersion: tls.VersionTLS12,
		VerifyConnection: func(cs tls.ConnectionState) error {
			if cs.ServerName != host {
				return fmt.Errorf("unexpected TLS hostname %q", cs.ServerName)
			}
			if len(cs.VerifiedChains) == 0 {
				return errors.New("server certificate was not CA-verified")
			}
			verified = cs.VerifiedChains
			return nil
		},
	}
	defer transport.CloseIdleConnections()
	client := &http.Client{
		Transport: transport,
		CheckRedirect: func(*http.Request, []*http.Request) error {
			// Pin the requested host, not a redirect destination.
			return http.ErrUseLastResponse
		},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodHead, "https://"+host+"/", nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	resp.Body.Close()
	if len(verified) == 0 {
		return nil, errors.New("TLS handshake did not return a verified chain")
	}
	// A HEAD request may get a 403/404 from a CDN: it still proves the
	// authenticated TLS handshake, which is all the collector needs.
	return pinsForChains(verified)
}

func main() {
	entries := make([]string, 0, len(requiredHosts))
	for _, host := range requiredHosts {
		var pins []string
		var err error
		for attempt := 1; attempt <= 3; attempt++ {
			ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			pins, err = collectHost(ctx, host)
			cancel()
			if err == nil {
				break
			}
			fmt.Fprintf(os.Stderr, "[TLS] %s attempt %d/3 failed: %v\n", host, attempt, err)
			if attempt < 3 {
				time.Sleep(time.Duration(attempt) * time.Second)
			}
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "[TLS] FATAL: no verified pins for required host %s\n", host)
			os.Exit(1)
		}
		fmt.Fprintf(os.Stderr, "[TLS] %s verified (%d SPKI pins)\n", host, len(pins))
		entries = append(entries, host+"="+strings.Join(pins, ","))
	}
	// Emit nothing on stdout until every required hostname is verified.
	fmt.Println(strings.Join(entries, ";"))
}

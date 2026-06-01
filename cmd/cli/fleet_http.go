package main

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"
)

func fleetHTTPClient(https bool, caCert string, timeout time.Duration) (*http.Client, error) {
	client := &http.Client{Timeout: timeout}
	if !https {
		return client, nil
	}
	if caCert == "" {
		return client, nil
	}
	pem, err := os.ReadFile(caCert)
	if err != nil {
		return nil, fmt.Errorf("read ca cert: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("parse ca cert")
	}
	client.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{
			RootCAs:    pool,
			MinVersion: tls.VersionTLS12,
		},
	}
	return client, nil
}

func fleetHTTPGet(url, token string, client *http.Client) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("control plane returned %s: %s", resp.Status, string(body))
	}
	return body, nil
}

func resolveFleetHost(host string) (string, error) {
	if host != "" {
		return host, nil
	}
	peek, err := readFleetConfigPeek(configFile)
	if err != nil {
		return "", fmt.Errorf("--host required: %w", err)
	}
	host = peek.Server.Endpoint
	if host == "" || host == "YOUR_CONTROL_PLANE_HOST" {
		return "", fmt.Errorf("control plane host is not configured; pass --host")
	}
	return host, nil
}

func resolveFleetCACert(explicit string) string {
	if explicit != "" {
		return explicit
	}
	peek, err := readFleetConfigPeek(configFile)
	if err != nil {
		return ""
	}
	return peek.Server.CACertPath
}

package splunkclient

import (
	"bytes"
	context "context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/norskhelsenett/dnsstats/pkg/models/splunkmodels"
)

type SplunkClient struct {
	Token             string `json:"token,omitempty"`               // Token for authentication
	EndPointUrl       string `json:"endpoint_url,omitempty"`        // Endpoint URL
	DisableKeepAlives bool   `json:"disable_keep_alives,omitempty"` // Disable HTTP keep-alives (optional)
	DisableTLS        bool   `json:"disable_tls,omitempty"`         // Disable TLS verification (optional)
	Timeout           int    `json:"timeout,omitempty"`             // Request timeout in seconds (optional)

	HECIndex      string `json:"hec_index,omitempty"`      // HEC index (optional)
	HECSource     string `json:"hec_source,omitempty"`     // HEC source (optional)
	HECSourcetype string `json:"hec_sourcetype,omitempty"` // HEC sourcetype (optional)
	HECTimestamp  int64  `json:"hec_timestamp,omitempty"`  // HEC timestamp (optional)

	HttpClient *http.Client
}

func NewSplunkClient(opts ...Option) *SplunkClient {

	client := &SplunkClient{
		Timeout:    10,    // Default timeout of 10 seconds,
		DisableTLS: false, // Default to TLS verification enabled
	}

	for _, opt := range opts {
		opt(client)
	}

	return client
}

func (c *SplunkClient) Send(ctx context.Context, request splunkmodels.Request) error {

	// Build HTTP client if not already built
	c.buildHTTPClient()

	// Marshal the request exactly as provided (no double-encoding of command field)
	body, err := json.Marshal(request)
	if err != nil {
		return fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", c.EndPointUrl, bytes.NewBuffer(body))
	if err != nil {
		return fmt.Errorf("failed to create HTTP request: %w", err)
	}

	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Authorization", "Splunk "+c.Token)

	resp, err := c.HttpClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("received non-OK HTTP status: %s", resp.Status)
	}

	return nil

}

func (c *SplunkClient) buildHTTPClient() {

	if c.HttpClient == nil {
		c.HttpClient = &http.Client{}
	}

	c.HttpClient.Timeout = time.Duration(c.Timeout) * time.Second

	tlsCfg := &tls.Config{
		InsecureSkipVerify: c.DisableTLS,
	}

	c.HttpClient.Transport = &http.Transport{
		TLSClientConfig:   tlsCfg,
		DisableKeepAlives: c.DisableKeepAlives,
	}

}

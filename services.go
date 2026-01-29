package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	tailscaleAPIBase    = "https://api.tailscale.com"
	tailscaleTokenURL   = "https://api.tailscale.com/api/v2/oauth/token"
	tokenExpiryBuffer   = 5 * time.Minute
	httpClientTimeout   = 30 * time.Second
)

// ServicesClient is a client for the Tailscale services API.
type ServicesClient struct {
	clientID     string
	clientSecret string
	tailnet      string
	httpClient   *http.Client

	mu          sync.Mutex
	accessToken string
	tokenExpiry time.Time
}

// NewServicesClient creates a new ServicesClient.
func NewServicesClient(clientID, clientSecret, tailnet string) *ServicesClient {
	return &ServicesClient{
		clientID:     clientID,
		clientSecret: clientSecret,
		tailnet:      tailnet,
		httpClient:   &http.Client{Timeout: httpClientTimeout},
	}
}

// ServiceHostInfo represents a host of a service.
type ServiceHostInfo struct {
	StableNodeID  string `json:"stableNodeID"`
	ApprovalLevel string `json:"approvalLevel"`
	Configured    string `json:"configured"`
}

// serviceHostsResponse is the response from the service hosts endpoint.
type serviceHostsResponse struct {
	Hosts []ServiceHostInfo `json:"hosts"`
}

// GetServiceHosts returns the hosts for the given service.
func (c *ServicesClient) GetServiceHosts(ctx context.Context, serviceName string) ([]ServiceHostInfo, error) {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting access token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v2/tailnet/%s/services/%s/devices",
		tailscaleAPIBase, url.PathEscape(c.tailnet), url.PathEscape(serviceName))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		// Service doesn't exist, return empty list.
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result serviceHostsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return result.Hosts, nil
}

// ServiceApproval represents the approval status of a service on a device.
type ServiceApproval struct {
	Approved     bool `json:"approved"`
	AutoApproved bool `json:"autoApproved"`
}

// GetServiceDeviceApproval returns the approval status of a service on a specific device.
func (c *ServicesClient) GetServiceDeviceApproval(ctx context.Context, serviceName, deviceID string) (*ServiceApproval, error) {
	token, err := c.getAccessToken(ctx)
	if err != nil {
		return nil, fmt.Errorf("getting access token: %w", err)
	}

	endpoint := fmt.Sprintf("%s/api/v2/tailnet/%s/services/%s/device/%s/approved",
		tailscaleAPIBase, url.PathEscape(c.tailnet), url.PathEscape(serviceName), url.PathEscape(deviceID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	req.Header.Set("Authorization", "Bearer "+token)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("executing request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return &ServiceApproval{}, nil
	}

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("unexpected status %d: %s", resp.StatusCode, string(body))
	}

	var result ServiceApproval
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("decoding response: %w", err)
	}

	return &result, nil
}

// oauthTokenResponse is the response from the OAuth token endpoint.
type oauthTokenResponse struct {
	AccessToken string `json:"access_token"`
	ExpiresIn   int    `json:"expires_in"`
}

// getAccessToken returns a valid access token, refreshing if necessary.
func (c *ServicesClient) getAccessToken(ctx context.Context) (string, error) {
	c.mu.Lock()
	defer c.mu.Unlock()

	// Return cached token if still valid.
	if c.accessToken != "" && time.Now().Add(tokenExpiryBuffer).Before(c.tokenExpiry) {
		return c.accessToken, nil
	}

	// Request new token.
	data := url.Values{}
	data.Set("grant_type", "client_credentials")

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, tailscaleTokenURL, strings.NewReader(data.Encode()))
	if err != nil {
		return "", fmt.Errorf("creating token request: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.SetBasicAuth(c.clientID, c.clientSecret)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("executing token request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("token request failed with status %d: %s", resp.StatusCode, string(body))
	}

	var tokenResp oauthTokenResponse
	if err := json.NewDecoder(resp.Body).Decode(&tokenResp); err != nil {
		return "", fmt.Errorf("decoding token response: %w", err)
	}

	c.accessToken = tokenResp.AccessToken
	c.tokenExpiry = time.Now().Add(time.Duration(tokenResp.ExpiresIn) * time.Second)

	return c.accessToken, nil
}

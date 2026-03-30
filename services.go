package main

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"

	tailscale "tailscale.com/client/tailscale/v2"
)

// ServicesClient checks service device approval via the Tailscale API.
// It wraps a tailscale.Client to reuse its auth and HTTP handling.
type ServicesClient struct {
	client *tailscale.Client
}

// NewServicesClient creates a new ServicesClient wrapping the given tailscale.Client.
func NewServicesClient(client *tailscale.Client) *ServicesClient {
	return &ServicesClient{client: client}
}

// ServiceApproval represents the approval status of a service on a device.
type ServiceApproval struct {
	Approved     bool `json:"approved"`
	AutoApproved bool `json:"autoApproved"`
}

// GetServiceDeviceApproval returns the approval status of a service on a specific device.
func (c *ServicesClient) GetServiceDeviceApproval(ctx context.Context, serviceName, deviceID string) (*ServiceApproval, error) {
	// Trigger client initialization so HTTP is authenticated.
	_ = c.client.VIPServices()

	endpoint := fmt.Sprintf("%s/api/v2/tailnet/%s/services/%s/device/%s/approved",
		c.client.BaseURL,
		url.PathEscape(c.client.Tailnet),
		url.PathEscape(serviceName),
		url.PathEscape(deviceID))

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("creating request: %w", err)
	}

	resp, err := c.client.HTTP.Do(req)
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

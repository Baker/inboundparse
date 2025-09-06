package service

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// webhookService implements the WebhookService interface
type webhookService struct {
	client   *http.Client
	url      string
	username string
	password string
}

// NewWebhookService creates a new webhook service
func NewWebhookService(url, username, password string) WebhookService {
	return &webhookService{
		client: &http.Client{
			Timeout: 30 * time.Second,
		},
		url:      url,
		username: username,
		password: password,
	}
}

// SendWebhook sends a webhook payload to the configured URL
func (w *webhookService) SendWebhook(ctx context.Context, payload *WebhookPayload) error {
	// Marshal payload to JSON
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal webhook payload: %w", err)
	}

	// Create HTTP request
	req, err := http.NewRequestWithContext(ctx, "POST", w.url, bytes.NewBuffer(jsonData))
	if err != nil {
		return fmt.Errorf("failed to create webhook request: %w", err)
	}

	// Set headers
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "inboundparse/1.0")

	// Add basic auth if credentials are provided
	if w.username != "" && w.password != "" {
		req.SetBasicAuth(w.username, w.password)
	}

	// Send request
	resp, err := w.client.Do(req)
	if err != nil {
		return fmt.Errorf("failed to send webhook request: %w", err)
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			// Log error but don't fail the request
			_ = err // Explicitly ignore the error
		}
	}()

	// Check response status
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("webhook request failed with status %d: %s", resp.StatusCode, string(body))
	}

	return nil
}

package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"

	"github.com/rs/zerolog/log"
)

// WebhookSender interface for sending webhook requests
type WebhookSender interface {
	SendWebhook(ctx context.Context, payload interface{}) error
}

// WebhookConfig holds webhook configuration
type WebhookConfig struct {
	URL      string
	Username string
	Password string
	Timeout  time.Duration
}

// webhookSender implements WebhookSender interface
type webhookSender struct {
	config WebhookConfig
	client *http.Client
}

// NewWebhookSender creates a new webhook sender
func NewWebhookSender(config WebhookConfig) WebhookSender {
	return &webhookSender{
		config: config,
		client: &http.Client{
			Timeout: config.Timeout,
		},
	}
}

// SendWebhook sends a webhook request with the given payload
func (w *webhookSender) SendWebhook(ctx context.Context, payload interface{}) error {
	start := time.Now()

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Error().
			Err(err).
			Msg("Failed to marshal webhook payload")
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, "POST", w.config.URL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Error().
			Err(err).
			Str("webhook_url", w.config.URL).
			Msg("Failed to create webhook request")
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "inboundparse/1.0")

	// Add basic authentication if configured
	if w.config.Username != "" && w.config.Password != "" {
		req.SetBasicAuth(w.config.Username, w.config.Password)
	}

	resp, err := w.client.Do(req)
	duration := time.Since(start)

	if err != nil {
		log.Error().
			Err(err).
			Str("webhook_url", w.config.URL).
			Dur("duration", duration).
			Msg("Webhook request failed")
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn().
				Err(closeErr).
				Msg("Failed to close response body")
		}
	}()

	if resp.StatusCode >= 400 {
		log.Error().
			Str("webhook_url", w.config.URL).
			Int("status_code", resp.StatusCode).
			Dur("duration", duration).
			Msg("Webhook returned error status")
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	log.Info().
		Str("webhook_url", w.config.URL).
		Int("status_code", resp.StatusCode).
		Dur("duration", duration).
		Msg("Successfully sent email to webhook")

	return nil
}

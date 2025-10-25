package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"inboundparse/internal/observability"
	"net/http"
	"time"
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
	config  WebhookConfig
	client  *http.Client
	logger  observability.Logger
	metrics observability.MetricsCollector
}

// NewWebhookSender creates a new webhook sender
func NewWebhookSender(config WebhookConfig, logger observability.Logger, metrics observability.MetricsCollector) WebhookSender {
	return &webhookSender{
		config:  config,
		client:  &http.Client{Timeout: config.Timeout},
		logger:  logger,
		metrics: metrics,
	}
}

// SendWebhook sends a webhook request with the given payload
func (w *webhookSender) SendWebhook(ctx context.Context, payload interface{}) error {
	start := time.Now()

	jsonData, err := json.Marshal(payload)
	if err != nil {
		w.logger.Error().
			Err(err).
			Msg("Failed to marshal webhook payload")
		w.metrics.TrackWebhookError("marshal_error")
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	requestSize := int64(len(jsonData))
	w.logger.Debug().
		Int64("request_size", requestSize).
		Str("url", w.config.URL).
		Msg("Sending webhook request")

	req, err := http.NewRequestWithContext(ctx, "POST", w.config.URL, bytes.NewBuffer(jsonData))
	if err != nil {
		w.logger.Error().
			Err(err).
			Str("url", w.config.URL).
			Msg("Failed to create webhook request")
		w.metrics.TrackWebhookError("request_creation_error")
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
		w.logger.Error().
			Err(err).
			Str("url", w.config.URL).
			Dur("duration", duration).
			Msg("Webhook request failed")

		// Determine error type for metrics
		errorType := "network_error"
		if ctx.Err() == context.DeadlineExceeded {
			errorType = "timeout_error"
		}
		w.metrics.TrackWebhookError(errorType)
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			w.logger.Warn().
				Err(closeErr).
				Msg("Failed to close response body")
		}
	}()

	// Track metrics
	w.metrics.TrackWebhookRequest(resp.StatusCode, duration)

	// Track request/response size
	responseSize := resp.ContentLength
	if responseSize < 0 {
		responseSize = 0 // Content-Length header not present
	}
	w.metrics.TrackWebhookRequestSize(requestSize, responseSize)

	// Log response details
	w.logger.Info().
		Int("status_code", resp.StatusCode).
		Dur("duration", duration).
		Int64("request_size", requestSize).
		Int64("response_size", responseSize).
		Msg("Webhook request completed")

	if resp.StatusCode >= 400 {
		errorType := "client_error"
		if resp.StatusCode >= 500 {
			errorType = "server_error"
		}
		w.metrics.TrackWebhookError(errorType)

		w.logger.Warn().
			Int("status_code", resp.StatusCode).
			Str("url", w.config.URL).
			Msg("Webhook request failed with non-success status")
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	return nil
}

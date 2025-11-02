package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"inboundparse/internal/observability"
	"net/http"
	"time"

	"github.com/failsafe-go/failsafe-go"
	"github.com/failsafe-go/failsafe-go/circuitbreaker"
	"github.com/failsafe-go/failsafe-go/ratelimiter"
	"github.com/failsafe-go/failsafe-go/retrypolicy"
)

// httpError represents an HTTP error response
type httpError struct {
	statusCode int
	message    string
}

func (e *httpError) Error() string {
	return e.message
}

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

	// Retry configuration
	MaxRetries      int
	RetryDelay      time.Duration
	MaxRetryDelay   time.Duration
	RetryMultiplier float64

	// Rate limiting configuration
	RateLimitPerSecond int
	RateLimitBurst     int
}

// webhookSender implements WebhookSender interface
type webhookSender struct {
	config         WebhookConfig
	client         *http.Client
	logger         observability.Logger
	metrics        observability.MetricsCollector
	retryPolicy    retrypolicy.RetryPolicy[any]
	rateLimiter    ratelimiter.RateLimiter[any]
	circuitBreaker circuitbreaker.CircuitBreaker[any]
}

// NewWebhookSender creates a new webhook sender
func NewWebhookSender(config WebhookConfig, logger observability.Logger, metrics observability.MetricsCollector) WebhookSender {
	// Set default values if not configured
	if config.MaxRetries == 0 {
		config.MaxRetries = 3
	}
	if config.RetryDelay == 0 {
		config.RetryDelay = 1 * time.Second
	}
	if config.MaxRetryDelay == 0 {
		config.MaxRetryDelay = 30 * time.Second
	}
	if config.RetryMultiplier == 0 {
		config.RetryMultiplier = 2.0
	}
	if config.RateLimitPerSecond == 0 {
		config.RateLimitPerSecond = 10
	}
	if config.RateLimitBurst == 0 {
		config.RateLimitBurst = 20
	}

	// Create retry policy
	retryPolicy := retrypolicy.NewBuilder[any]().
		WithMaxRetries(config.MaxRetries).
		WithDelay(config.RetryDelay).
		Build()

	// Create rate limiter
	rateLimit := config.RateLimitPerSecond
	if rateLimit < 0 {
		rateLimit = 0
	}
	// Ensure rate limit is within valid uint range
	if rateLimit > int(^uint(0)>>1) {
		rateLimit = int(^uint(0) >> 1)
	}
	// Safe conversion to uint with explicit bounds checking
	var rateLimitUint uint
	if rateLimit >= 0 {
		rateLimitUint = uint(rateLimit)
	}
	rateLimiter := ratelimiter.NewSmooth[any](rateLimitUint, time.Second)

	// Create circuit breaker
	circuitBreaker := circuitbreaker.NewBuilder[any]().
		WithFailureThreshold(5).
		WithSuccessThreshold(3).
		Build()

	return &webhookSender{
		config:         config,
		client:         &http.Client{Timeout: config.Timeout},
		logger:         logger,
		metrics:        metrics,
		retryPolicy:    retryPolicy,
		rateLimiter:    rateLimiter,
		circuitBreaker: circuitBreaker,
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

	// Create the HTTP request
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

	// Execute with failsafe (retry policy, rate limiter, circuit breaker)
	var resp *http.Response
	executor := failsafe.With(w.retryPolicy, w.rateLimiter, w.circuitBreaker)

	err = executor.Run(func() error {
		// Make the HTTP request
		httpResp, httpErr := w.client.Do(req)
		if httpErr != nil {
			return httpErr
		}

		// Check for HTTP error status codes
		if httpResp.StatusCode >= 400 {
			if closeErr := httpResp.Body.Close(); closeErr != nil {
				w.logger.Warn().
					Err(closeErr).
					Msg("Failed to close response body after error")
			}
			errorMsg := fmt.Sprintf("webhook returned error status: %d", httpResp.StatusCode)
			return &httpError{
				statusCode: httpResp.StatusCode,
				message:    errorMsg,
			}
		}

		resp = httpResp
		return nil
	})

	duration := time.Since(start)

	// Handle execution errors
	if err != nil {
		w.logger.Error().
			Err(err).
			Str("url", w.config.URL).
			Dur("duration", duration).
			Msg("Webhook request failed after retries")

		// Determine error type for metrics
		errorType := "network_error"
		if ctx.Err() == context.DeadlineExceeded {
			errorType = "timeout_error"
		}
		w.metrics.TrackWebhookError(errorType)
		return fmt.Errorf("webhook request failed: %w", err)
	}

	// Handle HTTP error responses
	if resp == nil {
		return fmt.Errorf("webhook request failed: no response received")
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

	return nil
}

// NoOpWebhookSender is a no-op implementation of WebhookSender
// that logs payloads when verbose logging is enabled
type NoOpWebhookSender struct {
	logger  observability.Logger
	verbose bool
}

// NewNoOpWebhookSender creates a new no-op webhook sender
func NewNoOpWebhookSender(logger observability.Logger, verbose bool) WebhookSender {
	return &NoOpWebhookSender{
		logger:  logger,
		verbose: verbose,
	}
}

// SendWebhook logs the payload if verbose logging is enabled, otherwise silently accepts
func (n *NoOpWebhookSender) SendWebhook(ctx context.Context, payload interface{}) error {
	if n.verbose {
		jsonData, err := json.Marshal(payload)
		if err != nil {
			n.logger.Warn().
				Err(err).
				Msg("Failed to marshal webhook payload for logging")
			return nil // Don't fail processing if logging fails
		}
		n.logger.Info().
			RawJSON("payload", jsonData).
			Msg("Webhook payload (no webhook URL configured)")
	}
	return nil
}

package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mnako/letters"
)

// messageProcessor implements the MessageProcessor interface
type messageProcessor struct {
	webhookService WebhookService
	authService    AuthService
	metricsService MetricsService
	remoteIP       net.IP
}

// NewMessageProcessor creates a new message processor
func NewMessageProcessor(
	webhookService WebhookService,
	authService AuthService,
	metricsService MetricsService,
	remoteIP net.IP,
) MessageProcessor {
	return &messageProcessor{
		webhookService: webhookService,
		authService:    authService,
		metricsService: metricsService,
		remoteIP:       remoteIP,
	}
}

// ProcessMessage processes an incoming email message
func (mp *messageProcessor) ProcessMessage(ctx context.Context, r io.Reader) error {
	startTime := time.Now()

	// Read the entire message
	var buf bytes.Buffer
	_, err := io.Copy(&buf, r)
	if err != nil {
		if mp.metricsService != nil {
			mp.metricsService.IncrementMessageParsingFailed()
		}
		return fmt.Errorf("failed to read message: %w", err)
	}

	messageData := buf.Bytes()

	// Record message size
	if mp.metricsService != nil {
		mp.metricsService.RecordMessageSize(int64(len(messageData)))
	}

	// Parse the email message
	email, err := letters.ParseEmail(bytes.NewReader(messageData))
	if err != nil {
		if mp.metricsService != nil {
			mp.metricsService.IncrementMessageParsingFailed()
		}
		return fmt.Errorf("failed to parse email: %w", err)
	}

	// Record parsing duration
	if mp.metricsService != nil {
		mp.metricsService.RecordMessageParsingDuration(time.Since(startTime))
	}

	// Perform authentication checks
	var authResult *AuthResult
	if mp.authService != nil {
		authResult, err = mp.authService.PerformAuthenticationChecks(ctx, messageData, mp.remoteIP)
		if err != nil {
			// Log error but don't fail the message processing
			// Authentication failures should not prevent message delivery
			_ = err // Explicitly ignore the error
		}
	}

	// Create webhook payload
	payload := &WebhookPayload{
		From:      email.Headers.From,
		To:        email.Headers.To,
		Subject:   email.Headers.Subject,
		Body:      email.Text,
		Headers:   mp.extractHeaders(email.Headers),
		RemoteIP:  mp.remoteIP.String(),
		Timestamp: time.Now(),
		Auth:      authResult,
	}

	// Send webhook
	if mp.webhookService != nil {
		webhookStart := time.Now()
		err = mp.webhookService.SendWebhook(ctx, payload)
		if err != nil {
			if mp.metricsService != nil {
				mp.metricsService.IncrementWebhookFailed()
			}
			return fmt.Errorf("failed to send webhook: %w", err)
		}

		// Record webhook metrics
		if mp.metricsService != nil {
			mp.metricsService.IncrementWebhookRequests()
			mp.metricsService.RecordWebhookDuration(time.Since(webhookStart))
		}
	}

	// Record successful processing
	if mp.metricsService != nil {
		mp.metricsService.IncrementMessagesProcessed()
	}

	return nil
}

// extractHeaders extracts relevant headers from the email
func (mp *messageProcessor) extractHeaders(headers letters.Headers) map[string]string {
	result := make(map[string]string)

	// Extract common headers
	if headers.MessageID != "" {
		result["Message-ID"] = string(headers.MessageID)
	}
	if !headers.Date.IsZero() {
		result["Date"] = headers.Date.Format(time.RFC3339)
	}
	if len(headers.ReplyTo) > 0 {
		result["Reply-To"] = headers.ReplyTo[0].Address
	}

	return result
}

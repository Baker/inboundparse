package service

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"time"

	"github.com/mnako/letters"
	"go.uber.org/zap"
)

// messageProcessor implements the MessageProcessor interface
type messageProcessor struct {
	webhookService WebhookService
	authService    AuthService
	metricsService MetricsService
	logger         LoggerService
	remoteIP       net.IP
}

// NewMessageProcessor creates a new message processor
func NewMessageProcessor(
	webhookService WebhookService,
	authService AuthService,
	metricsService MetricsService,
	remoteIP net.IP,
	logger LoggerService,
) MessageProcessor {
	return &messageProcessor{
		webhookService: webhookService,
		authService:    authService,
		metricsService: metricsService,
		remoteIP:       remoteIP,
		logger:         logger,
	}
}

// ProcessMessage processes an incoming email message
func (mp *messageProcessor) ProcessMessage(ctx context.Context, r io.Reader) error {
	startTime := time.Now()

	if mp.logger != nil {
		mp.logger.Debug(ctx, "starting message processing")
	}

	// Read and parse the message
	messageData, email, parseDuration, err := mp.readAndParseMessage(ctx, r)
	if err != nil {
		return err
	}

	// Perform authentication checks
	authResult := mp.performAuthChecks(ctx, messageData)

	// Create and send webhook payload
	if err := mp.sendWebhookPayload(ctx, email, authResult); err != nil {
		return err
	}

	// Record successful processing
	if mp.metricsService != nil {
		mp.metricsService.IncrementMessagesProcessed()
	}

	totalDuration := time.Since(startTime)
	if mp.logger != nil {
		mp.logger.Info(ctx, "message processing completed",
			zap.Duration("total_duration", totalDuration),
			zap.Duration("parse_duration", parseDuration),
		)
	}

	return nil
}

// readAndParseMessage reads and parses the email message
func (mp *messageProcessor) readAndParseMessage(ctx context.Context, r io.Reader) ([]byte, letters.Email, time.Duration, error) {
	// Read the entire message
	var buf bytes.Buffer
	bytesRead, err := io.Copy(&buf, r)
	if err != nil {
		if mp.metricsService != nil {
			mp.metricsService.IncrementMessageParsingFailed()
		}
		if mp.logger != nil {
			mp.logger.Error(ctx, "failed to read message", zap.Error(err))
		}
		return nil, letters.Email{}, 0, fmt.Errorf("failed to read message: %w", err)
	}

	messageData := buf.Bytes()

	// Record message size
	if mp.metricsService != nil {
		mp.metricsService.RecordMessageSize(int64(len(messageData)))
	}

	if mp.logger != nil {
		mp.logger.Info(ctx, "message received",
			zap.Int64("size_bytes", bytesRead),
			zap.String("remote_ip", mp.remoteIP.String()),
		)
	}

	// Parse the email message
	parseStart := time.Now()
	email, err := letters.ParseEmail(bytes.NewReader(messageData))
	if err != nil {
		if mp.metricsService != nil {
			mp.metricsService.IncrementMessageParsingFailed()
		}
		if mp.logger != nil {
			mp.logger.Error(ctx, "failed to parse email", zap.Error(err))
		}
		return nil, letters.Email{}, 0, fmt.Errorf("failed to parse email: %w", err)
	}

	parseDuration := time.Since(parseStart)

	// Record parsing duration
	if mp.metricsService != nil {
		mp.metricsService.RecordMessageParsingDuration(parseDuration)
	}

	// Extract email metadata for logging
	var fromAddresses, toAddresses []string
	for _, addr := range email.Headers.From {
		fromAddresses = append(fromAddresses, addr.Address)
	}
	for _, addr := range email.Headers.To {
		toAddresses = append(toAddresses, addr.Address)
	}

	if mp.logger != nil {
		mp.logger.Info(ctx, "email parsed successfully",
			zap.Strings("from", fromAddresses),
			zap.Strings("to", toAddresses),
			zap.String("subject", email.Headers.Subject),
			zap.Duration("parse_duration", parseDuration),
		)
	}

	return messageData, email, parseDuration, nil
}

// performAuthChecks performs authentication checks on the message
func (mp *messageProcessor) performAuthChecks(ctx context.Context, messageData []byte) *AuthResult {
	if mp.authService == nil {
		return nil
	}

	authStart := time.Now()
	authResult, err := mp.authService.PerformAuthenticationChecks(ctx, messageData, mp.remoteIP)
	authDuration := time.Since(authStart)

	if err != nil {
		// Log error but don't fail the message processing
		// Authentication failures should not prevent message delivery
		if mp.logger != nil {
			mp.logger.Warn(ctx, "authentication checks encountered error",
				zap.Error(err),
				zap.Duration("auth_duration", authDuration),
			)
		}
		return nil
	}

	// Log authentication results
	mp.logAuthenticationResults(ctx, authResult, authDuration)

	return authResult
}

// logAuthenticationResults logs the results of authentication checks
func (mp *messageProcessor) logAuthenticationResults(ctx context.Context, authResult *AuthResult, authDuration time.Duration) {
	if mp.logger == nil {
		return
	}

	fields := []zap.Field{
		zap.Duration("auth_duration", authDuration),
	}

	if authResult.SPF != nil {
		fields = append(fields,
			zap.String("spf_result", authResult.SPF.Result),
			zap.String("spf_domain", authResult.SPF.SenderDomain),
		)
	}

	if authResult.DKIM != nil {
		fields = append(fields,
			zap.String("dkim_result", authResult.DKIM.Result),
			zap.Int("dkim_signatures", len(authResult.DKIM.Signatures)),
		)
	}

	if authResult.DMARC != nil {
		fields = append(fields,
			zap.String("dmarc_result", authResult.DMARC.Result),
			zap.String("dmarc_policy", authResult.DMARC.Policy),
			zap.Bool("dmarc_spf_aligned", authResult.DMARC.SPFAligned),
			zap.Bool("dmarc_dkim_aligned", authResult.DMARC.DKIMAligned),
		)
	}

	mp.logger.Info(ctx, "authentication checks completed", fields...)
}

// sendWebhookPayload creates and sends the webhook payload
func (mp *messageProcessor) sendWebhookPayload(ctx context.Context, email letters.Email, authResult *AuthResult) error {
	if mp.webhookService == nil {
		return nil
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

	webhookStart := time.Now()

	if mp.logger != nil {
		mp.logger.Debug(ctx, "sending webhook")
	}

	err := mp.webhookService.SendWebhook(ctx, payload)
	webhookDuration := time.Since(webhookStart)

	if err != nil {
		if mp.metricsService != nil {
			mp.metricsService.IncrementWebhookFailed()
		}
		if mp.logger != nil {
			// Log webhook failure with context about the message
			var fromAddresses, toAddresses []string
			for _, addr := range email.Headers.From {
				fromAddresses = append(fromAddresses, addr.Address)
			}
			for _, addr := range email.Headers.To {
				toAddresses = append(toAddresses, addr.Address)
			}

			mp.logger.Error(ctx, "webhook delivery failed",
				zap.Duration("webhook_duration", webhookDuration),
				zap.Strings("from", fromAddresses),
				zap.Strings("to", toAddresses),
				zap.String("subject", email.Headers.Subject),
				zap.Int("body_length", len(email.Text)),
				zap.Error(err),
			)
		}
		return fmt.Errorf("failed to send webhook: %w", err)
	}

	// Record webhook metrics
	if mp.metricsService != nil {
		mp.metricsService.IncrementWebhookRequests()
		mp.metricsService.RecordWebhookDuration(webhookDuration)
	}

	if mp.logger != nil {
		mp.logger.Info(ctx, "webhook delivered successfully",
			zap.Duration("webhook_duration", webhookDuration),
		)
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

package processor

import (
	"bytes"
	"context"
	"fmt"
	"inboundparse/internal/auth"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"io"
	"net"
	"time"

	"github.com/mnako/letters"
)

// ProcessorConfig holds processor configuration
type ProcessorConfig struct {
	EnableSPF   bool
	EnableDKIM  bool
	EnableDMARC bool
}

// MessageProcessor handles email message processing
type MessageProcessor struct {
	config        ProcessorConfig
	authChecker   auth.AuthChecker
	webhookSender WebhookSender
	metrics       observability.MetricsCollector
	sentry        observability.SentryClient
	logger        observability.Logger
}

// NewMessageProcessor creates a new message processor
func NewMessageProcessor(
	config ProcessorConfig,
	authChecker auth.AuthChecker,
	webhookSender WebhookSender,
	metrics observability.MetricsCollector,
	sentry observability.SentryClient,
	logger observability.Logger,
) *MessageProcessor {
	return &MessageProcessor{
		config:        config,
		authChecker:   authChecker,
		webhookSender: webhookSender,
		metrics:       metrics,
		sentry:        sentry,
		logger:        logger,
	}
}

// ProcessMessage processes an email message
func (mp *MessageProcessor) ProcessMessage(ctx context.Context, r io.Reader, from string, to []string, sessionID string, remoteIP net.IP) error {
	start := time.Now()

	// Read the entire message
	var buf bytes.Buffer
	size, err := io.Copy(&buf, r)
	if err != nil {
		mp.logger.Error().
			Err(err).
			Str("session_id", sessionID).
			Msg("Failed to read message")
		mp.sentry.CaptureError(err, map[string]interface{}{
			"session_id": sessionID,
			"from":       from,
			"to":         to,
			"stage":      "read_message",
		})
		mp.metrics.TrackMessage(0, false)
		return fmt.Errorf("failed to read message: %w", err)
	}

	rawMessage := buf.String()

	// Parse the email
	email, err := letters.ParseEmail(bytes.NewReader(buf.Bytes()))
	if err != nil {
		mp.logger.Error().
			Err(err).
			Str("session_id", sessionID).
			Int64("size", size).
			Msg("Failed to parse message")
		mp.sentry.CaptureError(err, map[string]interface{}{
			"session_id": sessionID,
			"from":       from,
			"to":         to,
			"size":       size,
			"stage":      "parse_email",
		})
		mp.metrics.TrackMessage(size, false)
		return fmt.Errorf("failed to parse message: %w", err)
	}

	mp.logger.Info().
		Str("session_id", sessionID).
		Str("from", from).
		Strs("to", to).
		Str("subject", email.Headers.Subject).
		Str("message_id", string(email.Headers.MessageID)).
		Int64("size", size).
		Msg("Message parsed successfully")

	// Create webhook payload
	payload := &domain.WebhookPayload{
		Timestamp:        email.Headers.Date,
		From:             email.Headers.From,
		To:               email.Headers.To,
		Subject:          email.Headers.Subject,
		MessageID:        string(email.Headers.MessageID),
		Headers:          email.Headers.ExtraHeaders,
		TextBody:         email.Text,
		EnrichedTextBody: email.EnrichedText, // See RFC 1523, RFC 1563, and RFC 1896
		HTMLBody:         email.HTML,
		Attachments:      email.AttachedFiles,
		InlineFiles:      email.InlineFiles,
	}

	// Perform authentication checks
	if mp.config.EnableSPF || mp.config.EnableDKIM || mp.config.EnableDMARC {
		authResults, err := mp.performAuthenticationChecks(ctx, rawMessage, email.Headers, from, remoteIP)
		if err != nil {
			mp.logger.Warn().
				Err(err).
				Str("session_id", sessionID).
				Msg("Authentication checks failed")
			// Continue processing even if auth checks fail
		} else {
			payload.AuthenticationResults = authResults
		}
	}

	// Send to webhook
	err = mp.webhookSender.SendWebhook(ctx, payload)

	duration := time.Since(start)
	if err != nil {
		mp.logger.Error().
			Err(err).
			Str("session_id", sessionID).
			Str("message_id", string(email.Headers.MessageID)).
			Dur("duration", duration).
			Msg("Failed to process message")
		mp.metrics.TrackMessage(size, false)
		return err
	}

	mp.logger.Info().
		Str("session_id", sessionID).
		Str("message_id", string(email.Headers.MessageID)).
		Dur("duration", duration).
		Msg("Message processed successfully")
	mp.metrics.TrackMessage(size, true)

	return nil
}

// performAuthenticationChecks runs all enabled authentication checks
func (mp *MessageProcessor) performAuthenticationChecks(ctx context.Context, rawMessage string, headers letters.Headers, from string, remoteIP net.IP) (domain.AuthenticationResults, error) {
	results := domain.AuthenticationResults{}

	mp.logger.Debug().
		Bool("spf_enabled", mp.config.EnableSPF).
		Bool("dkim_enabled", mp.config.EnableDKIM).
		Bool("dmarc_enabled", mp.config.EnableDMARC).
		Msg("Starting authentication checks")

	// Extract domain from MAIL FROM (envelope sender)
	domain := auth.ExtractDomainFromEmail(from)

	// SPF Check
	if mp.config.EnableSPF {
		spfResult, err := mp.authChecker.CheckSPF(ctx, remoteIP, domain, from)
		if err != nil {
			mp.logger.Warn().
				Err(err).
				Msg("SPF check failed")
			mp.sentry.CaptureError(err, map[string]interface{}{
				"check_type": "spf",
				"from":       from,
				"domain":     domain,
			})
		} else if spfResult != nil {
			results.SPF = spfResult
			mp.metrics.TrackSPFResult(spfResult.Result)
		}
	}

	// DKIM Check
	if mp.config.EnableDKIM {
		dkimResult, err := mp.authChecker.CheckDKIM(ctx, rawMessage)
		if err != nil {
			mp.logger.Warn().
				Err(err).
				Msg("DKIM check failed")
			mp.sentry.CaptureError(err, map[string]interface{}{
				"check_type": "dkim",
				"from":       from,
			})
		} else if dkimResult != nil {
			results.DKIM = dkimResult
			mp.metrics.TrackDKIMResult(dkimResult.Valid)
		}
	}

	// DMARC Check - pass previously computed results to avoid redundant checks
	if mp.config.EnableDMARC {
		dmarcResult, err := mp.authChecker.CheckDMARC(ctx, rawMessage, headers, results.SPF, results.DKIM)
		if err != nil {
			mp.logger.Warn().
				Err(err).
				Msg("DMARC check failed")
			mp.sentry.CaptureError(err, map[string]interface{}{
				"check_type": "dmarc",
				"from":       from,
			})
		} else if dmarcResult != nil {
			results.DMARC = dmarcResult
			mp.metrics.TrackDMARCResult(dmarcResult.Result, dmarcResult.Policy)
		}
	}

	mp.logger.Info().
		Interface("spf", results.SPF).
		Interface("dkim", results.DKIM).
		Interface("dmarc", results.DMARC).
		Msg("Authentication checks completed")

	return results, nil
}

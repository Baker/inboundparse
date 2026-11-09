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
	"sync"
	"time"

	"github.com/mnako/letters"
)

// ProcessorConfig holds processor configuration
type ProcessorConfig struct {
	EnableSPF   bool
	EnableDKIM  bool
	EnableDKIM2 bool
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

	// Create session-aware logger with session_id context
	sessionLogger := observability.NewSessionLogger(mp.logger, sessionID, "")

	// Read the entire message
	readStart := time.Now()
	var buf bytes.Buffer
	size, err := io.Copy(&buf, r)
	readDuration := time.Since(readStart)
	mp.metrics.TrackMessageReadDuration(readDuration)

	if err != nil {
		sessionLogger.Error().
			Err(err).
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
	parseStart := time.Now()
	email, err := letters.ParseEmail(bytes.NewReader(buf.Bytes()))
	parseDuration := time.Since(parseStart)
	mp.metrics.TrackMessageParseDuration(parseDuration)

	if err != nil {
		sessionLogger.Error().
			Err(err).
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

	sessionLogger.Info().
		Str("from", from).
		Strs("to", to).
		Str("subject", email.Headers.Subject).
		Str("message_id", string(email.Headers.MessageID)).
		Int64("size", size).
		Msg("Message parsed successfully")

	// Track email characteristics
	mp.trackEmailCharacteristics(&email)

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
	if mp.config.EnableSPF || mp.config.EnableDKIM || mp.config.EnableDKIM2 || mp.config.EnableDMARC {
		authStart := time.Now()
		authResults, err := mp.performAuthenticationChecks(ctx, rawMessage, email.Headers, from, to, remoteIP, sessionLogger)
		authDuration := time.Since(authStart)
		mp.metrics.TrackMessageAuthDuration(authDuration)

		if err != nil {
			sessionLogger.Warn().
				Err(err).
				Msg("Authentication checks failed")
			// Continue processing even if auth checks fail
		} else {
			payload.AuthenticationResults = authResults
		}
	}

	// Send to webhook
	webhookStart := time.Now()
	err = mp.webhookSender.SendWebhook(ctx, payload)
	webhookDuration := time.Since(webhookStart)
	mp.metrics.TrackMessageWebhookDuration(webhookDuration)

	duration := time.Since(start)
	mp.metrics.TrackMessageTotalProcessingDuration(duration)

	if err != nil {
		sessionLogger.Error().
			Err(err).
			Str("message_id", string(email.Headers.MessageID)).
			Dur("duration", duration).
			Msg("Failed to process message")
		mp.metrics.TrackMessage(size, false)
		return err
	}

	sessionLogger.Info().
		Str("message_id", string(email.Headers.MessageID)).
		Dur("duration", duration).
		Msg("Message processed successfully")
	mp.metrics.TrackMessage(size, true)

	return nil
}

// performAuthenticationChecks runs all enabled authentication checks.
// SPF, DKIM, and DKIM2 run concurrently. DMARC waits on SPF and DKIM only.
func (mp *MessageProcessor) performAuthenticationChecks(ctx context.Context, rawMessage string, headers letters.Headers, from string, to []string, remoteIP net.IP, sessionLogger observability.Logger) (domain.AuthenticationResults, error) {
	results := domain.AuthenticationResults{}

	sessionLogger.Debug().
		Bool("spf_enabled", mp.config.EnableSPF).
		Bool("dkim_enabled", mp.config.EnableDKIM).
		Bool("dkim2_enabled", mp.config.EnableDKIM2).
		Bool("dmarc_enabled", mp.config.EnableDMARC).
		Msg("Starting authentication checks")

	senderDomain := auth.ExtractDomainFromEmail(from)

	// SPF, RFC 6376 DKIM, and DKIM2 are independent.
	var (
		spfResult   *domain.SPFResult
		dkimResult  *domain.DKIMResult
		dkim2Result *domain.DKIM2Result
		spfErr      error
		dkimErr     error
		dkim2Err    error
		wg          sync.WaitGroup
	)

	if mp.config.EnableSPF {
		wg.Add(1)
		go func() {
			defer wg.Done()
			spfResult, spfErr = mp.authChecker.CheckSPF(ctx, remoteIP, senderDomain, from, sessionLogger, mp.metrics)
		}()
	}

	if mp.config.EnableDKIM {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dkimResult, dkimErr = mp.authChecker.CheckDKIM(ctx, rawMessage, sessionLogger, mp.metrics)
		}()
	}

	if mp.config.EnableDKIM2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dkim2Result, dkim2Err = mp.authChecker.CheckDKIM2(ctx, rawMessage, from, to, sessionLogger, mp.metrics)
		}()
	}

	wg.Wait()

	if spfErr != nil {
		sessionLogger.Warn().Err(spfErr).Msg("SPF check failed")
		mp.sentry.CaptureError(spfErr, map[string]interface{}{
			"check_type": "spf",
			"from":       from,
			"domain":     senderDomain,
		})
	} else if spfResult != nil {
		results.SPF = spfResult
		mp.metrics.TrackSPFResult(spfResult.Result)
	}

	if dkimErr != nil {
		sessionLogger.Warn().Err(dkimErr).Msg("DKIM check failed")
		mp.sentry.CaptureError(dkimErr, map[string]interface{}{
			"check_type": "dkim",
			"from":       from,
		})
	} else if dkimResult != nil {
		results.DKIM = dkimResult
		mp.metrics.TrackDKIMResult(dkimResult.Valid)
	}

	if dkim2Err != nil {
		sessionLogger.Warn().Err(dkim2Err).Msg("DKIM2 check failed")
		mp.sentry.CaptureError(dkim2Err, map[string]interface{}{
			"check_type": "dkim2",
			"from":       from,
		})
	} else if dkim2Result != nil {
		results.DKIM2 = dkim2Result
		mp.metrics.TrackDKIM2Result(dkim2Result.Result, dkim2Result.Reason)
	}

	// DMARC depends on SPF and RFC 6376 DKIM. DKIM2 is not an input.
	if mp.config.EnableDMARC {
		dmarcResult, err := mp.authChecker.CheckDMARC(ctx, rawMessage, headers, results.SPF, results.DKIM, sessionLogger, mp.metrics)
		if err != nil {
			sessionLogger.Warn().Err(err).Msg("DMARC check failed")
			mp.sentry.CaptureError(err, map[string]interface{}{
				"check_type": "dmarc",
				"from":       from,
			})
		} else if dmarcResult != nil {
			results.DMARC = dmarcResult
			mp.metrics.TrackDMARCResult(dmarcResult.Result, dmarcResult.Policy)
		}
	}

	completed := sessionLogger.Info().
		Interface("spf", results.SPF).
		Interface("dkim", results.DKIM).
		Interface("dmarc", results.DMARC)
	if results.DKIM2 != nil {
		completed = completed.
			Str("dkim2_result", results.DKIM2.Result).
			Str("dkim2_reason", results.DKIM2.Reason)
	}
	completed.Msg("Authentication checks completed")

	return results, nil
}

// trackEmailCharacteristics tracks various characteristics of the parsed email
func (mp *MessageProcessor) trackEmailCharacteristics(email *letters.Email) {
	// Track attachment count and size
	attachmentCount := len(email.AttachedFiles)
	mp.metrics.TrackEmailAttachmentCount(attachmentCount)

	var totalAttachmentSize int64
	for _, attachment := range email.AttachedFiles {
		totalAttachmentSize += int64(len(attachment.Data))
	}
	if totalAttachmentSize > 0 {
		mp.metrics.TrackEmailAttachmentSize(totalAttachmentSize)
	}

	// Track body type
	bodyType := "text"
	if email.HTML != "" {
		bodyType = "html"
	}
	if len(email.AttachedFiles) > 0 {
		bodyType = "multipart"
	}
	mp.metrics.TrackEmailBodyType(bodyType)

	// Track header count
	headerCount := len(email.Headers.ExtraHeaders)
	mp.metrics.TrackEmailHeaderCount(headerCount)

	// Track recipient count (To + CC + BCC)
	recipientCount := len(email.Headers.To) + len(email.Headers.Cc) + len(email.Headers.Bcc)
	mp.metrics.TrackEmailRecipientCount(recipientCount)
}

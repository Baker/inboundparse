package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/mail"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/getsentry/sentry-go"
	"github.com/mnako/letters"
	"github.com/rs/zerolog/log"
)

type MessageProcessor struct {
	config    *ServerConfig
	from      string
	to        []string
	conn      *smtp.Conn
	sessionID string
	// testRemoteIP allows tests to stub the remote IP without a real connection
	testRemoteIP net.IP
}

type EmailAddress struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
}

type AuthenticationResults struct {
	SPF   *SPFResult   `json:"spf,omitempty"`
	DKIM  *DKIMResult  `json:"dkim,omitempty"`
	DMARC *DMARCResult `json:"dmarc,omitempty"`
}

type SPFResult struct {
	Result    string `json:"result"`
	Raw       string `json:"raw"`
	Mechanism string `json:"mechanism,omitempty"`
	Qualifier string `json:"qualifier,omitempty"`
}

type DKIMResult struct {
	Valid      bool     `json:"valid"`
	Signatures []string `json:"signatures,omitempty"`
	Raw        string   `json:"raw"`
	Error      string   `json:"error,omitempty"`
}

type DMARCResult struct {
	Result string `json:"result"`
	Raw    string `json:"raw"`
	Policy string `json:"policy,omitempty"`
	Error  string `json:"error,omitempty"`
}

type Attachment struct {
	Filename           string `json:"filename"`
	ContentType        string `json:"content_type"`
	ContentDisposition string `json:"content_disposition"`
	ContentID          string `json:"content_id,omitempty"`
}

type Body struct {
	Text        string       `json:"text,omitempty"`
	HTML        string       `json:"html,omitempty"`
	AMP         string       `json:"amp,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

type WebhookPayload struct {
	Timestamp             time.Time              `json:"timestamp"`
	From                  []*mail.Address        `json:"from"`
	To                    []*mail.Address        `json:"to"`
	Subject               string                 `json:"subject"`
	MessageID             string                 `json:"message_id"`
	Headers               map[string][]string    `json:"headers"`
	TextBody              string                 `json:"text_body"`
	EnrichedTextBody      string                 `json:"enriched_text_body"`
	HTMLBody              string                 `json:"html_body"`
	Attachments           []letters.AttachedFile `json:"attachments"`
	InlineFiles           []letters.InlineFile   `json:"inline_files"`
	AuthenticationResults AuthenticationResults  `json:"authentication_results"`
}

func (mp *MessageProcessor) ProcessMessage(r io.Reader) error {
	start := time.Now()

	// Read the entire message
	var buf bytes.Buffer
	size, err := io.Copy(&buf, r)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", mp.sessionID).
			Msg("Failed to read message")
		CaptureError(err, map[string]interface{}{
			"session_id": mp.sessionID,
			"from":       mp.from,
			"to":         mp.to,
			"stage":      "read_message",
		})
		TrackMessage(0, false)
		return fmt.Errorf("failed to read message: %w", err)
	}

	rawMessage := buf.String()

	// Parse the email
	email, err := letters.ParseEmail(bytes.NewReader(buf.Bytes()))
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", mp.sessionID).
			Int64("size", size).
			Msg("Failed to parse message")
		CaptureError(err, map[string]interface{}{
			"session_id": mp.sessionID,
			"from":       mp.from,
			"to":         mp.to,
			"size":       size,
			"stage":      "parse_email",
		})
		TrackMessage(size, false)
		return fmt.Errorf("failed to parse message: %w", err)
	}

	log.Info().
		Str("session_id", mp.sessionID).
		Str("from", mp.from).
		Strs("to", mp.to).
		Str("subject", email.Headers.Subject).
		Str("message_id", string(email.Headers.MessageID)).
		Int64("size", size).
		Msg("Message parsed successfully")

	// Create webhook payload
	payload := &WebhookPayload{
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
		payload.AuthenticationResults = mp.performAuthenticationChecks(rawMessage, email.Headers)
	}

	// Send to webhook
	err = mp.sendWebhook(payload)

	duration := time.Since(start)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", mp.sessionID).
			Str("message_id", string(email.Headers.MessageID)).
			Dur("duration", duration).
			Msg("Failed to process message")
		TrackMessage(size, false)
		return err
	}

	log.Info().
		Str("session_id", mp.sessionID).
		Str("message_id", string(email.Headers.MessageID)).
		Dur("duration", duration).
		Msg("Message processed successfully")
	TrackMessage(size, true)

	return nil
}

func (mp *MessageProcessor) sendWebhook(payload *WebhookPayload) error {
	start := time.Now()

	jsonData, err := json.Marshal(payload)
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", mp.sessionID).
			Msg("Failed to marshal webhook payload")
		CaptureError(err, map[string]interface{}{
			"session_id": mp.sessionID,
			"from":       mp.from,
			"to":         mp.to,
			"subject":    payload.Subject,
			"message_id": payload.MessageID,
			"stage":      "marshal_payload",
		})
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", mp.config.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", mp.sessionID).
			Str("webhook_url", mp.config.WebhookURL).
			Msg("Failed to create webhook request")
		CaptureError(err, map[string]interface{}{
			"session_id":  mp.sessionID,
			"webhook_url": mp.config.WebhookURL,
			"stage":       "create_request",
		})
		return fmt.Errorf("failed to create request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "inboundparse/1.0")

	// Add basic authentication if configured
	if mp.config.WebhookUser != "" && mp.config.WebhookPass != "" {
		req.SetBasicAuth(mp.config.WebhookUser, mp.config.WebhookPass)
	}

	client := &http.Client{
		Timeout: 30 * time.Second,
	}

	resp, err := client.Do(req)
	duration := time.Since(start)

	if err != nil {
		log.Error().
			Err(err).
			Str("session_id", mp.sessionID).
			Str("webhook_url", mp.config.WebhookURL).
			Dur("duration", duration).
			Msg("Webhook request failed")
		CaptureError(err, map[string]interface{}{
			"session_id":  mp.sessionID,
			"webhook_url": mp.config.WebhookURL,
			"from":        mp.from,
			"to":          mp.to,
			"subject":     payload.Subject,
			"message_id":  payload.MessageID,
			"stage":       "send_request",
		})
		TrackWebhookRequest(0, duration)
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Warn().
				Err(closeErr).
				Str("session_id", mp.sessionID).
				Msg("Failed to close response body")
		}
	}()

	TrackWebhookRequest(resp.StatusCode, duration)

	if resp.StatusCode >= 400 {
		log.Error().
			Str("session_id", mp.sessionID).
			Str("webhook_url", mp.config.WebhookURL).
			Int("status_code", resp.StatusCode).
			Dur("duration", duration).
			Msg("Webhook returned error status")

		CaptureMessage(
			fmt.Sprintf("Webhook returned error status: %d", resp.StatusCode),
			sentry.LevelError,
			map[string]interface{}{
				"session_id":  mp.sessionID,
				"webhook_url": mp.config.WebhookURL,
				"status_code": resp.StatusCode,
				"from":        mp.from,
				"to":          mp.to,
				"subject":     payload.Subject,
				"message_id":  payload.MessageID,
			},
		)
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	log.Info().
		Str("session_id", mp.sessionID).
		Str("webhook_url", mp.config.WebhookURL).
		Int("status_code", resp.StatusCode).
		Dur("duration", duration).
		Msg("Successfully sent email to webhook")

	return nil
}

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/mail"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/mnako/letters"
)

type MessageProcessor struct {
	config *ServerConfig
	from   string
	to     []string
	conn   *smtp.Conn
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
	startTime := time.Now()

	// Read the entire message
	var buf bytes.Buffer
	_, err := io.Copy(&buf, r)
	if err != nil {
		if mp.config.Metrics != nil {
			mp.config.Metrics.IncrementMessageParsingFailed()
		}
		return fmt.Errorf("failed to read message: %w", err)
	}

	rawMessage := buf.String()

	// Record message size
	if mp.config.Metrics != nil {
		mp.config.Metrics.RecordMessageSize(int64(buf.Len()))
	}

	// Parse the email
	email, err := letters.ParseEmail(bytes.NewReader(buf.Bytes()))
	if err != nil {
		if mp.config.Metrics != nil {
			mp.config.Metrics.IncrementMessageParsingFailed()
		}
		return fmt.Errorf("failed to parse message: %w", err)
	}

	// Record parsing duration
	if mp.config.Metrics != nil {
		mp.config.Metrics.RecordMessageParsingDuration(time.Since(startTime))
	}

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
		payload.AuthenticationResults = mp.performAuthenticationChecksWithMetrics(rawMessage, email.Headers)
	}

	// Send to webhook
	return mp.sendWebhook(payload)
}

func (mp *MessageProcessor) sendWebhook(payload *WebhookPayload) error {
	startTime := time.Now()

	jsonData, err := json.Marshal(payload)
	if err != nil {
		if mp.config.Metrics != nil {
			mp.config.Metrics.IncrementWebhookFailed()
		}
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", mp.config.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
		if mp.config.Metrics != nil {
			mp.config.Metrics.IncrementWebhookFailed()
		}
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

	// Record webhook request
	if mp.config.Metrics != nil {
		mp.config.Metrics.IncrementWebhookRequests()
	}

	resp, err := client.Do(req)
	if err != nil {
		if mp.config.Metrics != nil {
			mp.config.Metrics.IncrementWebhookFailed()
		}
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer func() {
		if closeErr := resp.Body.Close(); closeErr != nil {
			log.Printf("Failed to close response body: %v", closeErr)
		}
	}()

	// Record webhook duration
	if mp.config.Metrics != nil {
		mp.config.Metrics.RecordWebhookDuration(time.Since(startTime))
	}

	if resp.StatusCode >= 400 {
		if mp.config.Metrics != nil {
			mp.config.Metrics.IncrementWebhookFailed()
		}
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	if mp.config.Verbose {
		log.Printf("Successfully sent email to webhook: %s", mp.config.WebhookURL)
	}

	return nil
}

func (mp *MessageProcessor) performAuthenticationChecksWithMetrics(rawMessage string, headers letters.Headers) AuthenticationResults {
	results := AuthenticationResults{}

	// SPF Check
	if mp.config.EnableSPF {
		if mp.config.Metrics != nil {
			mp.config.Metrics.IncrementAuthChecks()
			mp.config.Metrics.IncrementSPFChecks()
		}

		results.SPF = mp.checkSPF()
		if results.SPF != nil {
			if mp.config.Metrics != nil {
				// Record detailed SPF result
				mp.config.Metrics.RecordSPFResult(results.SPF.Result)

				if results.SPF.Result == "temperror" {
					mp.config.Metrics.IncrementAuthChecksFailed()
				}
			}
		}
	}

	// DKIM Check
	if mp.config.EnableDKIM {
		if mp.config.Metrics != nil {
			mp.config.Metrics.IncrementAuthChecks()
			mp.config.Metrics.IncrementDKIMChecks()
		}

		results.DKIM = mp.checkDKIM(rawMessage)
		if results.DKIM != nil {
			if mp.config.Metrics != nil {
				// Record detailed DKIM result
				if results.DKIM.Valid {
					mp.config.Metrics.RecordDKIMResult("pass")
				} else {
					mp.config.Metrics.RecordDKIMResult("fail")
				}

				if !results.DKIM.Valid && results.DKIM.Error != "" {
					mp.config.Metrics.IncrementAuthChecksFailed()
				}
			}
		}
	}

	// DMARC Check
	if mp.config.EnableDMARC {
		if mp.config.Metrics != nil {
			mp.config.Metrics.IncrementAuthChecks()
			mp.config.Metrics.IncrementDMARCChecks()
		}

		results.DMARC = mp.checkDMARC(rawMessage, headers, results.SPF, results.DKIM)
		if results.DMARC != nil {
			if mp.config.Metrics != nil {
				// Record detailed DMARC result
				mp.config.Metrics.RecordDMARCResult(results.DMARC.Result)

				// Record DMARC policy
				mp.config.Metrics.RecordDMARCPolicy(results.DMARC.Policy)

				if results.DMARC.Result == "temperror" {
					mp.config.Metrics.IncrementAuthChecksFailed()
				}
			}
		}
	}

	return results
}

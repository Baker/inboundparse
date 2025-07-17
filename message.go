package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
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
	Headers               letters.Headers        `json:"headers"`
	TextBody              string                 `json:"text_body"`
	EnrichedTextBody      string                 `json:"enriched_text_body"`
	HTMLBody              string                 `json:"html_body"`
	Attachments           []letters.AttachedFile `json:"attachments"`
	InlineFiles           []letters.InlineFile   `json:"inline_files"`
	AuthenticationResults AuthenticationResults  `json:"authentication_results"`
	ServerInfo            ServerInfo             `json:"server_info"`
}

type ServerInfo struct {
	RemoteAddr string `json:"remote_addr"`
	LocalAddr  string `json:"local_addr"`
	ServerName string `json:"server_name"`
}

func (mp *MessageProcessor) ProcessMessage(r io.Reader) error {
	// Read the entire message
	var buf bytes.Buffer
	_, err := io.Copy(&buf, r)
	if err != nil {
		return fmt.Errorf("failed to read message: %w", err)
	}

	rawMessage := buf.String()

	// Parse the email
	email, err := letters.ParseEmail(bytes.NewReader(buf.Bytes()))
	if err != nil {
		return fmt.Errorf("failed to parse message: %w", err)
	}

	// Create webhook payload
	payload := &WebhookPayload{
		Timestamp:        email.Headers.Date,
		From:             email.Headers.From,
		To:               email.Headers.To,
		Subject:          email.Headers.Subject,
		MessageID:        string(email.Headers.MessageID),
		Headers:          email.Headers,
		TextBody:         email.Text,
		EnrichedTextBody: email.EnrichedText, // See RFC 1523, RFC 1563, and RFC 1896
		HTMLBody:         email.HTML,
		Attachments:      email.AttachedFiles,
		InlineFiles:      email.InlineFiles,
		ServerInfo: ServerInfo{
			RemoteAddr: mp.getRemoteAddr(),
			LocalAddr:  mp.getLocalAddr(),
			ServerName: mp.config.ServerName,
		},
	}

	// Perform authentication checks
	if mp.config.EnableSPF || mp.config.EnableDKIM || mp.config.EnableDMARC {
		payload.AuthenticationResults = mp.performAuthenticationChecks(rawMessage, email.Headers)
	}

	// Send to webhook
	return mp.sendWebhook(payload)
}

func (mp *MessageProcessor) getRemoteAddr() string {
	if mp.conn != nil && mp.conn.Conn() != nil {
		return mp.conn.Conn().RemoteAddr().String()
	}
	return "unknown"
}

func (mp *MessageProcessor) getLocalAddr() string {
	if mp.conn != nil && mp.conn.Conn() != nil {
		return mp.conn.Conn().LocalAddr().String()
	}
	return "unknown"
}

func (mp *MessageProcessor) sendWebhook(payload *WebhookPayload) error {
	jsonData, err := json.Marshal(payload)
	if err != nil {
		return fmt.Errorf("failed to marshal payload: %w", err)
	}

	req, err := http.NewRequest("POST", mp.config.WebhookURL, bytes.NewBuffer(jsonData))
	if err != nil {
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
	if err != nil {
		return fmt.Errorf("webhook request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 400 {
		return fmt.Errorf("webhook returned error status: %d", resp.StatusCode)
	}

	if mp.config.Verbose {
		log.Printf("Successfully sent email to webhook: %s", mp.config.WebhookURL)
	}

	return nil
}

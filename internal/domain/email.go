package domain

import (
	"net/mail"
	"time"

	"github.com/mnako/letters"
)

// EmailAddress represents an email address with optional display name
type EmailAddress struct {
	Address string `json:"address"`
	Name    string `json:"name,omitempty"`
}

// AuthenticationResults contains the results of email authentication checks
type AuthenticationResults struct {
	SPF   *SPFResult   `json:"spf,omitempty"`
	DKIM  *DKIMResult  `json:"dkim,omitempty"`
	DMARC *DMARCResult `json:"dmarc,omitempty"`
}

// SPFResult contains SPF validation results
type SPFResult struct {
	Result      string `json:"result"`
	Raw         string `json:"raw"`
	Mechanism   string `json:"mechanism,omitempty"`
	Qualifier   string `json:"qualifier,omitempty"`
	Explanation string `json:"explanation,omitempty"` // SPF explanation from DNS (RFC 7208 Section 6.2)
	Problem     string `json:"problem,omitempty"`     // Description of any processing issues
	Sender      string `json:"sender,omitempty"`      // The identity checked (MAIL FROM)
}

// DKIMSignatureDetail contains detailed information about a single DKIM signature
type DKIMSignatureDetail struct {
	Domain        string   `json:"domain"`               // d= tag
	Selector      string   `json:"selector"`             // s= tag
	Algorithm     string   `json:"algorithm"`            // a= tag
	HeadersSigned []string `json:"headers_signed"`       // h= tag
	BodyHash      string   `json:"body_hash"`            // bh= tag
	Timestamp     int64    `json:"timestamp,omitempty"`  // t= tag
	Expiration    int64    `json:"expiration,omitempty"` // x= tag
	Valid         bool     `json:"valid"`
	Error         string   `json:"error,omitempty"`
}

// DKIMResult contains DKIM validation results
type DKIMResult struct {
	Valid      bool                  `json:"valid"`
	Signatures []string              `json:"signatures,omitempty"`
	Details    []DKIMSignatureDetail `json:"details,omitempty"` // Per-signature structured data
	Raw        string                `json:"raw"`
	Error      string                `json:"error,omitempty"`
}

// DMARCResult contains DMARC validation results
type DMARCResult struct {
	Result          string `json:"result"`
	Raw             string `json:"raw"`
	Policy          string `json:"policy,omitempty"`
	Error           string `json:"error,omitempty"`
	Domain          string `json:"domain,omitempty"`           // Domain where policy was found
	Percentage      int    `json:"percentage,omitempty"`       // pct= tag value (RFC 7489 Section 6.3)
	SubdomainPolicy string `json:"subdomain_policy,omitempty"` // sp= tag value
	SPFAligned      bool   `json:"spf_aligned"`                // Whether SPF identifier aligned
	DKIMAligned     bool   `json:"dkim_aligned"`               // Whether DKIM identifier aligned
	SPFDomain       string `json:"spf_domain,omitempty"`       // Domain used for SPF alignment check
	DKIMDomain      string `json:"dkim_domain,omitempty"`      // Domain(s) used for DKIM alignment
}

// Attachment represents an email attachment
type Attachment struct {
	Filename           string `json:"filename"`
	ContentType        string `json:"content_type"`
	ContentDisposition string `json:"content_disposition"`
	ContentID          string `json:"content_id,omitempty"`
}

// Body represents the email body content
type Body struct {
	Text        string       `json:"text,omitempty"`
	HTML        string       `json:"html,omitempty"`
	AMP         string       `json:"amp,omitempty"`
	Attachments []Attachment `json:"attachments,omitempty"`
}

// WebhookPayload represents the payload sent to webhooks
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

// MessageProcessor represents a message processor with its dependencies
type MessageProcessor struct {
	From      string
	To        []string
	SessionID string
	// TestRemoteIP allows tests to stub the remote IP without a real connection
	TestRemoteIP string
}

// NewMessageProcessor creates a new message processor
func NewMessageProcessor(from string, to []string, sessionID string) *MessageProcessor {
	return &MessageProcessor{
		From:      from,
		To:        to,
		SessionID: sessionID,
	}
}

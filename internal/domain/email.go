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

// AuthenticationResults contains the results of email authentication checks.
// DKIM2 is draft-ietf-dkim-dkim2-spec-09 and stays separate from RFC 6376 DKIM
// and RFC 7489 DMARC.
type AuthenticationResults struct {
	SPF   *SPFResult   `json:"spf,omitempty"`
	DKIM  *DKIMResult  `json:"dkim,omitempty"`
	DKIM2 *DKIM2Result `json:"dkim2,omitempty"`
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
	IpAddress   string `json:"ip_address,omitempty"`  // The IP address checked (from remote IP)
}

// DKIMSignatureDetail contains detailed information about a single DKIM signature
// Only includes fields available from go-msgauth library
type DKIMSignatureDetail struct {
	Domain        string   `json:"domain"`               // d= tag (from verification.Domain)
	HeadersSigned []string `json:"headers_signed"`       // h= tag (from verification.HeaderKeys)
	Timestamp     int64    `json:"timestamp,omitempty"`  // t= tag (from verification.Time)
	Expiration    int64    `json:"expiration,omitempty"` // x= tag (from verification.Expiration)
	Valid         bool     `json:"valid"`
	Error         string   `json:"error,omitempty"`
}

// DMARCLookupDetail contains detailed information about a single DMARC lookup attempt
type DMARCLookupDetail struct {
	Domain      string `json:"domain"`                // Domain where lookup was attempted
	RecordFound bool   `json:"record_found"`          // Whether a record was found
	PolicyUsed  string `json:"policy_used,omitempty"` // Which policy was applied (p or sp)
	Error       string `json:"error,omitempty"`       // Any error during lookup
}

// DKIMResult contains DKIM validation results
type DKIMResult struct {
	Valid      bool                  `json:"valid"`
	Signatures []string              `json:"signatures,omitempty"`
	Details    []DKIMSignatureDetail `json:"details,omitempty"` // Per-signature structured data
	Raw        string                `json:"raw"`
	Error      string                `json:"error,omitempty"`
}

// DKIM2Check is one closed-vocabulary fact from DKIM2 verification.
type DKIM2Check struct {
	Class  string `json:"class"`
	Reason string `json:"reason"`
}

// DKIM2Signature is one signature-set fact. Selector is present only when the
// library exposes it, which is for a set that did not pass.
type DKIM2Signature struct {
	Algorithm string `json:"algorithm"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	Selector  string `json:"selector,omitempty"`
}

// DKIM2Result is the draft-09 verification state reported on the webhook.
// Result is none, pass, fail, temperror, or permerror. Reason is the library
// reason code, or unavailable when the check was canceled. The signing domain
// is withheld on purpose.
type DKIM2Result struct {
	Result               string           `json:"result"`
	Reason               string           `json:"reason,omitempty"`
	Scope                string           `json:"scope,omitempty"`
	HistoricalContent    string           `json:"historical_content,omitempty"`
	HistoricalSignatures string           `json:"historical_signatures,omitempty"`
	Custody              string           `json:"custody,omitempty"`
	Sequence             uint64           `json:"sequence,omitempty"`
	Instance             uint64           `json:"instance,omitempty"`
	Checks               []DKIM2Check     `json:"checks,omitempty"`
	Signatures           []DKIM2Signature `json:"signatures,omitempty"`
}

// DMARCResult contains DMARC validation results
type DMARCResult struct {
	Result          string              `json:"result"`
	Raw             string              `json:"raw"`
	Policy          string              `json:"policy,omitempty"`
	Error           string              `json:"error,omitempty"`
	Domain          string              `json:"domain,omitempty"`           // Domain where policy was found
	Percentage      int                 `json:"percentage"`                 // pct= tag value (RFC 7489 Section 6.3)
	SubdomainPolicy string              `json:"subdomain_policy,omitempty"` // sp= tag value
	SPFAligned      bool                `json:"spf_aligned"`                // Whether SPF identifier aligned
	DKIMAligned     bool                `json:"dkim_aligned"`               // Whether DKIM identifier aligned
	SPFDomain       string              `json:"spf_domain,omitempty"`       // Domain used for SPF alignment check
	DKIMDomain      string              `json:"dkim_domain,omitempty"`      // Domain(s) used for DKIM alignment
	Details         []DMARCLookupDetail `json:"details,omitempty"`          // Per-domain lookup details
	// Additional RFC 7489 compliant fields
	SPFAlignment   string   `json:"spf_alignment,omitempty"`   // aspf= tag value (RFC 7489 Section 6.3)
	DKIMAlignment  string   `json:"dkim_alignment,omitempty"`  // adkim= tag value (RFC 7489 Section 6.3)
	FailureOptions string   `json:"failure_options,omitempty"` // fo= tag value (RFC 7489 Section 6.3)
	ReportURIs     []string `json:"report_uris,omitempty"`     // rua= tag values (RFC 7489 Section 6.3)
	FailureURIs    []string `json:"failure_uris,omitempty"`    // ruf= tag values (RFC 7489 Section 6.3)
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

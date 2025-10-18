package service

import (
	"context"
	"io"
	"net"
	"net/mail"
	"time"

	"github.com/emersion/go-smtp"
)

// MetricsService defines the interface for metrics collection
type MetricsService interface {
	IncrementSMTPConnections()
	IncrementActiveConnections()
	DecrementActiveConnections()
	RecordConnectionDuration(duration time.Duration)
	IncrementSMTPMessages()
	RecordMessageSize(size int64)
	IncrementMessagesProcessed()
	IncrementMessagesFailed()
	IncrementWebhookRequests()
	RecordWebhookDuration(duration time.Duration)
	IncrementWebhookFailed()
	IncrementAuthChecks()
	IncrementSPFChecks()
	IncrementDKIMChecks()
	IncrementDMARCChecks()
	IncrementAuthChecksFailed()
	RecordMessageParsingDuration(duration time.Duration)
	IncrementMessageParsingFailed()
	IncrementActiveSessions()
	DecrementActiveSessions()
	RecordSPFResult(result string)
	RecordDKIMResult(result string)
	RecordDMARCResult(result string)
	RecordDMARCPolicy(policy string)
	Close() error
}

// WebhookService defines the interface for webhook operations
type WebhookService interface {
	SendWebhook(ctx context.Context, payload *WebhookPayload) error
}

// AuthService defines the interface for email authentication
type AuthService interface {
	PerformAuthenticationChecks(ctx context.Context, message []byte, remoteIP net.IP, heloName string, mailFrom string) (*AuthResult, error)
}

// MessageProcessor defines the interface for message processing
type MessageProcessor interface {
	ProcessMessage(ctx context.Context, r io.Reader, heloName string, mailFrom string) error
}

// SMTPBackend defines the interface for SMTP backend operations
type SMTPBackend interface {
	NewSession(conn *smtp.Conn) (smtp.Session, error)
}

// SMTPHandler defines the interface for SMTP session handling
type SMTPHandler interface {
	AuthPlain(username, password string) error
	Mail(from string, opts *smtp.MailOptions) error
	Rcpt(to string, opts *smtp.RcptOptions) error
	Data(r io.Reader) error
	Reset() error
	Logout() error
}

// WebhookPayload represents the payload sent to webhooks
type WebhookPayload struct {
	From      []*mail.Address   `json:"from"`
	To        []*mail.Address   `json:"to"`
	Subject   string            `json:"subject"`
	Body      string            `json:"body"`
	Headers   map[string]string `json:"headers"`
	RemoteIP  string            `json:"remote_ip"`
	Timestamp time.Time         `json:"timestamp"`
	Auth      *AuthResult       `json:"auth,omitempty"`
}

// AuthResult represents the result of authentication checks
type AuthResult struct {
	SPF   *SPFResult   `json:"spf,omitempty"`
	DKIM  *DKIMResult  `json:"dkim,omitempty"`
	DMARC *DMARCResult `json:"dmarc,omitempty"`
}

// SPFResult represents SPF authentication result (RFC 7208)
type SPFResult struct {
	Result      string `json:"result"`                // pass, fail, softfail, neutral, none, temperror, permerror
	Mechanism   string `json:"mechanism,omitempty"`   // Matched SPF mechanism
	Domain      string `json:"domain,omitempty"`      // Checked domain
	Explanation string `json:"explanation,omitempty"` // SPF explanation string
	Error       string `json:"error,omitempty"`
}

// DKIMSignature represents a single DKIM signature verification result (RFC 6376)
type DKIMSignature struct {
	Domain           string `json:"domain"`                     // d= parameter
	Result           string `json:"result"`                     // pass or fail for this signature
	Error            string `json:"error,omitempty"`            // Error detail if failed
	Algorithm        string `json:"algorithm,omitempty"`        // Signing algorithm
	Canonicalization string `json:"canonicalization,omitempty"` // Canonicalization algorithm
}

// DKIMResult represents DKIM authentication result (RFC 6376)
type DKIMResult struct {
	Result     string          `json:"result"`               // pass, fail, none, temperror, permerror
	Signatures []DKIMSignature `json:"signatures,omitempty"` // All DKIM signatures found
	Body       string          `json:"body,omitempty"`       // Human-readable details
	Error      string          `json:"error,omitempty"`
}

// DMARCResult represents DMARC authentication result (RFC 7489)
type DMARCResult struct {
	Result          string `json:"result"`                     // pass, fail, none, temperror, permerror
	Policy          string `json:"policy,omitempty"`           // p= tag (none, quarantine, reject)
	SubdomainPolicy string `json:"subdomain_policy,omitempty"` // sp= tag
	Percentage      int    `json:"percentage,omitempty"`       // pct= tag
	SPFAlignment    string `json:"spf_alignment,omitempty"`    // pass/fail with mode
	DKIMAlignment   string `json:"dkim_alignment,omitempty"`   // pass/fail with mode
	Error           string `json:"error,omitempty"`
}

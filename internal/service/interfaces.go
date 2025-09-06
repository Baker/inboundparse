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
	PerformAuthenticationChecks(ctx context.Context, message []byte, remoteIP net.IP) (*AuthResult, error)
}

// MessageProcessor defines the interface for message processing
type MessageProcessor interface {
	ProcessMessage(ctx context.Context, r io.Reader) error
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

// SPFResult represents SPF authentication result
type SPFResult struct {
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

// DKIMResult represents DKIM authentication result
type DKIMResult struct {
	Result string `json:"result"`
	Error  string `json:"error,omitempty"`
}

// DMARCResult represents DMARC authentication result
type DMARCResult struct {
	Result string `json:"result"`
	Policy string `json:"policy,omitempty"`
	Error  string `json:"error,omitempty"`
}

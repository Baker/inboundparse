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

// SPFResult represents SPF authentication result per RFC 7208
type SPFResult struct {
	Result       string `json:"result"`                  // pass, fail, softfail, neutral, none, temperror, permerror
	Mechanism    string `json:"mechanism,omitempty"`     // The mechanism that matched
	Explanation  string `json:"explanation,omitempty"`   // Human-readable explanation
	SenderDomain string `json:"sender_domain,omitempty"` // The domain being checked
	HeloDomain   string `json:"helo_domain,omitempty"`   // HELO/EHLO domain
	RawRecord    string `json:"raw_record,omitempty"`    // Raw SPF record
	Error        string `json:"error,omitempty"`         // Error message if any
}

// DKIMSignature represents a single DKIM signature verification result per RFC 6376
type DKIMSignature struct {
	Domain            string   `json:"domain"`                        // d= signing domain
	Selector          string   `json:"selector"`                      // s= selector
	Result            string   `json:"result"`                        // pass, fail, temperror, permerror, none
	Algorithm         string   `json:"algorithm,omitempty"`           // a= signature algorithm
	BodyHashAlgorithm string   `json:"body_hash_algorithm,omitempty"` // Part of a=
	Canonicalization  string   `json:"canonicalization,omitempty"`    // c= canonicalization algorithm
	HeadersSigned     []string `json:"headers_signed,omitempty"`      // h= headers included in signature
	Identity          string   `json:"identity,omitempty"`            // i= agent or user identifier
	Timestamp         int64    `json:"timestamp,omitempty"`           // t= signature timestamp
	Expiration        int64    `json:"expiration,omitempty"`          // x= signature expiration
	BodyLength        int64    `json:"body_length,omitempty"`         // l= body length count
	QueryMethod       string   `json:"query_method,omitempty"`        // q= query method
	Error             string   `json:"error,omitempty"`               // Error message if verification failed
}

// DKIMResult represents DKIM authentication results per RFC 6376
type DKIMResult struct {
	Signatures []*DKIMSignature `json:"signatures,omitempty"` // All DKIM signatures found and verified
	Result     string           `json:"result"`               // Overall result: pass (at least one valid), fail, none
	Error      string           `json:"error,omitempty"`      // Error message if any
}

// DMARCResult represents DMARC authentication result per RFC 7489
type DMARCResult struct {
	Result             string   `json:"result"`                         // pass, fail, temperror, permerror, none
	Policy             string   `json:"policy,omitempty"`               // none, quarantine, reject
	SubdomainPolicy    string   `json:"subdomain_policy,omitempty"`     // sp= subdomain policy
	Percentage         int      `json:"percentage,omitempty"`           // pct= percentage of messages to filter
	AlignmentModeSPF   string   `json:"alignment_mode_spf,omitempty"`   // aspf= relaxed or strict
	AlignmentModeDKIM  string   `json:"alignment_mode_dkim,omitempty"`  // adkim= relaxed or strict
	SPFAligned         bool     `json:"spf_aligned"`                    // Whether SPF alignment passed
	DKIMAligned        bool     `json:"dkim_aligned"`                   // Whether DKIM alignment passed
	ReportURIAggregate []string `json:"report_uri_aggregate,omitempty"` // rua= aggregate report URIs
	ReportURIForensic  []string `json:"report_uri_forensic,omitempty"`  // ruf= forensic report URIs
	RawRecord          string   `json:"raw_record,omitempty"`           // Raw DMARC record
	Domain             string   `json:"domain,omitempty"`               // Domain checked
	Error              string   `json:"error,omitempty"`                // Error message if any
}

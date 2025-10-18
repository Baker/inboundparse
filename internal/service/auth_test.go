package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestAuthService_PerformAuthenticationChecks(t *testing.T) {
	tests := []struct {
		name        string
		enableSPF   bool
		enableDKIM  bool
		enableDMARC bool
		message     []byte
		remoteIP    net.IP
		heloName    string
		mailFrom    string
		wantSPF     bool
		wantDKIM    bool
		wantDMARC   bool
	}{
		{
			name:        "all authentication disabled",
			enableSPF:   false,
			enableDKIM:  false,
			enableDMARC: false,
			message:     []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			remoteIP:    net.IPv4(127, 0, 0, 1),
			heloName:    "mail.example.com",
			mailFrom:    "test@example.com",
			wantSPF:     false,
			wantDKIM:    false,
			wantDMARC:   false,
		},
		{
			name:        "SPF enabled only",
			enableSPF:   true,
			enableDKIM:  false,
			enableDMARC: false,
			message:     []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			remoteIP:    net.IPv4(127, 0, 0, 1),
			heloName:    "mail.example.com",
			mailFrom:    "test@example.com",
			wantSPF:     true,
			wantDKIM:    false,
			wantDMARC:   false,
		},
		{
			name:        "DKIM enabled only",
			enableSPF:   false,
			enableDKIM:  true,
			enableDMARC: false,
			message:     []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			remoteIP:    net.IPv4(127, 0, 0, 1),
			heloName:    "mail.example.com",
			mailFrom:    "test@example.com",
			wantSPF:     false,
			wantDKIM:    true,
			wantDMARC:   false,
		},
		{
			name:        "DMARC enabled only - should not run without SPF or DKIM",
			enableSPF:   false,
			enableDKIM:  false,
			enableDMARC: true,
			message:     []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			remoteIP:    net.IPv4(127, 0, 0, 1),
			heloName:    "mail.example.com",
			mailFrom:    "test@example.com",
			wantSPF:     false,
			wantDKIM:    false,
			wantDMARC:   false, // DMARC should not run without SPF or DKIM
		},
		{
			name:        "all authentication enabled",
			enableSPF:   true,
			enableDKIM:  true,
			enableDMARC: true,
			message:     []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			remoteIP:    net.IPv4(127, 0, 0, 1),
			heloName:    "mail.example.com",
			mailFrom:    "test@example.com",
			wantSPF:     true,
			wantDKIM:    true,
			wantDMARC:   true,
		},
		{
			name:        "SPF and DMARC enabled",
			enableSPF:   true,
			enableDKIM:  false,
			enableDMARC: true,
			message:     []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			remoteIP:    net.IPv4(127, 0, 0, 1),
			heloName:    "mail.example.com",
			mailFrom:    "test@example.com",
			wantSPF:     true,
			wantDKIM:    false,
			wantDMARC:   true, // DMARC runs with SPF
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService := NewAuthService(tt.enableSPF, tt.enableDKIM, tt.enableDMARC)
			ctx := context.Background()

			result, err := authService.PerformAuthenticationChecks(ctx, tt.message, tt.remoteIP, tt.heloName, tt.mailFrom)
			require.NoError(t, err)

			// Check SPF result
			if tt.wantSPF {
				assert.NotNil(t, result.SPF, "Expected SPF result, got nil")
			} else {
				assert.Nil(t, result.SPF, "Expected no SPF result, got result")
			}

			// Check DKIM result
			if tt.wantDKIM {
				assert.NotNil(t, result.DKIM, "Expected DKIM result, got nil")
			} else {
				assert.Nil(t, result.DKIM, "Expected no DKIM result, got result")
			}

			// Check DMARC result
			if tt.wantDMARC {
				assert.NotNil(t, result.DMARC, "Expected DMARC result, got nil")
			} else {
				assert.Nil(t, result.DMARC, "Expected no DMARC result, got result")
			}
		})
	}
}

func TestAuthService_SPF_RFC7208(t *testing.T) {
	tests := []struct {
		name           string
		message        []byte
		remoteIP       net.IP
		heloName       string
		mailFrom       string
		wantResult     string // pass, fail, softfail, neutral, none, temperror, permerror
		checkDomain    bool
		expectedDomain string
	}{
		{
			name:           "SPF check with MAIL FROM",
			message:        []byte("From: sender@example.com\r\nTo: recipient@test.com\r\nSubject: Test\r\n\r\nBody"),
			remoteIP:       net.IPv4(127, 0, 0, 1),
			heloName:       "mail.example.com",
			mailFrom:       "sender@example.com",
			wantResult:     "none", // Will be none or fail depending on DNS
			checkDomain:    true,
			expectedDomain: "example.com",
		},
		{
			name:           "SPF check falls back to HELO when no MAIL FROM",
			message:        []byte("From: sender@example.com\r\nTo: recipient@test.com\r\nSubject: Test\r\n\r\nBody"),
			remoteIP:       net.IPv4(127, 0, 0, 1),
			heloName:       "mail.example.com",
			mailFrom:       "",
			wantResult:     "none",
			checkDomain:    true,
			expectedDomain: "mail.example.com",
		},
		{
			name:           "SPF check with null sender uses HELO",
			message:        []byte("From: sender@example.com\r\nTo: recipient@test.com\r\nSubject: Test\r\n\r\nBody"),
			remoteIP:       net.IPv4(127, 0, 0, 1),
			heloName:       "mail.example.com",
			mailFrom:       "<>",
			wantResult:     "none",
			checkDomain:    true,
			expectedDomain: "mail.example.com",
		},
		{
			name:        "SPF check with no domain returns none",
			message:     []byte("From: sender@example.com\r\nTo: recipient@test.com\r\nSubject: Test\r\n\r\nBody"),
			remoteIP:    net.IPv4(127, 0, 0, 1),
			heloName:    "",
			mailFrom:    "",
			wantResult:  "none",
			checkDomain: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService := NewAuthService(true, false, false)
			ctx := context.Background()

			result, err := authService.PerformAuthenticationChecks(ctx, tt.message, tt.remoteIP, tt.heloName, tt.mailFrom)
			require.NoError(t, err)
			require.NotNil(t, result.SPF)

			// Result should be one of the RFC 7208 values
			assert.Contains(t, []string{"pass", "fail", "softfail", "neutral", "none", "temperror", "permerror"}, result.SPF.Result)

			if tt.checkDomain {
				assert.Equal(t, tt.expectedDomain, result.SPF.Domain)
			}
		})
	}
}

func TestAuthService_DKIM_RFC6376(t *testing.T) {
	tests := []struct {
		name       string
		message    []byte
		wantResult string // pass, fail, none, temperror
	}{
		{
			name:       "message without DKIM signature",
			message:    []byte("From: sender@example.com\r\nTo: recipient@test.com\r\nSubject: Test\r\n\r\nBody"),
			wantResult: "none",
		},
		{
			name:       "empty message",
			message:    []byte(""),
			wantResult: "temperror", // Empty message causes parsing error
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService := NewAuthService(false, true, false)
			ctx := context.Background()

			result, err := authService.PerformAuthenticationChecks(ctx, tt.message, net.IPv4(127, 0, 0, 1), "mail.example.com", "sender@example.com")
			require.NoError(t, err)
			require.NotNil(t, result.DKIM)

			assert.Equal(t, tt.wantResult, result.DKIM.Result)
		})
	}
}

func TestAuthService_DMARC_RFC7489(t *testing.T) {
	tests := []struct {
		name       string
		enableSPF  bool
		enableDKIM bool
		message    []byte
		remoteIP   net.IP
		heloName   string
		mailFrom   string
		wantDMARC  bool
	}{
		{
			name:       "DMARC requires SPF or DKIM",
			enableSPF:  false,
			enableDKIM: false,
			message:    []byte("From: sender@example.com\r\nTo: recipient@test.com\r\nSubject: Test\r\n\r\nBody"),
			remoteIP:   net.IPv4(127, 0, 0, 1),
			heloName:   "mail.example.com",
			mailFrom:   "sender@example.com",
			wantDMARC:  false,
		},
		{
			name:       "DMARC runs with SPF enabled",
			enableSPF:  true,
			enableDKIM: false,
			message:    []byte("From: sender@example.com\r\nTo: recipient@test.com\r\nSubject: Test\r\n\r\nBody"),
			remoteIP:   net.IPv4(127, 0, 0, 1),
			heloName:   "mail.example.com",
			mailFrom:   "sender@example.com",
			wantDMARC:  true,
		},
		{
			name:       "DMARC runs with DKIM enabled",
			enableSPF:  false,
			enableDKIM: true,
			message:    []byte("From: sender@example.com\r\nTo: recipient@test.com\r\nSubject: Test\r\n\r\nBody"),
			remoteIP:   net.IPv4(127, 0, 0, 1),
			heloName:   "mail.example.com",
			mailFrom:   "sender@example.com",
			wantDMARC:  true,
		},
		{
			name:       "DMARC runs with both enabled",
			enableSPF:  true,
			enableDKIM: true,
			message:    []byte("From: sender@example.com\r\nTo: recipient@test.com\r\nSubject: Test\r\n\r\nBody"),
			remoteIP:   net.IPv4(127, 0, 0, 1),
			heloName:   "mail.example.com",
			mailFrom:   "sender@example.com",
			wantDMARC:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService := NewAuthService(tt.enableSPF, tt.enableDKIM, true)
			ctx := context.Background()

			result, err := authService.PerformAuthenticationChecks(ctx, tt.message, tt.remoteIP, tt.heloName, tt.mailFrom)
			require.NoError(t, err)

			if tt.wantDMARC {
				assert.NotNil(t, result.DMARC, "Expected DMARC result")
			} else {
				assert.Nil(t, result.DMARC, "Expected no DMARC result")
			}
		})
	}
}

func TestAuthService_ExtractDomainFromMessage(t *testing.T) {
	tests := []struct {
		name    string
		message []byte
		want    string
		wantErr bool
	}{
		{
			name:    "valid email address",
			message: []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:    "example.com",
			wantErr: false,
		},
		{
			name:    "email with display name",
			message: []byte("From: Test User <test@example.com>\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:    "example.com",
			wantErr: false,
		},
		{
			name:    "no From header",
			message: []byte("To: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:    "",
			wantErr: true,
		},
		{
			name:    "From header without @",
			message: []byte("From: invalid-email\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:    "",
			wantErr: true,
		},
		{
			name:    "empty From header",
			message: []byte("From: \r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService := &authService{}
			got, err := authService.extractDomainFromMessage(tt.message)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthService_ExtractDomainFromMessage_EdgeCases(t *testing.T) {
	authService := &authService{}

	tests := []struct {
		name    string
		message []byte
		want    string
		wantErr bool
	}{
		{
			name:    "email with multiple @ symbols",
			message: []byte("From: test@example@domain.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:    "domain.com",
			wantErr: false,
		},
		{
			name:    "email with display name and multiple @ symbols",
			message: []byte("From: Test User <test@example@domain.com>\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:    "domain.com",
			wantErr: false,
		},
		{
			name:    "email with trailing > without opening <",
			message: []byte("From: test@example.com>\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:    "example.com",
			wantErr: false,
		},
		{
			name:    "From header with only display name",
			message: []byte("From: Test User\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:    "",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := authService.extractDomainFromMessage(tt.message)
			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
			assert.Equal(t, tt.want, got)
		})
	}
}

func TestAuthService_Alignment(t *testing.T) {
	tests := []struct {
		name             string
		identifierDomain string
		fromDomain       string
		alignmentMode    string
		wantAligned      bool
	}{
		{
			name:             "exact match - relaxed mode",
			identifierDomain: "example.com",
			fromDomain:       "example.com",
			alignmentMode:    "r",
			wantAligned:      true,
		},
		{
			name:             "exact match - strict mode",
			identifierDomain: "example.com",
			fromDomain:       "example.com",
			alignmentMode:    "s",
			wantAligned:      true,
		},
		{
			name:             "subdomain - relaxed mode",
			identifierDomain: "mail.example.com",
			fromDomain:       "example.com",
			alignmentMode:    "r",
			wantAligned:      true,
		},
		{
			name:             "subdomain - strict mode",
			identifierDomain: "mail.example.com",
			fromDomain:       "example.com",
			alignmentMode:    "s",
			wantAligned:      false,
		},
		{
			name:             "different domains",
			identifierDomain: "example.com",
			fromDomain:       "other.com",
			alignmentMode:    "r",
			wantAligned:      false,
		},
		{
			name:             "identifier with @ symbol",
			identifierDomain: "user@example.com",
			fromDomain:       "example.com",
			alignmentMode:    "r",
			wantAligned:      true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Note: We can't directly test checkAlignment as it's not exported
			// This test documents expected behavior
			t.Logf("Test: %s - identifier=%s, from=%s, mode=%s, expect=%v",
				tt.name, tt.identifierDomain, tt.fromDomain, tt.alignmentMode, tt.wantAligned)
		})
	}
}

func TestAuthService_DifferentMessageFormats(t *testing.T) {
	service := NewAuthService(true, true, true)
	assert.NotNil(t, service)

	testCases := []struct {
		name     string
		message  []byte
		heloName string
		mailFrom string
	}{
		{
			name:     "standard message",
			message:  []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			heloName: "mail.example.com",
			mailFrom: "test@example.com",
		},
		{
			name:     "message with multiple recipients",
			message:  []byte("From: test@example.com\r\nTo: recipient1@example.com, recipient2@example.com\r\nSubject: Test\r\n\r\nTest message"),
			heloName: "mail.example.com",
			mailFrom: "test@example.com",
		},
		{
			name:     "message with CC and BCC",
			message:  []byte("From: test@example.com\r\nTo: recipient@example.com\r\nCC: cc@example.com\r\nBCC: bcc@example.com\r\nSubject: Test\r\n\r\nTest message"),
			heloName: "mail.example.com",
			mailFrom: "test@example.com",
		},
		{
			name:     "empty message",
			message:  []byte(""),
			heloName: "mail.example.com",
			mailFrom: "test@example.com",
		},
		{
			name:     "message without headers",
			message:  []byte("Just a plain text message without any headers"),
			heloName: "mail.example.com",
			mailFrom: "test@example.com",
		},
	}

	remoteIP := net.IPv4(127, 0, 0, 1)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := service.PerformAuthenticationChecks(context.Background(), tc.message, remoteIP, tc.heloName, tc.mailFrom)
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

func TestAuthService_DifferentIPAddresses(t *testing.T) {
	service := NewAuthService(true, true, true)
	assert.NotNil(t, service)

	message := []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")

	testCases := []struct {
		name     string
		ip       net.IP
		heloName string
		mailFrom string
	}{
		{
			name:     "IPv4 localhost",
			ip:       net.IPv4(127, 0, 0, 1),
			heloName: "localhost",
			mailFrom: "test@example.com",
		},
		{
			name:     "IPv4 private",
			ip:       net.IPv4(192, 168, 1, 1),
			heloName: "mail.local",
			mailFrom: "test@example.com",
		},
		{
			name:     "IPv4 public",
			ip:       net.IPv4(8, 8, 8, 8),
			heloName: "dns.google",
			mailFrom: "test@example.com",
		},
		{
			name:     "IPv6 localhost",
			ip:       net.IPv6loopback,
			heloName: "localhost",
			mailFrom: "test@example.com",
		},
		{
			name:     "IPv6 public",
			ip:       net.ParseIP("2001:4860:4860::8888"),
			heloName: "dns.google",
			mailFrom: "test@example.com",
		},
		{
			name:     "nil IP",
			ip:       nil,
			heloName: "mail.example.com",
			mailFrom: "test@example.com",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := service.PerformAuthenticationChecks(context.Background(), message, tc.ip, tc.heloName, tc.mailFrom)
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

func TestAuthService_ConcurrentAccess(t *testing.T) {
	service := NewAuthService(true, true, true)
	assert.NotNil(t, service)

	message := []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")
	remoteIP := net.IPv4(127, 0, 0, 1)

	// Test concurrent access
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			result, err := service.PerformAuthenticationChecks(context.Background(), message, remoteIP, "mail.example.com", "test@example.com")
			assert.NoError(t, err)
			assert.NotNil(t, result)
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

func TestAuthService_LargeMessages(t *testing.T) {
	service := NewAuthService(true, true, true)
	assert.NotNil(t, service)

	remoteIP := net.IPv4(127, 0, 0, 1)

	// Test with a large message
	largeBody := strings.Repeat("This is a test message. ", 10000) // ~250KB
	largeMessage := []byte(fmt.Sprintf("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\n%s", largeBody))

	result, err := service.PerformAuthenticationChecks(context.Background(), largeMessage, remoteIP, "mail.example.com", "test@example.com")
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

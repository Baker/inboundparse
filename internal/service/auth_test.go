package service

import (
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

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
			wantSPF:     false,
			wantDKIM:    true,
			wantDMARC:   false,
		},
		{
			name:        "DMARC enabled only",
			enableSPF:   false,
			enableDKIM:  false,
			enableDMARC: true,
			message:     []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			remoteIP:    net.IPv4(127, 0, 0, 1),
			wantSPF:     false,
			wantDKIM:    false,
			wantDMARC:   true,
		},
		{
			name:        "all authentication enabled",
			enableSPF:   true,
			enableDKIM:  true,
			enableDMARC: true,
			message:     []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			remoteIP:    net.IPv4(127, 0, 0, 1),
			wantSPF:     true,
			wantDKIM:    true,
			wantDMARC:   true,
		},
		{
			name:        "message without From header",
			enableSPF:   true,
			enableDKIM:  true,
			enableDMARC: true,
			message:     []byte("To: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			remoteIP:    net.IPv4(127, 0, 0, 1),
			wantSPF:     true,
			wantDKIM:    true,
			wantDMARC:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			authService := NewAuthService(tt.enableSPF, tt.enableDKIM, tt.enableDMARC)
			ctx := context.Background()

			result, err := authService.PerformAuthenticationChecks(ctx, tt.message, tt.remoteIP)
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

func TestAuthService_ExtractDomainFromMessage(t *testing.T) {
	tests := []struct {
		name     string
		message  []byte
		want     string
		wantErr  bool
	}{
		{
			name:     "valid email address",
			message:  []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "example.com",
			wantErr:  false,
		},
		{
			name:     "email with display name",
			message:  []byte("From: Test User <test@example.com>\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "example.com",
			wantErr:  false,
		},
		{
			name:     "no From header",
			message:  []byte("To: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "",
			wantErr:  true,
		},
		{
			name:     "From header without @",
			message:  []byte("From: invalid-email\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "",
			wantErr:  true,
		},
		{
			name:     "empty From header",
			message:  []byte("From: \r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "",
			wantErr:  true,
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

func TestAuthService_CheckSPF_ErrorCases(t *testing.T) {
	authService := &authService{enableSPF: true}

	tests := []struct {
		name     string
		message  []byte
		remoteIP net.IP
		wantErr  bool
	}{
		{
			name:     "message without From header",
			message:  []byte("To: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			remoteIP: net.IPv4(127, 0, 0, 1),
			wantErr:  true,
		},
		{
			name:     "message with invalid From header",
			message:  []byte("From: invalid-email\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			remoteIP: net.IPv4(127, 0, 0, 1),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := authService.checkSPF(tt.message, tt.remoteIP)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, "none", result)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_CheckDMARC_ErrorCases(t *testing.T) {
	authService := &authService{enableDMARC: true}

	tests := []struct {
		name     string
		message  []byte
		wantErr  bool
	}{
		{
			name:     "message without From header",
			message:  []byte("To: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			wantErr:  true,
		},
		{
			name:     "message with invalid From header",
			message:  []byte("From: invalid-email\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, policy, err := authService.checkDMARC(tt.message)
			if tt.wantErr {
				assert.Error(t, err)
				assert.Equal(t, "none", result)
				assert.Empty(t, policy)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestAuthService_ExtractDomainFromMessage_EdgeCases(t *testing.T) {
	authService := &authService{}

	tests := []struct {
		name     string
		message  []byte
		want     string
		wantErr  bool
	}{
		{
			name:     "email with multiple @ symbols",
			message:  []byte("From: test@example@domain.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "domain.com",
			wantErr:  false,
		},
		{
			name:     "email with display name and multiple @ symbols",
			message:  []byte("From: Test User <test@example@domain.com>\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "domain.com",
			wantErr:  false,
		},
		{
			name:     "email with trailing > without opening <",
			message:  []byte("From: test@example.com>\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "example.com",
			wantErr:  false,
		},
		{
			name:     "email with opening < without closing >",
			message:  []byte("From: <test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "example.com",
			wantErr:  false,
		},
		{
			name:     "From header with only display name",
			message:  []byte("From: Test User\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "",
			wantErr:  true,
		},
		{
			name:     "From header with malformed email",
			message:  []byte("From: @example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "example.com",
			wantErr:  false,
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

func TestAuthService_PerformAuthenticationChecks_WithRealSPF(t *testing.T) {
	// Test with SPF enabled and a real domain
	authService := NewAuthService(true, false, false)
	ctx := context.Background()

	message := []byte("From: test@google.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")
	remoteIP := net.IPv4(8, 8, 8, 8) // Google's DNS server

	result, err := authService.PerformAuthenticationChecks(ctx, message, remoteIP)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.SPF)
	assert.Nil(t, result.DKIM)
	assert.Nil(t, result.DMARC)
}

func TestAuthService_PerformAuthenticationChecks_WithRealDKIM(t *testing.T) {
	// Test with DKIM enabled
	authService := NewAuthService(false, true, false)
	ctx := context.Background()

	message := []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")
	remoteIP := net.IPv4(127, 0, 0, 1)

	result, err := authService.PerformAuthenticationChecks(ctx, message, remoteIP)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Nil(t, result.SPF)
	assert.NotNil(t, result.DKIM)
	assert.Nil(t, result.DMARC)
}

func TestAuthService_PerformAuthenticationChecks_WithRealDMARC(t *testing.T) {
	// Test with DMARC enabled
	authService := NewAuthService(false, false, true)
	ctx := context.Background()

	message := []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")
	remoteIP := net.IPv4(127, 0, 0, 1)

	result, err := authService.PerformAuthenticationChecks(ctx, message, remoteIP)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.Nil(t, result.SPF)
	assert.Nil(t, result.DKIM)
	assert.NotNil(t, result.DMARC)
}

// Test auth service error handling paths
func TestAuthService_ErrorHandling(t *testing.T) {
	service := NewAuthService(true, true, true)
	assert.NotNil(t, service)

	// Test with invalid message format
	invalidMessage := []byte("Invalid email message without proper headers")
	remoteIP := net.IPv4(127, 0, 0, 1)

	result, err := service.PerformAuthenticationChecks(context.Background(), invalidMessage, remoteIP)
	assert.NoError(t, err) // The service should handle invalid messages gracefully
	assert.NotNil(t, result)
}

// Test auth service with different message formats
func TestAuthService_DifferentMessageFormats(t *testing.T) {
	service := NewAuthService(true, true, true)
	assert.NotNil(t, service)

	testCases := []struct {
		name    string
		message []byte
	}{
		{
			name:    "standard message",
			message: []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "message with multiple recipients",
			message: []byte("From: test@example.com\r\nTo: recipient1@example.com, recipient2@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "message with CC and BCC",
			message: []byte("From: test@example.com\r\nTo: recipient@example.com\r\nCC: cc@example.com\r\nBCC: bcc@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "message with custom headers",
			message: []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\nX-Custom-Header: value\r\n\r\nTest message"),
		},
		{
			name:    "message with unicode",
			message: []byte("From: 测试@example.com\r\nTo: recipient@example.com\r\nSubject: 测试\r\n\r\n测试消息"),
		},
		{
			name:    "empty message",
			message: []byte(""),
		},
		{
			name:    "message without headers",
			message: []byte("Just a plain text message without any headers"),
		},
	}

	remoteIP := net.IPv4(127, 0, 0, 1)

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := service.PerformAuthenticationChecks(context.Background(), tc.message, remoteIP)
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

// Test auth service with different IP addresses
func TestAuthService_DifferentIPAddresses(t *testing.T) {
	service := NewAuthService(true, true, true)
	assert.NotNil(t, service)

	message := []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")

	testCases := []struct {
		name string
		ip   net.IP
	}{
		{
			name: "IPv4 localhost",
			ip:   net.IPv4(127, 0, 0, 1),
		},
		{
			name: "IPv4 private",
			ip:   net.IPv4(192, 168, 1, 1),
		},
		{
			name: "IPv4 public",
			ip:   net.IPv4(8, 8, 8, 8),
		},
		{
			name: "IPv6 localhost",
			ip:   net.IPv6loopback,
		},
		{
			name: "IPv6 public",
			ip:   net.ParseIP("2001:4860:4860::8888"),
		},
		{
			name: "nil IP",
			ip:   nil,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := service.PerformAuthenticationChecks(context.Background(), message, tc.ip)
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

// Test auth service with different domain formats
func TestAuthService_DifferentDomainFormats(t *testing.T) {
	service := NewAuthService(true, true, true)
	assert.NotNil(t, service)

	remoteIP := net.IPv4(127, 0, 0, 1)

	testCases := []struct {
		name    string
		message []byte
	}{
		{
			name:    "simple domain",
			message: []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "subdomain",
			message: []byte("From: test@mail.example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "international domain",
			message: []byte("From: test@测试.example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "long domain",
			message: []byte("From: test@very-long-domain-name-that-might-cause-issues.example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "domain with port",
			message: []byte("From: test@example.com:25\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "domain with path",
			message: []byte("From: test@example.com/path\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := service.PerformAuthenticationChecks(context.Background(), tc.message, remoteIP)
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

// Test auth service with malformed email addresses
func TestAuthService_MalformedEmailAddresses(t *testing.T) {
	service := NewAuthService(true, true, true)
	assert.NotNil(t, service)

	remoteIP := net.IPv4(127, 0, 0, 1)

	testCases := []struct {
		name    string
		message []byte
	}{
		{
			name:    "missing @ symbol",
			message: []byte("From: testexample.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "multiple @ symbols",
			message: []byte("From: test@@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "empty local part",
			message: []byte("From: @example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "empty domain part",
			message: []byte("From: test@\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "invalid characters",
			message: []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "quoted local part",
			message: []byte("From: \"test user\"@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
		{
			name:    "display name format",
			message: []byte("From: Test User <test@example.com>\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			result, err := service.PerformAuthenticationChecks(context.Background(), tc.message, remoteIP)
			assert.NoError(t, err)
			assert.NotNil(t, result)
		})
	}
}

// Test auth service with different authentication combinations
func TestAuthService_AuthenticationCombinations(t *testing.T) {
	combinations := []struct {
		name        string
		enableSPF   bool
		enableDKIM  bool
		enableDMARC bool
	}{
		{"all disabled", false, false, false},
		{"SPF only", true, false, false},
		{"DKIM only", false, true, false},
		{"DMARC only", false, false, true},
		{"SPF and DKIM", true, true, false},
		{"SPF and DMARC", true, false, true},
		{"DKIM and DMARC", false, true, true},
		{"all enabled", true, true, true},
	}

	message := []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")
	remoteIP := net.IPv4(127, 0, 0, 1)

	for _, combo := range combinations {
		t.Run(combo.name, func(t *testing.T) {
			service := NewAuthService(combo.enableSPF, combo.enableDKIM, combo.enableDMARC)
			assert.NotNil(t, service)

			result, err := service.PerformAuthenticationChecks(context.Background(), message, remoteIP)
			assert.NoError(t, err)
			assert.NotNil(t, result)

			// Check that only enabled authentication methods have results
			if combo.enableSPF {
				assert.NotNil(t, result.SPF)
			} else {
				assert.Nil(t, result.SPF)
			}

			if combo.enableDKIM {
				assert.NotNil(t, result.DKIM)
			} else {
				assert.Nil(t, result.DKIM)
			}

			if combo.enableDMARC {
				assert.NotNil(t, result.DMARC)
			} else {
				assert.Nil(t, result.DMARC)
			}
		})
	}
}

// Test auth service with large messages
func TestAuthService_LargeMessages(t *testing.T) {
	service := NewAuthService(true, true, true)
	assert.NotNil(t, service)

	remoteIP := net.IPv4(127, 0, 0, 1)

	// Test with a large message
	largeBody := strings.Repeat("This is a test message. ", 10000) // ~250KB
	largeMessage := []byte(fmt.Sprintf("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\n%s", largeBody))

	result, err := service.PerformAuthenticationChecks(context.Background(), largeMessage, remoteIP)
	assert.NoError(t, err)
	assert.NotNil(t, result)
}

// Test auth service with concurrent access
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

			result, err := service.PerformAuthenticationChecks(context.Background(), message, remoteIP)
			assert.NoError(t, err)
			assert.NotNil(t, result)
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Test auth service with context cancellation
func TestAuthService_ContextCancellation(t *testing.T) {
	service := NewAuthService(true, true, true)
	assert.NotNil(t, service)

	message := []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")
	remoteIP := net.IPv4(127, 0, 0, 1)

	// Test with cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // Cancel immediately

	result, err := service.PerformAuthenticationChecks(ctx, message, remoteIP)
	assert.NoError(t, err) // The service should handle cancelled context gracefully
	assert.NotNil(t, result)
}

// Test auth service with timeout context
func TestAuthService_TimeoutContext(t *testing.T) {
	service := NewAuthService(true, true, true)
	assert.NotNil(t, service)

	message := []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")
	remoteIP := net.IPv4(127, 0, 0, 1)

	// Test with timeout context
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Wait for timeout
	time.Sleep(2 * time.Millisecond)

	result, err := service.PerformAuthenticationChecks(ctx, message, remoteIP)
	assert.NoError(t, err) // The service should handle timeout context gracefully
	assert.NotNil(t, result)
}

func TestAuthService_PerformAuthenticationChecks_WithAllEnabled(t *testing.T) {
	// Test with all authentication methods enabled
	authService := NewAuthService(true, true, true)
	ctx := context.Background()

	message := []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")
	remoteIP := net.IPv4(127, 0, 0, 1)

	result, err := authService.PerformAuthenticationChecks(ctx, message, remoteIP)
	assert.NoError(t, err)
	assert.NotNil(t, result)
	assert.NotNil(t, result.SPF)
	assert.NotNil(t, result.DKIM)
	assert.NotNil(t, result.DMARC)
}

func TestAuthService_CheckSPF_WithValidDomain(t *testing.T) {
	authService := &authService{enableSPF: true}
	
	message := []byte("From: test@google.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")
	remoteIP := net.IPv4(8, 8, 8, 8) // Google's DNS server

	result, err := authService.checkSPF(message, remoteIP)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestAuthService_CheckDKIM_WithValidMessage(t *testing.T) {
	authService := &authService{enableDKIM: true}
	
	message := []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")

	result, err := authService.checkDKIM(message)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
}

func TestAuthService_CheckDMARC_WithValidMessage(t *testing.T) {
	authService := &authService{enableDMARC: true}
	
	message := []byte("From: test@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message")

	result, policy, err := authService.checkDMARC(message)
	assert.NoError(t, err)
	assert.NotEmpty(t, result)
	assert.NotEmpty(t, policy)
}

func TestAuthService_ExtractDomainFromMessage_WithComplexEmail(t *testing.T) {
	authService := &authService{}

	tests := []struct {
		name     string
		message  []byte
		want     string
		wantErr  bool
	}{
		{
			name:     "email with display name and angle brackets",
			message:  []byte("From: \"John Doe\" <john.doe@example.com>\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "example.com",
			wantErr:  false,
		},
		{
			name:     "email with multiple recipients",
			message:  []byte("From: sender@example.com\r\nTo: user1@example.com, user2@test.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "example.com",
			wantErr:  false,
		},
		{
			name:     "email with reply-to header",
			message:  []byte("From: sender@example.com\r\nReply-To: reply@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "example.com",
			wantErr:  false,
		},
		{
			name:     "email with return-path header",
			message:  []byte("Return-Path: <bounce@example.com>\r\nFrom: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"),
			want:     "example.com",
			wantErr:  false,
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
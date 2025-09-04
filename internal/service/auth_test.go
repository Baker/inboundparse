package service

import (
	"context"
	"net"
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
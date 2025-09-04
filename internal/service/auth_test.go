package service

import (
	"context"
	"net"
	"testing"
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
			if err != nil {
				t.Errorf("PerformAuthenticationChecks() error = %v", err)
				return
			}

			// Check SPF result
			if tt.wantSPF {
				if result.SPF == nil {
					t.Error("Expected SPF result, got nil")
				}
			} else {
				if result.SPF != nil {
					t.Error("Expected no SPF result, got result")
				}
			}

			// Check DKIM result
			if tt.wantDKIM {
				if result.DKIM == nil {
					t.Error("Expected DKIM result, got nil")
				}
			} else {
				if result.DKIM != nil {
					t.Error("Expected no DKIM result, got result")
				}
			}

			// Check DMARC result
			if tt.wantDMARC {
				if result.DMARC == nil {
					t.Error("Expected DMARC result, got nil")
				}
			} else {
				if result.DMARC != nil {
					t.Error("Expected no DMARC result, got result")
				}
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
			if (err != nil) != tt.wantErr {
				t.Errorf("extractDomainFromMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractDomainFromMessage() = %v, want %v", got, tt.want)
			}
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
			if (err != nil) != tt.wantErr {
				t.Errorf("checkSPF() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && result != "none" {
				t.Errorf("checkSPF() result = %v, want none", result)
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
			if (err != nil) != tt.wantErr {
				t.Errorf("checkDMARC() error = %v, wantErr %v", err, tt.wantErr)
			}
			if tt.wantErr && result != "none" {
				t.Errorf("checkDMARC() result = %v, want none", result)
			}
			if tt.wantErr && policy != "" {
				t.Errorf("checkDMARC() policy = %v, want empty", policy)
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
			if (err != nil) != tt.wantErr {
				t.Errorf("extractDomainFromMessage() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("extractDomainFromMessage() = %v, want %v", got, tt.want)
			}
		})
	}
}
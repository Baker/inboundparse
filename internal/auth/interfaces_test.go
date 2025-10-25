package auth

import (
	"context"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"net"
	"testing"

	"github.com/mnako/letters"
)

// Mock implementations for testing
type mockSPFChecker struct {
	result *domain.SPFResult
	err    error
}

func (m *mockSPFChecker) CheckSPF(ctx context.Context, remoteIP net.IP, domainName, from string, logger observability.Logger) (*domain.SPFResult, error) {
	return m.result, m.err
}

type mockDKIMChecker struct {
	result *domain.DKIMResult
	err    error
}

func (m *mockDKIMChecker) CheckDKIM(ctx context.Context, rawMessage string, logger observability.Logger) (*domain.DKIMResult, error) {
	return m.result, m.err
}

type mockDMARCChecker struct {
	result *domain.DMARCResult
	err    error
}

func (m *mockDMARCChecker) CheckDMARC(ctx context.Context, rawMessage string, headers letters.Headers, spfResult *domain.SPFResult, dkimResult *domain.DKIMResult, logger observability.Logger) (*domain.DMARCResult, error) {
	return m.result, m.err
}

func TestAuthChecker_CheckSPF_Enabled(t *testing.T) {
	config := AuthConfig{
		EnableSPF: true,
	}

	authChecker := NewAuthChecker(config)

	ctx := context.Background()
	remoteIP := net.ParseIP("192.168.1.1")

	// Test with a domain that should have SPF records
	result, err := authChecker.CheckSPF(ctx, remoteIP, "google.com", "test@google.com", &MockLogger{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	// SPF result can be pass, fail, temperror, etc. - we just want to ensure it's not nil
	if result.Result == "" {
		t.Error("Expected non-empty result")
	}
}

func TestAuthChecker_CheckSPF_Disabled(t *testing.T) {
	config := AuthConfig{
		EnableSPF: false,
	}

	authChecker := NewAuthChecker(config)

	ctx := context.Background()
	remoteIP := net.ParseIP("192.168.1.1")

	result, err := authChecker.CheckSPF(ctx, remoteIP, "example.com", "test@example.com", &MockLogger{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result != nil {
		t.Error("Expected nil result when SPF is disabled")
	}
}

func TestAuthChecker_CheckDKIM_Enabled(t *testing.T) {
	config := AuthConfig{
		EnableDKIM: true,
	}

	authChecker := NewAuthChecker(config)

	ctx := context.Background()

	result, err := authChecker.CheckDKIM(ctx, "test message", &MockLogger{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	// DKIM validation might fail without proper signatures, but we want to ensure it doesn't crash
	// The result should be a valid DKIMResult struct even if Valid is false
}

func TestAuthChecker_CheckDKIM_Disabled(t *testing.T) {
	config := AuthConfig{
		EnableDKIM: false,
	}

	authChecker := NewAuthChecker(config)

	ctx := context.Background()

	result, err := authChecker.CheckDKIM(ctx, "test message", &MockLogger{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result != nil {
		t.Error("Expected nil result when DKIM is disabled")
	}
}

func TestAuthChecker_CheckDMARC_Enabled(t *testing.T) {
	config := AuthConfig{
		EnableDMARC: true,
	}

	authChecker := NewAuthChecker(config)

	ctx := context.Background()
	headers := letters.Headers{}
	spfResult := &domain.SPFResult{Result: "pass"}
	dkimResult := &domain.DKIMResult{Valid: true}

	result, err := authChecker.CheckDMARC(ctx, "test message", headers, spfResult, dkimResult, &MockLogger{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	// DMARC result can be pass, fail, none, etc. - we just want to ensure it's not nil
	if result.Result == "" {
		t.Error("Expected non-empty result")
	}
}

func TestAuthChecker_CheckDMARC_Disabled(t *testing.T) {
	config := AuthConfig{
		EnableDMARC: false,
	}

	authChecker := NewAuthChecker(config)

	ctx := context.Background()
	headers := letters.Headers{}
	spfResult := &domain.SPFResult{Result: "pass"}
	dkimResult := &domain.DKIMResult{Valid: true}

	result, err := authChecker.CheckDMARC(ctx, "test message", headers, spfResult, dkimResult, &MockLogger{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result != nil {
		t.Error("Expected nil result when DMARC is disabled")
	}
}

func TestExtractDomainFromEmail_ValidEmails(t *testing.T) {
	testCases := []struct {
		input    string
		expected string
	}{
		{"user@example.com", "example.com"},
		{"<user@example.com>", "example.com"},
		{"John Doe <user@example.com>", "example.com"},
		{"user+tag@sub.example.com", "sub.example.com"},
		{"test@localhost", "localhost"},
	}

	for _, tc := range testCases {
		t.Run(tc.input, func(t *testing.T) {
			result := ExtractDomainFromEmail(tc.input)
			if result != tc.expected {
				t.Errorf("Expected '%s', got '%s'", tc.expected, result)
			}
		})
	}
}

func TestExtractDomainFromEmail_InvalidEmails(t *testing.T) {
	testCases := []string{
		"",
		"no-at-symbol",
		"missing-domain@",
		"invalid@",
		"@",
	}

	for _, input := range testCases {
		t.Run(input, func(t *testing.T) {
			result := ExtractDomainFromEmail(input)
			if result != "" {
				t.Errorf("Expected empty string for invalid email '%s', got '%s'", input, result)
			}
		})
	}
}

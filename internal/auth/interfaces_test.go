package auth

import (
	"context"
	"inboundparse/internal/domain"
	"net"
	"testing"

	"github.com/mnako/letters"
)

// Mock implementations for testing
type mockSPFChecker struct {
	result *domain.SPFResult
	err    error
}

func (m *mockSPFChecker) CheckSPF(ctx context.Context, remoteIP net.IP, domainName, from string) (*domain.SPFResult, error) {
	return m.result, m.err
}

type mockDKIMChecker struct {
	result *domain.DKIMResult
	err    error
}

func (m *mockDKIMChecker) CheckDKIM(ctx context.Context, rawMessage string) (*domain.DKIMResult, error) {
	return m.result, m.err
}

type mockDMARCChecker struct {
	result *domain.DMARCResult
	err    error
}

func (m *mockDMARCChecker) CheckDMARC(ctx context.Context, rawMessage string, headers letters.Headers, spfResult *domain.SPFResult, dkimResult *domain.DKIMResult) (*domain.DMARCResult, error) {
	return m.result, m.err
}

func TestAuthChecker_CheckSPF_Enabled(t *testing.T) {
	t.Skip("Skipping integration test that requires DNS resolution")
	config := AuthConfig{
		EnableSPF: true,
	}

	authChecker := NewAuthChecker(config)

	ctx := context.Background()
	remoteIP := net.ParseIP("192.168.1.1")

	result, err := authChecker.CheckSPF(ctx, remoteIP, "example.com", "test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.Result != "pass" {
		t.Errorf("Expected result 'pass', got '%s'", result.Result)
	}
}

func TestAuthChecker_CheckSPF_Disabled(t *testing.T) {
	config := AuthConfig{
		EnableSPF: false,
	}

	authChecker := NewAuthChecker(config)

	ctx := context.Background()
	remoteIP := net.ParseIP("192.168.1.1")

	result, err := authChecker.CheckSPF(ctx, remoteIP, "example.com", "test@example.com")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result != nil {
		t.Error("Expected nil result when SPF is disabled")
	}
}

func TestAuthChecker_CheckDKIM_Enabled(t *testing.T) {
	t.Skip("Skipping integration test that requires DNS resolution")
	config := AuthConfig{
		EnableDKIM: true,
	}

	authChecker := NewAuthChecker(config)

	ctx := context.Background()

	result, err := authChecker.CheckDKIM(ctx, "test message")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if !result.Valid {
		t.Error("Expected valid DKIM result")
	}
}

func TestAuthChecker_CheckDKIM_Disabled(t *testing.T) {
	config := AuthConfig{
		EnableDKIM: false,
	}

	authChecker := NewAuthChecker(config)

	ctx := context.Background()

	result, err := authChecker.CheckDKIM(ctx, "test message")
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result != nil {
		t.Error("Expected nil result when DKIM is disabled")
	}
}

func TestAuthChecker_CheckDMARC_Enabled(t *testing.T) {
	t.Skip("Skipping integration test that requires DNS resolution")
	config := AuthConfig{
		EnableDMARC: true,
	}

	authChecker := NewAuthChecker(config)

	ctx := context.Background()
	headers := letters.Headers{}
	spfResult := &domain.SPFResult{Result: "pass"}
	dkimResult := &domain.DKIMResult{Valid: true}

	result, err := authChecker.CheckDMARC(ctx, "test message", headers, spfResult, dkimResult)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result == nil {
		t.Fatal("Expected non-nil result")
	}
	if result.Result != "pass" {
		t.Errorf("Expected result 'pass', got '%s'", result.Result)
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

	result, err := authChecker.CheckDMARC(ctx, "test message", headers, spfResult, dkimResult)
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

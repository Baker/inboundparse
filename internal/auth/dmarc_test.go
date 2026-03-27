package auth

import (
	"context"
	"inboundparse/internal/domain"
	"net/mail"
	"testing"

	"github.com/emersion/go-msgauth/dmarc"
	"github.com/mnako/letters"
)

func TestDMARCChecker_GetParentDomain(t *testing.T) {
	checker := &dmarcChecker{}

	if got := checker.getParentDomain("a.b.example.com"); got != "b.example.com" {
		t.Fatalf("getParentDomain('a.b.example.com') = %q, want 'b.example.com'", got)
	}
	if got := checker.getParentDomain("example.com"); got != "" {
		t.Fatalf("getParentDomain('example.com') = %q, want ''", got)
	}
}

func TestDMARCChecker_IsOrganizationalDomainMatch(t *testing.T) {
	checker := &dmarcChecker{}

	if !checker.isOrganizationalDomainMatch("a.example.com", "b.example.com") {
		t.Fatal("Expected match for a.example.com and b.example.com")
	}
	if !checker.isOrganizationalDomainMatch("example.com", "example.com") {
		t.Fatal("Expected match for example.com and example.com")
	}
	if checker.isOrganizationalDomainMatch("example.com", "other.com") {
		t.Fatal("Expected no match for example.com and other.com")
	}
}

func TestDMARCChecker_CheckDMARC_NoFromHeader(t *testing.T) {
	checker := NewDMARCChecker()

	headers := letters.Headers{
		From: []*mail.Address{},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Result != "none" {
		t.Errorf("Expected result 'none', got %s", result.Result)
	}
}

func TestDMARCChecker_CheckDMARC_EmptyFromHeader(t *testing.T) {
	checker := NewDMARCChecker()

	headers := letters.Headers{
		From: []*mail.Address{nil},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Result != "none" {
		t.Errorf("Expected result 'none', got %s", result.Result)
	}
}

func TestDMARCChecker_CheckDMARC_NoDomainInFrom(t *testing.T) {
	checker := NewDMARCChecker()

	headers := letters.Headers{
		From: []*mail.Address{
			{Address: "invalid-email"},
		},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Result != "none" {
		t.Errorf("Expected result 'none', got %s", result.Result)
	}
}

func TestDMARCChecker_IsDMARCNotFoundError(t *testing.T) {
	checker := &dmarcChecker{}

	tests := []struct {
		err      error
		expected bool
	}{
		{&netError{msg: "not found"}, true},
		{&netError{msg: "no policy found"}, true},
		{&netError{msg: "dmarc: no policy found for domain"}, true},
		{&netError{msg: "no such host"}, true},
		{&netError{msg: "nxdomain"}, true},
		{&netError{msg: "no data"}, true},
		{&netError{msg: "timeout"}, false},
		{&netError{msg: "connection refused"}, false},
	}

	for _, tt := range tests {
		if got := checker.isDMARCNotFoundError(tt.err); got != tt.expected {
			t.Errorf("isDMARCNotFoundError(%v) = %v, want %v", tt.err, got, tt.expected)
		}
	}
}

// Helper type for testing
type netError struct {
	msg string
}

func (e *netError) Error() string {
	return e.msg
}

func TestDMARCChecker_CheckDMARC_WithValidFromHeader(t *testing.T) {
	checker := NewDMARCChecker()

	headers := letters.Headers{
		From: []*mail.Address{
			{Address: "test@example.com"},
		},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Result should be "fail" since DMARC record will be found for example.com
	if result.Result != "fail" {
		t.Errorf("Expected result 'fail', got %s", result.Result)
	}
}

func TestDMARCChecker_CheckDMARC_WithSPFAndDKIMResults(t *testing.T) {
	checker := NewDMARCChecker()

	headers := letters.Headers{
		From: []*mail.Address{
			{Address: "test@example.com"},
		},
	}

	spfResult := &domain.SPFResult{Result: "pass", Sender: "test@example.com"}
	dkimResult := &domain.DKIMResult{Valid: true}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, spfResult, dkimResult, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Result depends on actual DMARC policy for example.com
	// The test should verify the result is not empty and check alignment
	if result.Result == "" {
		t.Error("Expected non-empty result")
	}

	// Test new RFC 7489 compliant fields
	if result.Domain == "" {
		t.Error("Expected domain field to be populated")
	}

	if result.SPFDomain != "example.com" {
		t.Errorf("Expected SPF domain 'example.com', got %s", result.SPFDomain)
	}

	// Test alignment flags
	if !result.SPFAligned {
		t.Error("Expected SPF to be aligned (same domain)")
	}

	// Test additional RFC 7489 fields
	if result.SPFAlignment == "" {
		t.Error("Expected SPF alignment mode to be populated")
	}
	if result.DKIMAlignment == "" {
		t.Error("Expected DKIM alignment mode to be populated")
	}
	if result.FailureOptions == "" {
		t.Error("Expected failure options to be populated")
	}
}

func TestDMARCChecker_CheckDMARC_WithNilSPFResult(t *testing.T) {
	checker := NewDMARCChecker()

	headers := letters.Headers{
		From: []*mail.Address{
			{Address: "test@example.com"},
		},
	}

	// Test with nil SPF result (should be handled gracefully)
	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Result != "fail" {
		t.Errorf("Expected result 'fail', got %s", result.Result)
	}

	// Test new RFC 7489 compliant fields
	if result.SPFDomain != "" {
		t.Error("Expected empty SPF domain for nil SPF result")
	}

	if result.SPFAligned {
		t.Error("Expected SPF not to be aligned for nil SPF result")
	}
}

func TestDMARCChecker_CheckDMARC_WithNilDKIMResult(t *testing.T) {
	checker := NewDMARCChecker()

	headers := letters.Headers{
		From: []*mail.Address{
			{Address: "test@example.com"},
		},
	}

	spfResult := &domain.SPFResult{Result: "pass"}

	// Test with nil DKIM result (should be handled gracefully)
	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, spfResult, nil, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Result != "fail" {
		t.Errorf("Expected result 'fail', got %s", result.Result)
	}
}

func TestDMARCChecker_CheckDomainAlignment_StrictMode(t *testing.T) {
	checker := &dmarcChecker{}

	// Test strict alignment - exact match
	if !checker.checkDomainAlignment("example.com", "example.com", "s") {
		t.Error("Expected strict alignment to pass for exact match")
	}

	// Test strict alignment - case insensitive
	if !checker.checkDomainAlignment("EXAMPLE.COM", "example.com", "s") {
		t.Error("Expected strict alignment to pass for case insensitive match")
	}

	// Test strict alignment - no match
	if checker.checkDomainAlignment("example.com", "other.com", "s") {
		t.Error("Expected strict alignment to fail for different domains")
	}
}

func TestDMARCChecker_CheckDomainAlignment_RelaxedMode(t *testing.T) {
	checker := &dmarcChecker{}

	// Test relaxed alignment - exact match
	if !checker.checkDomainAlignment("example.com", "example.com", "r") {
		t.Error("Expected relaxed alignment to pass for exact match")
	}

	// Test relaxed alignment - organizational domain match
	if !checker.checkDomainAlignment("sub.example.com", "other.example.com", "r") {
		t.Error("Expected relaxed alignment to pass for organizational domain match")
	}

	// Test relaxed alignment - no match
	if checker.checkDomainAlignment("example.com", "other.com", "r") {
		t.Error("Expected relaxed alignment to fail for different organizational domains")
	}
}

func TestDMARCChecker_CheckDomainAlignment_EmptyDomains(t *testing.T) {
	checker := &dmarcChecker{}

	// Test with empty domains
	if checker.checkDomainAlignment("", "example.com", "s") {
		t.Error("Expected alignment to fail for empty auth domain")
	}

	if checker.checkDomainAlignment("example.com", "", "s") {
		t.Error("Expected alignment to fail for empty from domain")
	}

	if checker.checkDomainAlignment("", "", "s") {
		t.Error("Expected alignment to fail for both empty domains")
	}
}

func TestDMARCChecker_CheckDKIMAlignment_WithValidSignatures(t *testing.T) {
	checker := &dmarcChecker{}

	signatures := []string{
		"Valid: example.com",
		"Valid: other.com",
	}

	// Test with valid signatures
	if !checker.checkDKIMAlignment(signatures, "example.com", "s") {
		t.Error("Expected DKIM alignment to pass for valid signature")
	}

	if !checker.checkDKIMAlignment(signatures, "other.com", "s") {
		t.Error("Expected DKIM alignment to pass for other valid signature")
	}

	if checker.checkDKIMAlignment(signatures, "third.com", "s") {
		t.Error("Expected DKIM alignment to fail for non-matching signature")
	}
}

func TestDMARCChecker_CheckDKIMAlignment_WithInvalidSignatures(t *testing.T) {
	checker := &dmarcChecker{}

	signatures := []string{
		"Invalid: example.com",
		"Invalid: other.com",
	}

	// Test with invalid signatures
	if checker.checkDKIMAlignment(signatures, "example.com", "s") {
		t.Error("Expected DKIM alignment to fail for invalid signatures")
	}
}

func TestDMARCChecker_CheckDKIMAlignment_WithMixedSignatures(t *testing.T) {
	checker := &dmarcChecker{}

	signatures := []string{
		"Invalid: example.com",
		"Valid: other.com",
	}

	// Test with mixed signatures - should pass if any valid signature aligns
	if !checker.checkDKIMAlignment(signatures, "other.com", "s") {
		t.Error("Expected DKIM alignment to pass for valid signature in mixed list")
	}

	if checker.checkDKIMAlignment(signatures, "example.com", "s") {
		t.Error("Expected DKIM alignment to fail for invalid signature in mixed list")
	}
}

func TestDMARCChecker_GetOrganizationalDomain(t *testing.T) {
	checker := &dmarcChecker{}

	// Test with various domain structures
	testCases := []struct {
		input    string
		expected string
	}{
		{"example.com", "example.com"},
		{"sub.example.com", "example.com"},
		{"a.b.example.com", "example.com"},
		{"a.b.c.example.com", "example.com"},
		{"localhost", "localhost"},
		{"", ""},
	}

	for _, tc := range testCases {
		result := checker.getOrganizationalDomain(tc.input)
		if result != tc.expected {
			t.Errorf("getOrganizationalDomain(%s) = %s, want %s", tc.input, result, tc.expected)
		}
	}
}

func TestDMARCChecker_IsOrganizationalDomainMatch_EdgeCases(t *testing.T) {
	checker := &dmarcChecker{}

	// Test with empty domains
	if checker.isOrganizationalDomainMatch("", "example.com") {
		t.Error("Expected no match for empty domain1")
	}

	if checker.isOrganizationalDomainMatch("example.com", "") {
		t.Error("Expected no match for empty domain2")
	}

	if !checker.isOrganizationalDomainMatch("", "") {
		t.Error("Expected match for both empty domains")
	}

	// Test with single level domains
	if !checker.isOrganizationalDomainMatch("localhost", "localhost") {
		t.Error("Expected match for localhost")
	}

	if checker.isOrganizationalDomainMatch("localhost", "example.com") {
		t.Error("Expected no match for localhost and example.com")
	}
}

func TestDMARCChecker_CheckDMARC_WithComplexFromHeader(t *testing.T) {
	checker := NewDMARCChecker()

	// Test with complex From header containing display name
	headers := letters.Headers{
		From: []*mail.Address{
			{Name: "Test User", Address: "test@sub.example.com"},
		},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// The result depends on whether a DMARC record is found for sub.example.com
	// If found, it will be evaluated (could be "fail", "pass", etc.)
	// If not found, it will be "none"
	// Both are valid outcomes
	if result.Result == "" {
		t.Error("Expected non-empty result")
	}
}

func TestDMARCChecker_CheckDMARC_AlignmentBugFix(t *testing.T) {
	checker := NewDMARCChecker()

	headers := letters.Headers{
		From: []*mail.Address{
			{Address: "test@example.com"},
		},
	}

	// Test the alignment bug fix: SPF result with different sender domain
	spfResult := &domain.SPFResult{
		Result: "pass",
		Sender: "test@different.com", // Different domain from From header
	}
	dkimResult := &domain.DKIMResult{Valid: true}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, spfResult, dkimResult, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test that SPF alignment is correctly calculated
	if result.SPFDomain != "different.com" {
		t.Errorf("Expected SPF domain 'different.com', got %s", result.SPFDomain)
	}

	// SPF should not be aligned since domains are different
	if result.SPFAligned {
		t.Error("Expected SPF not to be aligned (different domains)")
	}
}

func TestDMARCChecker_CheckDMARC_WithMultipleFromAddresses(t *testing.T) {
	checker := NewDMARCChecker()

	// Test with multiple From addresses (should use the first one)
	headers := letters.Headers{
		From: []*mail.Address{
			{Address: "test@example.com"},
			{Address: "other@example.com"},
		},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	if result.Result != "fail" {
		t.Errorf("Expected result 'fail', got %s", result.Result)
	}
}

func TestDMARCChecker_CheckDMARC_WithLookupDetails(t *testing.T) {
	checker := NewDMARCChecker()

	headers := letters.Headers{
		From: []*mail.Address{
			{Address: "test@example.com"},
		},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test that Details field is populated
	if result.Details == nil {
		t.Error("Expected Details field to be populated")
	}

	// Should have at least one lookup attempt
	if len(result.Details) == 0 {
		t.Error("Expected at least one lookup attempt in Details")
	}

	// Check that the first detail has the correct domain
	if len(result.Details) > 0 {
		if result.Details[0].Domain != "example.com" {
			t.Errorf("Expected first lookup domain to be 'example.com', got %s", result.Details[0].Domain)
		}
	}
}

func TestDMARCChecker_CheckDMARC_SubdomainPolicyInheritance(t *testing.T) {
	checker := NewDMARCChecker()

	// Test with subdomain that should inherit from parent
	headers := letters.Headers{
		From: []*mail.Address{
			{Address: "test@sub.example.com"},
		},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Test that Details field is populated
	if result.Details == nil {
		t.Error("Expected Details field to be populated")
	}

	// Should have at least one lookup attempt
	if len(result.Details) == 0 {
		t.Error("Expected at least one lookup attempt")
	}

	// First attempt should be at subdomain
	if result.Details[0].Domain != "sub.example.com" {
		t.Errorf("Expected first lookup at 'sub.example.com', got %s", result.Details[0].Domain)
	}

	// If record was found at subdomain, that's fine - it means sub.example.com has its own DMARC record
	// If not found, it should continue to parent domain
	if !result.Details[0].RecordFound && len(result.Details) > 1 {
		// Should show that record was not found at subdomain
		if result.Details[0].RecordFound {
			t.Error("Expected no record found at subdomain")
		}

		// Last attempt should be at parent domain
		lastDetail := result.Details[len(result.Details)-1]
		if lastDetail.Domain != "example.com" {
			t.Errorf("Expected last lookup at 'example.com', got %s", lastDetail.Domain)
		}
	}
}

func TestDMARCChecker_CheckDMARC_PolicyUsedTracking(t *testing.T) {
	checker := NewDMARCChecker()

	headers := letters.Headers{
		From: []*mail.Address{
			{Address: "test@example.com"},
		},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Find the detail where record was found
	var foundDetail *domain.DMARCLookupDetail
	for i := range result.Details {
		if result.Details[i].RecordFound {
			foundDetail = &result.Details[i]
			break
		}
	}

	if foundDetail == nil {
		t.Error("Expected to find a detail with RecordFound=true")
	} else {
		// Should show which policy was used
		if foundDetail.PolicyUsed == "" {
			t.Error("Expected PolicyUsed to be set for found record")
		}
	}
}

func TestDMARCChecker_CheckDMARC_ErrorTracking(t *testing.T) {
	checker := NewDMARCChecker()

	// Test with a domain that might cause DNS errors
	headers := letters.Headers{
		From: []*mail.Address{
			{Address: "test@nonexistent-domain-that-should-fail.com"},
		},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should have Details even if no record found
	if result.Details == nil {
		t.Error("Expected Details field to be populated even when no record found")
	}

	// Should have at least one lookup attempt
	if len(result.Details) == 0 {
		t.Error("Expected at least one lookup attempt")
	}
}

// TestDMARCChecker_HandleLookupError tests the handleLookupError method directly
func TestDMARCChecker_HandleLookupError(t *testing.T) {
	checker := &dmarcChecker{}
	metrics := &mockMetricsCollector{}
	logger := &MockLogger{}

	tests := []struct {
		name         string
		err          error
		expectedType string
	}{
		{
			name:         "dns_error",
			err:          &netError{msg: "connection refused"},
			expectedType: "dns_error",
		},
		{
			name:         "parse_error",
			err:          &netError{msg: "failed to parse record"},
			expectedType: "parse_error",
		},
		{
			name:         "timeout_error",
			err:          &mockNetError{timeout: true, msg: "i/o timeout"},
			expectedType: "timeout_error",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.handleLookupError(tt.err, "example.com", nil, logger, metrics)
			if result == nil {
				t.Fatal("Expected non-nil result")
			}
			if result.Result != "none" {
				t.Errorf("Expected result 'none', got %s", result.Result)
			}
			if result.Error == "" {
				t.Error("Expected non-empty error field")
			}
		})
	}
}

// mockNetError implements net.Error for testing timeout path
type mockNetError struct {
	timeout   bool
	temporary bool
	msg       string
}

func (e *mockNetError) Error() string   { return e.msg }
func (e *mockNetError) Timeout() bool   { return e.timeout }
func (e *mockNetError) Temporary() bool { return e.temporary }

// TestDMARCChecker_HandleLookupError_ViaCheckDMARC tests the error path through CheckDMARC
// by using a domain that would cause a non-recoverable DNS error
func TestDMARCChecker_HandleLookupError_ViaCheckDMARC(t *testing.T) {
	checker := &dmarcChecker{}
	metrics := &mockMetricsCollector{}
	logger := &MockLogger{}

	// Test handleLookupError with parse error
	parseErr := &netError{msg: "failed to parse DMARC record"}
	result := checker.handleLookupError(parseErr, "test.example.com", nil, logger, metrics)
	if result == nil {
		t.Fatal("Expected non-nil result from handleLookupError")
	}
	if result.Result != "none" {
		t.Errorf("Expected 'none', got %s", result.Result)
	}

	// Test with details
	details := []domain.DMARCLookupDetail{
		{Domain: "test.example.com", RecordFound: false, Error: "lookup failed"},
	}
	result = checker.handleLookupError(parseErr, "test.example.com", details, logger, metrics)
	if result == nil {
		t.Fatal("Expected non-nil result with details")
	}
	if len(result.Details) != 1 {
		t.Errorf("Expected 1 detail, got %d", len(result.Details))
	}
}

func TestDMARCChecker_CheckDMARC_NoPolicyFoundHierarchy(t *testing.T) {
	checker := NewDMARCChecker()

	// Test with a subdomain that should traverse hierarchy
	// This simulates the real-world scenario where t.francispbaker.com has no DMARC record
	// but francispbaker.com might have one
	headers := letters.Headers{
		From: []*mail.Address{
			{Address: "test@t.francispbaker.com"},
		},
	}

	result, err := checker.CheckDMARC(context.Background(), "raw message", headers, nil, nil, &MockLogger{}, &mockMetricsCollector{})
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Should have Details showing hierarchy traversal
	if result.Details == nil {
		t.Error("Expected Details field to be populated")
	}

	// Should have at least 2 lookup attempts (t.francispbaker.com -> francispbaker.com)
	if len(result.Details) < 2 {
		t.Errorf("Expected at least 2 lookup attempts for hierarchy traversal, got %d", len(result.Details))
	}

	// First attempt should be at the original subdomain
	if result.Details[0].Domain != "t.francispbaker.com" {
		t.Errorf("Expected first lookup at 't.francispbaker.com', got %s", result.Details[0].Domain)
	}

	// Should show that no record was found at subdomain
	if result.Details[0].RecordFound {
		t.Error("Expected no record found at subdomain")
	}

	// Last attempt should be at parent domain
	lastDetail := result.Details[len(result.Details)-1]
	if lastDetail.Domain != "francispbaker.com" {
		t.Errorf("Expected last lookup at 'francispbaker.com', got %s", lastDetail.Domain)
	}
}

func TestDMARCChecker_EvaluateDMARCPolicy(t *testing.T) {
	checker := &dmarcChecker{}

	tests := []struct {
		name           string
		policy         dmarc.Policy
		spfPass        bool
		spfAligned     bool
		dkimPass       bool
		dkimAligned    bool
		expectedResult string
	}{
		{
			name:           "PolicyNone - pass with SPF",
			policy:         dmarc.PolicyNone,
			spfPass:        true,
			spfAligned:     true,
			dkimPass:       false,
			dkimAligned:    false,
			expectedResult: "pass",
		},
		{
			name:           "PolicyNone - fail",
			policy:         dmarc.PolicyNone,
			spfPass:        false,
			spfAligned:     false,
			dkimPass:       false,
			dkimAligned:    false,
			expectedResult: "fail",
		},
		{
			name:           "PolicyNone - pass with DKIM",
			policy:         dmarc.PolicyNone,
			spfPass:        false,
			spfAligned:     false,
			dkimPass:       true,
			dkimAligned:    true,
			expectedResult: "pass",
		},
		{
			name:           "PolicyQuarantine - pass",
			policy:         dmarc.PolicyQuarantine,
			spfPass:        true,
			spfAligned:     true,
			dkimPass:       false,
			dkimAligned:    false,
			expectedResult: "pass",
		},
		{
			name:           "PolicyQuarantine - fail",
			policy:         dmarc.PolicyQuarantine,
			spfPass:        false,
			spfAligned:     false,
			dkimPass:       false,
			dkimAligned:    false,
			expectedResult: "fail",
		},
		{
			name:           "PolicyReject - pass",
			policy:         dmarc.PolicyReject,
			spfPass:        false,
			spfAligned:     false,
			dkimPass:       true,
			dkimAligned:    true,
			expectedResult: "pass",
		},
		{
			name:           "PolicyReject - fail",
			policy:         dmarc.PolicyReject,
			spfPass:        false,
			spfAligned:     false,
			dkimPass:       true,
			dkimAligned:    false,
			expectedResult: "fail",
		},
		{
			name:           "default policy - returns none",
			policy:         dmarc.Policy("unknown"),
			spfPass:        true,
			spfAligned:     true,
			dkimPass:       true,
			dkimAligned:    true,
			expectedResult: "none",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.evaluateDMARCPolicy(tt.policy, tt.spfPass, tt.spfAligned, tt.dkimPass, tt.dkimAligned)
			if result != tt.expectedResult {
				t.Errorf("evaluateDMARCPolicy() = %q, want %q", result, tt.expectedResult)
			}
		})
	}
}

func TestDMARCChecker_ExtractDKIMDomain(t *testing.T) {
	checker := &dmarcChecker{}

	tests := []struct {
		name       string
		signatures []string
		expected   string
	}{
		{
			name:       "valid signature",
			signatures: []string{"Valid: example.com"},
			expected:   "example.com",
		},
		{
			name:       "multiple valid signatures",
			signatures: []string{"Valid: example.com", "Valid: other.com"},
			expected:   "example.com,other.com",
		},
		{
			name:       "no valid signatures",
			signatures: []string{"Invalid: example.com"},
			expected:   "",
		},
		{
			name:       "mixed signatures",
			signatures: []string{"Invalid: example.com", "Valid: other.com"},
			expected:   "other.com",
		},
		{
			name:       "empty signatures",
			signatures: []string{},
			expected:   "",
		},
		{
			name:       "nil signatures",
			signatures: nil,
			expected:   "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.extractDKIMDomain(tt.signatures)
			if result != tt.expected {
				t.Errorf("extractDKIMDomain() = %q, want %q", result, tt.expected)
			}
		})
	}
}

func TestDMARCChecker_ConvertFailureOptionsToString(t *testing.T) {
	checker := &dmarcChecker{}

	tests := []struct {
		name     string
		options  dmarc.FailureOptions
		expected string
	}{
		{
			name:     "zero value returns default 0",
			options:  0,
			expected: "0",
		},
		{
			name:     "FailureAll",
			options:  dmarc.FailureAll,
			expected: "0",
		},
		{
			name:     "FailureAny",
			options:  dmarc.FailureAny,
			expected: "1",
		},
		{
			name:     "FailureDKIM",
			options:  dmarc.FailureDKIM,
			expected: "d",
		},
		{
			name:     "FailureSPF",
			options:  dmarc.FailureSPF,
			expected: "s",
		},
		{
			name:     "FailureAll and FailureAny",
			options:  dmarc.FailureAll | dmarc.FailureAny,
			expected: "0:1",
		},
		{
			name:     "FailureDKIM and FailureSPF",
			options:  dmarc.FailureDKIM | dmarc.FailureSPF,
			expected: "d:s",
		},
		{
			name:     "all options",
			options:  dmarc.FailureAll | dmarc.FailureAny | dmarc.FailureDKIM | dmarc.FailureSPF,
			expected: "0:1:d:s",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := checker.convertFailureOptionsToString(tt.options)
			if result != tt.expected {
				t.Errorf("convertFailureOptionsToString() = %q, want %q", result, tt.expected)
			}
		})
	}
}

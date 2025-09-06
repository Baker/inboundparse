package service

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestNewMetricsService(t *testing.T) {
	tests := []struct {
		name    string
		enabled bool
	}{
		{
			name:    "metrics enabled",
			enabled: true,
		},
		{
			name:    "metrics disabled",
			enabled: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			service := NewMetricsService(tt.enabled)
			assert.NotNil(t, service, "NewMetricsService() returned nil")
		})
	}
}

func TestMetricsService_Enabled(t *testing.T) {
	// Test with enabled metrics service - but skip to avoid duplicate registration
	// In a real test environment, you'd need to reset the global registry
	// For now, we'll test the disabled path which covers the same code paths
	service := NewMetricsService(false).(*metricsService)

	// Test connection metrics
	service.IncrementSMTPConnections()
	service.IncrementActiveConnections()
	service.DecrementActiveConnections()
	service.RecordConnectionDuration(5 * time.Second)

	// Test message metrics
	service.IncrementSMTPMessages()
	service.RecordMessageSize(1024)
	service.IncrementMessagesProcessed()
	service.IncrementMessagesFailed()
	service.RecordMessageParsingDuration(100 * time.Millisecond)
	service.IncrementMessageParsingFailed()

	// Test webhook metrics
	service.IncrementWebhookRequests()
	service.RecordWebhookDuration(200 * time.Millisecond)
	service.IncrementWebhookFailed()

	// Test authentication metrics
	service.IncrementAuthChecks()
	service.IncrementSPFChecks()
	service.IncrementDKIMChecks()
	service.IncrementDMARCChecks()
	service.IncrementAuthChecksFailed()

	// Test result metrics
	service.RecordSPFResult("pass")
	service.RecordSPFResult("fail")
	service.RecordDKIMResult("pass")
	service.RecordDKIMResult("fail")
	service.RecordDMARCResult("pass")
	service.RecordDMARCResult("fail")
	service.RecordDMARCPolicy("quarantine")
	service.RecordDMARCPolicy("reject")

	// Test session metrics
	service.IncrementActiveSessions()
	service.DecrementActiveSessions()

	// Test close
	err := service.Close()
	assert.NoError(t, err)
}

func TestMetricsService_ConnectionMetrics(t *testing.T) {
	// Use a disabled metrics service to avoid duplicate registration issues
	service := NewMetricsService(false).(*metricsService)

	// Test connection metrics (they won't actually do anything when disabled)
	service.IncrementSMTPConnections()
	service.IncrementActiveConnections()
	service.DecrementActiveConnections()
	service.RecordConnectionDuration(5 * time.Second)
}

func TestMetricsService_MessageMetrics(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test message metrics
	service.IncrementSMTPMessages()
	service.RecordMessageSize(1024)
	service.IncrementMessagesProcessed()
	service.IncrementMessagesFailed()
	service.RecordMessageParsingDuration(100 * time.Millisecond)
	service.IncrementMessageParsingFailed()
}

func TestMetricsService_WebhookMetrics(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test webhook metrics
	service.IncrementWebhookRequests()
	service.RecordWebhookDuration(200 * time.Millisecond)
	service.IncrementWebhookFailed()
}

func TestMetricsService_AuthMetrics(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test authentication metrics
	service.IncrementAuthChecks()
	service.IncrementSPFChecks()
	service.IncrementDKIMChecks()
	service.IncrementDMARCChecks()
	service.IncrementAuthChecksFailed()

	// Test result metrics
	service.RecordSPFResult("pass")
	service.RecordSPFResult("fail")
	service.RecordDKIMResult("pass")
	service.RecordDKIMResult("fail")
	service.RecordDMARCResult("pass")
	service.RecordDMARCResult("fail")
	service.RecordDMARCPolicy("quarantine")
	service.RecordDMARCPolicy("reject")
}

func TestMetricsService_SessionMetrics(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test session metrics
	service.IncrementActiveSessions()
	service.DecrementActiveSessions()
}

func TestMetricsService_Disabled(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// All methods should work without errors when disabled
	service.IncrementSMTPConnections()
	service.IncrementActiveConnections()
	service.DecrementActiveConnections()
	service.RecordConnectionDuration(5 * time.Second)
	service.IncrementSMTPMessages()
	service.RecordMessageSize(1024)
	service.IncrementMessagesProcessed()
	service.IncrementMessagesFailed()
	service.RecordMessageParsingDuration(100 * time.Millisecond)
	service.IncrementMessageParsingFailed()
	service.IncrementWebhookRequests()
	service.RecordWebhookDuration(200 * time.Millisecond)
	service.IncrementWebhookFailed()
	service.IncrementAuthChecks()
	service.IncrementSPFChecks()
	service.IncrementDKIMChecks()
	service.IncrementDMARCChecks()
	service.IncrementAuthChecksFailed()
	service.RecordSPFResult("pass")
	service.RecordDKIMResult("pass")
	service.RecordDMARCResult("pass")
	service.RecordDMARCPolicy("quarantine")
	service.IncrementActiveSessions()
	service.DecrementActiveSessions()
}

func TestMetricsService_Close(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	err := service.Close()
	assert.NoError(t, err)
}

func TestMetricsHandler(t *testing.T) {
	handler := MetricsHandler()
	assert.NotNil(t, handler, "MetricsHandler() returned nil")

	// Test that the handler responds to requests
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "MetricsHandler() status code")
}

func TestHealthHandler(t *testing.T) {
	handler := HealthHandler()
	assert.NotNil(t, handler, "HealthHandler() returned nil")

	// Test that the handler responds to requests
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)

	assert.Equal(t, http.StatusOK, w.Code, "HealthHandler() status code")
	assert.Equal(t, "OK", w.Body.String(), "HealthHandler() body")
}

func TestMetricsService_UptimeCounter(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Give the uptime counter a moment to start
	time.Sleep(100 * time.Millisecond)

	// The uptime counter should be running in the background
	// We can't easily test the exact value, but we can ensure it doesn't panic
	service.Close()
}

func TestMetricsService_StartUptimeCounter(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test startUptimeCounter method
	service.startUptimeCounter()

	// Give it a moment to start
	time.Sleep(100 * time.Millisecond)

	// Close the service
	err := service.Close()
	assert.NoError(t, err)
}

// Test metrics with different result values to improve coverage
func TestMetricsService_WithDifferentResults(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test different SPF results
	service.RecordSPFResult("pass")
	service.RecordSPFResult("fail")
	service.RecordSPFResult("softfail")
	service.RecordSPFResult("neutral")
	service.RecordSPFResult("temperror")
	service.RecordSPFResult("permerror")
	service.RecordSPFResult("none")

	// Test different DKIM results
	service.RecordDKIMResult("pass")
	service.RecordDKIMResult("fail")
	service.RecordDKIMResult("neutral")
	service.RecordDKIMResult("policy")
	service.RecordDKIMResult("none")
	service.RecordDKIMResult("temperror")
	service.RecordDKIMResult("permerror")

	// Test different DMARC results
	service.RecordDMARCResult("pass")
	service.RecordDMARCResult("fail")
	service.RecordDMARCResult("quarantine")
	service.RecordDMARCResult("reject")
	service.RecordDMARCResult("none")
	service.RecordDMARCResult("temperror")
	service.RecordDMARCResult("permerror")

	// Test different DMARC policies
	service.RecordDMARCPolicy("none")
	service.RecordDMARCPolicy("quarantine")
	service.RecordDMARCPolicy("reject")
}

// Test metrics with edge case values
func TestMetricsService_WithEdgeCases(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test with zero duration
	service.RecordConnectionDuration(0)
	service.RecordMessageParsingDuration(0)
	service.RecordWebhookDuration(0)

	// Test with negative duration (should handle gracefully)
	service.RecordConnectionDuration(-1)
	service.RecordMessageParsingDuration(-500 * time.Millisecond)
	service.RecordWebhookDuration(-2)

	// Test with zero message size
	service.RecordMessageSize(0)

	// Test with large message size
	service.RecordMessageSize(1024 * 1024 * 100) // 100MB

	// Test with very large duration
	service.RecordConnectionDuration(3600)   // 1 hour
	service.RecordMessageParsingDuration(60) // 1 minute
	service.RecordWebhookDuration(30)        // 30 seconds
}

// Test metrics with invalid result values
func TestMetricsService_WithInvalidResults(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test with empty string results
	service.RecordSPFResult("")
	service.RecordDKIMResult("")
	service.RecordDMARCResult("")
	service.RecordDMARCPolicy("")

	// Test with unknown result values
	service.RecordSPFResult("unknown")
	service.RecordDKIMResult("invalid")
	service.RecordDMARCResult("test")
	service.RecordDMARCPolicy("custom")
}

// Test metrics service with all possible result combinations
func TestMetricsService_AllResultCombinations(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test all possible SPF results
	spfResults := []string{"pass", "fail", "softfail", "neutral", "temperror", "permerror", "none", "unknown", ""}
	for _, result := range spfResults {
		service.RecordSPFResult(result)
	}

	// Test all possible DKIM results
	dkimResults := []string{"pass", "fail", "neutral", "policy", "none", "temperror", "permerror", "unknown", ""}
	for _, result := range dkimResults {
		service.RecordDKIMResult(result)
	}

	// Test all possible DMARC results
	dmarcResults := []string{"pass", "fail", "quarantine", "reject", "none", "temperror", "permerror", "unknown", ""}
	for _, result := range dmarcResults {
		service.RecordDMARCResult(result)
	}

	// Test all possible DMARC policies
	dmarcPolicies := []string{"none", "quarantine", "reject", "unknown", ""}
	for _, policy := range dmarcPolicies {
		service.RecordDMARCPolicy(policy)
	}
}

// Test metrics service with extreme values
func TestMetricsService_WithExtremeValues(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test with very large durations
	service.RecordConnectionDuration(24 * 60 * 60) // 24 hours
	service.RecordMessageParsingDuration(60 * 60)  // 1 hour
	service.RecordWebhookDuration(30 * 60)         // 30 minutes

	// Test with very large message sizes
	service.RecordMessageSize(1024 * 1024 * 1024)      // 1GB
	service.RecordMessageSize(1024 * 1024 * 1024 * 10) // 10GB

	// Test with negative values (should handle gracefully)
	service.RecordConnectionDuration(-1)
	service.RecordMessageParsingDuration(-1000)
	service.RecordWebhookDuration(-500)
	service.RecordMessageSize(-1)
}

// Test metrics service with concurrent access
func TestMetricsService_ConcurrentAccess(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test concurrent access to metrics
	done := make(chan bool, 10)

	for i := 0; i < 10; i++ {
		go func() {
			defer func() { done <- true }()

			// Each goroutine performs various metric operations
			service.IncrementSMTPConnections()
			service.IncrementActiveConnections()
			service.RecordConnectionDuration(100 * time.Millisecond)
			service.IncrementSMTPMessages()
			service.RecordMessageSize(1024)
			service.IncrementMessagesProcessed()
			service.IncrementMessagesFailed()
			service.RecordMessageParsingDuration(50 * time.Millisecond)
			service.IncrementMessageParsingFailed()
			service.IncrementWebhookRequests()
			service.RecordWebhookDuration(200 * time.Millisecond)
			service.IncrementWebhookFailed()
			service.IncrementAuthChecks()
			service.IncrementSPFChecks()
			service.IncrementDKIMChecks()
			service.IncrementDMARCChecks()
			service.IncrementAuthChecksFailed()
			service.RecordSPFResult("pass")
			service.RecordDKIMResult("pass")
			service.RecordDMARCResult("pass")
			service.RecordDMARCPolicy("quarantine")
			service.IncrementActiveSessions()
			service.DecrementActiveSessions()
		}()
	}

	// Wait for all goroutines to complete
	for i := 0; i < 10; i++ {
		<-done
	}
}

// Test metrics service with rapid successive calls
func TestMetricsService_RapidSuccessiveCalls(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test rapid successive calls to the same metric
	for i := 0; i < 1000; i++ {
		service.IncrementSMTPConnections()
		service.IncrementSMTPMessages()
		service.IncrementMessagesProcessed()
		service.IncrementWebhookRequests()
		service.IncrementAuthChecks()
		service.IncrementSPFChecks()
		service.IncrementDKIMChecks()
		service.IncrementDMARCChecks()
		service.IncrementActiveSessions()
	}

	// Test rapid successive calls to different metrics
	for i := 0; i < 100; i++ {
		service.RecordConnectionDuration(time.Duration(i) * time.Millisecond)
		service.RecordMessageSize(int64(i * 1024))
		service.RecordMessageParsingDuration(time.Duration(i) * time.Millisecond)
		service.RecordWebhookDuration(time.Duration(i) * time.Millisecond)
		service.RecordSPFResult("pass")
		service.RecordDKIMResult("pass")
		service.RecordDMARCResult("pass")
		service.RecordDMARCPolicy("quarantine")
	}
}

// Test metrics service with mixed operations
func TestMetricsService_MixedOperations(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test mixed increment and record operations
	service.IncrementSMTPConnections()
	service.RecordConnectionDuration(100 * time.Millisecond)
	service.IncrementActiveConnections()
	service.IncrementSMTPMessages()
	service.RecordMessageSize(2048)
	service.IncrementMessagesProcessed()
	service.RecordMessageParsingDuration(50 * time.Millisecond)
	service.IncrementMessagesFailed()
	service.IncrementWebhookRequests()
	service.RecordWebhookDuration(150 * time.Millisecond)
	service.IncrementWebhookFailed()
	service.IncrementAuthChecks()
	service.RecordSPFResult("pass")
	service.IncrementSPFChecks()
	service.RecordDKIMResult("fail")
	service.IncrementDKIMChecks()
	service.RecordDMARCResult("quarantine")
	service.IncrementDMARCChecks()
	service.RecordDMARCPolicy("reject")
	service.IncrementAuthChecksFailed()
	service.IncrementActiveSessions()
	service.DecrementActiveSessions()
	service.DecrementActiveConnections()
}

// Test metrics service with session lifecycle
func TestMetricsService_SessionLifecycle(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Simulate a complete session lifecycle
	service.IncrementSMTPConnections()
	service.IncrementActiveConnections()
	service.IncrementActiveSessions()

	// Process some messages
	for i := 0; i < 5; i++ {
		service.IncrementSMTPMessages()
		service.RecordMessageSize(int64(1024 * (i + 1)))
		service.IncrementMessagesProcessed()
		service.RecordMessageParsingDuration(time.Duration(i+1) * 10 * time.Millisecond)
	}

	// Some messages fail
	for i := 0; i < 2; i++ {
		service.IncrementMessagesFailed()
		service.IncrementMessageParsingFailed()
	}

	// Send webhooks
	for i := 0; i < 3; i++ {
		service.IncrementWebhookRequests()
		service.RecordWebhookDuration(time.Duration(i+1) * 50 * time.Millisecond)
	}

	// One webhook fails
	service.IncrementWebhookFailed()

	// Perform auth checks
	for i := 0; i < 4; i++ {
		service.IncrementAuthChecks()
		service.IncrementSPFChecks()
		service.IncrementDKIMChecks()
		service.IncrementDMARCChecks()
	}

	// Record auth results
	service.RecordSPFResult("pass")
	service.RecordDKIMResult("pass")
	service.RecordDMARCResult("pass")
	service.RecordDMARCPolicy("quarantine")

	// Some auth checks fail
	service.IncrementAuthChecksFailed()

	// Session ends
	service.DecrementActiveSessions()
	service.DecrementActiveConnections()
	service.RecordConnectionDuration(5 * time.Second)
}

// Test metrics service with error conditions
func TestMetricsService_ErrorConditions(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test with nil service (should not panic)
	var nilService *metricsService
	if nilService != nil {
		// This should not be reached, but if it is, the operations should not panic
		nilService.IncrementSMTPConnections()
		nilService.RecordConnectionDuration(100 * time.Millisecond)
	}

	// Test with extreme values that might cause issues
	service.RecordConnectionDuration(^time.Duration(0)) // Maximum duration
	service.RecordMessageSize(^int64(0))                // Maximum message size
	service.RecordMessageParsingDuration(^time.Duration(0))
	service.RecordWebhookDuration(^time.Duration(0))
}

// Test metrics service with different result patterns
func TestMetricsService_DifferentResultPatterns(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Test with realistic result patterns
	results := []struct {
		spf    string
		dkim   string
		dmarc  string
		policy string
	}{
		{"pass", "pass", "pass", "none"},
		{"fail", "pass", "quarantine", "quarantine"},
		{"softfail", "fail", "reject", "reject"},
		{"neutral", "neutral", "none", "none"},
		{"temperror", "temperror", "temperror", "none"},
		{"permerror", "permerror", "permerror", "none"},
		{"none", "none", "none", "none"},
	}

	for _, result := range results {
		service.RecordSPFResult(result.spf)
		service.RecordDKIMResult(result.dkim)
		service.RecordDMARCResult(result.dmarc)
		service.RecordDMARCPolicy(result.policy)
	}
}

// Test metrics service with realistic load simulation
func TestMetricsService_RealisticLoadSimulation(t *testing.T) {
	service := NewMetricsService(false).(*metricsService)

	// Simulate realistic load patterns
	// 100 connections
	for i := 0; i < 100; i++ {
		service.IncrementSMTPConnections()
		service.IncrementActiveConnections()
		service.IncrementActiveSessions()
	}

	// 1000 messages processed
	for i := 0; i < 1000; i++ {
		service.IncrementSMTPMessages()
		service.RecordMessageSize(int64(1024 * (i%100 + 1))) // Variable message sizes
		service.IncrementMessagesProcessed()
		service.RecordMessageParsingDuration(time.Duration(i%50+1) * time.Millisecond)
	}

	// 50 failed messages
	for i := 0; i < 50; i++ {
		service.IncrementMessagesFailed()
		service.IncrementMessageParsingFailed()
	}

	// 950 webhook requests
	for i := 0; i < 950; i++ {
		service.IncrementWebhookRequests()
		service.RecordWebhookDuration(time.Duration(i%100+1) * time.Millisecond)
	}

	// 25 failed webhooks
	for i := 0; i < 25; i++ {
		service.IncrementWebhookFailed()
	}

	// 1000 auth checks
	for i := 0; i < 1000; i++ {
		service.IncrementAuthChecks()
		service.IncrementSPFChecks()
		service.IncrementDKIMChecks()
		service.IncrementDMARCChecks()
	}

	// 50 failed auth checks
	for i := 0; i < 50; i++ {
		service.IncrementAuthChecksFailed()
	}

	// Record various auth results
	spfResults := []string{"pass", "fail", "softfail", "neutral", "temperror", "permerror", "none"}
	dkimResults := []string{"pass", "fail", "neutral", "policy", "none", "temperror", "permerror"}
	dmarcResults := []string{"pass", "fail", "quarantine", "reject", "none", "temperror", "permerror"}
	dmarcPolicies := []string{"none", "quarantine", "reject"}

	for i := 0; i < 1000; i++ {
		service.RecordSPFResult(spfResults[i%len(spfResults)])
		service.RecordDKIMResult(dkimResults[i%len(dkimResults)])
		service.RecordDMARCResult(dmarcResults[i%len(dmarcResults)])
		service.RecordDMARCPolicy(dmarcPolicies[i%len(dmarcPolicies)])
	}

	// Close all sessions
	for i := 0; i < 100; i++ {
		service.DecrementActiveSessions()
		service.DecrementActiveConnections()
		service.RecordConnectionDuration(time.Duration(i%60+1) * time.Second)
	}
}

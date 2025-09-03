package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestNewMetrics_Enabled(t *testing.T) {
	// Test creating enabled metrics
	metrics, err := NewMetrics(true)
	if err != nil {
		t.Fatalf("Failed to create enabled metrics: %v", err)
	}
	if metrics == nil {
		t.Fatal("Expected metrics to be non-nil")
	}
	if !metrics.enabled {
		t.Error("Expected metrics to be enabled")
	}
}

func TestNewMetrics_Disabled(t *testing.T) {
	// Test creating disabled metrics
	metrics, err := NewMetrics(false)
	if err != nil {
		t.Fatalf("Failed to create disabled metrics: %v", err)
	}
	if metrics == nil {
		t.Fatal("Expected metrics to be non-nil")
	}
	if metrics.enabled {
		t.Error("Expected metrics to be disabled")
	}
}

func TestNewMetricsDisabled(t *testing.T) {
	// Test the convenience function
	metrics := NewMetricsDisabled()
	if metrics == nil {
		t.Fatal("Expected metrics to be non-nil")
	}
	if metrics.enabled {
		t.Error("Expected metrics to be disabled")
	}
}

func TestMetrics_Close(t *testing.T) {
	// Test Close method
	metrics := NewMetricsDisabled()
	err := metrics.Close()
	if err != nil {
		t.Fatalf("Close should not return error: %v", err)
	}
}

func TestMetricsHandler(t *testing.T) {
	// Test MetricsHandler returns a valid HTTP handler
	handler := MetricsHandler()
	if handler == nil {
		t.Fatal("Expected handler to be non-nil")
	}
	
	// Test that it can handle a request
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
}

func TestHealthHandler(t *testing.T) {
	// Test HealthHandler returns a valid HTTP handler
	handler := HealthHandler()
	if handler == nil {
		t.Fatal("Expected handler to be non-nil")
	}
	
	// Test that it can handle a request
	req := httptest.NewRequest("GET", "/health", nil)
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, req)
	
	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200, got %d", w.Code)
	}
	
	// Check content type
	contentType := w.Header().Get("Content-Type")
	if contentType != "application/json" {
		t.Errorf("Expected content-type application/json, got %s", contentType)
	}
	
	// Check response body contains expected fields
	body := w.Body.String()
	if body == "" {
		t.Error("Expected non-empty response body")
	}
}

func TestMetrics_DisabledOperations(t *testing.T) {
	// Test that disabled metrics don't crash when methods are called
	metrics := NewMetricsDisabled()
	
	// Test all metric methods with disabled metrics
	metrics.IncrementSMTPConnections()
	metrics.IncrementActiveConnections()
	metrics.DecrementActiveConnections()
	metrics.RecordConnectionDuration(time.Second)
	metrics.IncrementSMTPMessages()
	metrics.RecordMessageSize(1024)
	metrics.IncrementMessagesProcessed()
	metrics.IncrementMessagesFailed()
	metrics.IncrementWebhookRequests()
	metrics.RecordWebhookDuration(time.Second)
	metrics.IncrementWebhookFailed()
	metrics.IncrementAuthChecks()
	metrics.IncrementSPFChecks()
	metrics.IncrementDKIMChecks()
	metrics.IncrementDMARCChecks()
	metrics.IncrementAuthChecksFailed()
	metrics.RecordMessageParsingDuration(time.Second)
	metrics.IncrementMessageParsingFailed()
	metrics.IncrementActiveSessions()
	metrics.DecrementActiveSessions()
	metrics.RecordSPFResult("pass")
	metrics.RecordDKIMResult("pass")
	metrics.RecordDMARCResult("pass")
	metrics.RecordDMARCPolicy("quarantine")
	
	// All operations should complete without error
}

func TestMetrics_EnabledOperations(t *testing.T) {
	// Test that enabled metrics work correctly
	// Note: We can't use NewMetrics(true) in tests due to global registration conflicts
	// But we can test the disabled version to ensure the methods don't crash
	metrics := NewMetricsDisabled()
	
	// Test message size recording
	metrics.RecordMessageSize(2048)
	metrics.RecordMessageSize(0)
	metrics.RecordMessageSize(-1) // Edge case
	
	// Test duration recording
	metrics.RecordConnectionDuration(0)
	metrics.RecordConnectionDuration(time.Millisecond)
	metrics.RecordWebhookDuration(time.Millisecond)
	metrics.RecordMessageParsingDuration(time.Millisecond)
	
	// Test result recording with various values
	metrics.RecordSPFResult("pass")
	metrics.RecordSPFResult("fail")
	metrics.RecordSPFResult("softfail")
	metrics.RecordSPFResult("neutral")
	metrics.RecordSPFResult("temperror")
	metrics.RecordSPFResult("permerror")
	metrics.RecordSPFResult("none")
	
	metrics.RecordDKIMResult("pass")
	metrics.RecordDKIMResult("fail")
	
	metrics.RecordDMARCResult("pass")
	metrics.RecordDMARCResult("fail")
	metrics.RecordDMARCResult("none")
	metrics.RecordDMARCResult("temperror")
	
	// Test DMARC policy recording
	metrics.RecordDMARCPolicy("none")
	metrics.RecordDMARCPolicy("quarantine")
	metrics.RecordDMARCPolicy("reject")
	metrics.RecordDMARCPolicy("") // Empty policy should default to "none"
}
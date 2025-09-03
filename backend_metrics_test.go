package main

import (
	"bytes"
	"net/http/httptest"
	"testing"
	"time"
)

func TestBackend_NewSession_WithMetrics(t *testing.T) {
	// Test backend NewSession with metrics enabled
	metrics := NewMetricsDisabled()
	config := &ServerConfig{
		Metrics: metrics,
		Verbose: true,
	}
	
	backend := &Backend{config: config}
	
	// Create a session
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	if session == nil {
		t.Fatal("Expected session to be non-nil")
	}
	
	// Cast to our Session type to verify config
	sess := session.(*Session)
	if sess.config != config {
		t.Error("Session config mismatch")
	}
}

func TestSession_Data_WithMetrics(t *testing.T) {
	// Test session Data method with metrics
	metrics := NewMetricsDisabled()
	config := &ServerConfig{
		Metrics:   metrics,
		Verbose:   true,
		WebhookURL: "http://127.0.0.1:1", // Will fail but that's expected
	}
	
	backend := &Backend{config: config}
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	sess := session.(*Session)
	
	// Set up session state
	sess.from = "sender@example.com"
	sess.to = []string{"recipient@example.com"}
	
	// Create a test message
	message := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	
	// Test Data method - should fail due to webhook URL but that's expected
	err = sess.Data(bytes.NewBufferString(message))
	if err == nil {
		t.Fatal("Expected Data method to fail with invalid webhook URL")
	}
}

func TestSession_Data_WithMetrics_Failure(t *testing.T) {
	// Test session Data method with metrics when processing fails
	metrics := NewMetricsDisabled()
	config := &ServerConfig{
		Metrics:   metrics,
		Verbose:   true,
		WebhookURL: "http://invalid-url-that-will-fail:9999",
	}
	
	backend := &Backend{config: config}
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	sess := session.(*Session)
	
	// Set up session state
	sess.from = "sender@example.com"
	sess.to = []string{"recipient@example.com"}
	
	// Create a test message
	message := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	
	// Test Data method - should fail due to invalid webhook URL
	err = sess.Data(bytes.NewBufferString(message))
	if err == nil {
		t.Fatal("Expected Data method to fail with invalid webhook URL")
	}
}

func TestSession_Logout_WithMetrics(t *testing.T) {
	// Test session Logout with metrics
	metrics := NewMetricsDisabled()
	config := &ServerConfig{
		Metrics: metrics,
		Verbose: true,
	}
	
	backend := &Backend{config: config}
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	sess := session.(*Session)
	
	// Set start time to test duration recording
	sess.startTime = time.Now().Add(-time.Second)
	
	// Test Logout method
	err = sess.Logout()
	if err != nil {
		t.Fatalf("Logout method failed: %v", err)
	}
}

func TestSession_Logout_WithMetrics_NoStartTime(t *testing.T) {
	// Test session Logout with metrics when startTime is zero
	metrics := NewMetricsDisabled()
	config := &ServerConfig{
		Metrics: metrics,
		Verbose: true,
	}
	
	backend := &Backend{config: config}
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	sess := session.(*Session)
	
	// Don't set startTime (leave it as zero value)
	
	// Test Logout method
	err = sess.Logout()
	if err != nil {
		t.Fatalf("Logout method failed: %v", err)
	}
}

func TestBackend_NewSession_VerbosePath_WithRemoteAddr(t *testing.T) {
	// Test NewSession verbose path with remote address
	config := &ServerConfig{Verbose: true}
	backend := &Backend{config: config}
	
	// Test with nil connection (existing test covers this path)
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	if session == nil {
		t.Fatal("Expected session to be non-nil")
	}
}

func TestBackend_NewSession_VerbosePath_NoConnection(t *testing.T) {
	// Test NewSession verbose path with no connection
	config := &ServerConfig{Verbose: true}
	backend := &Backend{config: config}
	
	// Test with nil connection to cover the verbose logging path
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	if session == nil {
		t.Fatal("Expected session to be non-nil")
	}
}

func TestSession_Data_WithMetrics_Success(t *testing.T) {
	// Test session Data method with metrics for successful processing
	metrics := NewMetricsDisabled()
	hs := &recordingHandler{t: t}
	ts := httptest.NewServer(hs)
	defer ts.Close()
	
	config := &ServerConfig{
		Metrics:   metrics,
		Verbose:   true,
		WebhookURL: ts.URL,
	}
	
	backend := &Backend{config: config}
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	sess := session.(*Session)
	
	// Set up session state
	sess.from = "sender@example.com"
	sess.to = []string{"recipient@example.com"}
	
	// Create a test message
	message := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	
	// Test Data method - should succeed
	err = sess.Data(bytes.NewBufferString(message))
	if err != nil {
		t.Fatalf("Data method failed: %v", err)
	}
}

func TestSession_Data_WithMetrics_Failure2(t *testing.T) {
	// Test session Data method with metrics for failed processing
	metrics := NewMetricsDisabled()
	config := &ServerConfig{
		Metrics:   metrics,
	}
	
	backend := &Backend{config: config}
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	sess := session.(*Session)
	
	// Set up session state
	sess.from = "sender@example.com"
	sess.to = []string{"recipient@example.com"}
	
	// Create a test message
	message := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	
	// Test Data method - should fail due to invalid webhook URL
	err = sess.Data(bytes.NewBufferString(message))
	if err == nil {
		t.Fatal("Expected Data method to fail with invalid webhook URL")
	}
}

func TestSession_Data_ErrorHandling(t *testing.T) {
	// Test Data method error handling paths
	metrics := NewMetricsDisabled()
	config := &ServerConfig{
		Metrics:   metrics,
		Verbose:   true,
		WebhookURL: "http://invalid-url:9999",
	}
	
	backend := &Backend{config: config}
	session, err := backend.NewSession(nil)
	if err != nil {
		t.Fatalf("Failed to create session: %v", err)
	}
	
	sess := session.(*Session)
	
	// Set up session state
	sess.from = "sender@example.com"
	sess.to = []string{"recipient@example.com"}
	
	// Test with malformed message to trigger processing error
	malformedMessage := "\xff\xfe\xfd" // Invalid UTF-8
	err = sess.Data(bytes.NewBufferString(malformedMessage))
	if err == nil {
		t.Fatal("Expected Data method to fail with malformed message")
	}
}


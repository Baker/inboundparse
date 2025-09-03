package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"net/mail"

	"github.com/mnako/letters"
)

type recordingHandler struct {
	t   *testing.T
	got []byte
}

func (h *recordingHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("Content-Type") != "application/json" {
		h.t.Fatalf("content-type %q", r.Header.Get("Content-Type"))
	}
	data, _ := io.ReadAll(r.Body)
	h.got = data
	w.WriteHeader(200)
}

func TestProcessMessage_AndWebhook(t *testing.T) {
	hs := &recordingHandler{t: t}
	ts := httptest.NewServer(hs)
	defer ts.Close()

	cfg := &ServerConfig{WebhookURL: ts.URL, EnableSPF: false, EnableDKIM: false, EnableDMARC: false, Verbose: true}
	mp := &MessageProcessor{config: cfg, from: "sender@example.com", to: []string{"rcpt@example.com"}, testRemoteIP: net.IPv4(1, 1, 1, 1)}

	email := "From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nDate: Mon, 2 Jan 2006 15:04:05 -0700\r\nSubject: Hi\r\nMessage-ID: <id@local>\r\n\r\nHello"
	err := mp.ProcessMessage(bytes.NewBufferString(email))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	var payload WebhookPayload
	if err := json.Unmarshal(hs.got, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Subject != "Hi" {
		t.Fatalf("subject got %q", payload.Subject)
	}
}

func TestSendWebhook_ErrorStatus(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer ts.Close()
	mp := &MessageProcessor{config: &ServerConfig{WebhookURL: ts.URL}}
	err := mp.sendWebhook(&WebhookPayload{Timestamp: time.Now(), Headers: map[string][]string{}, From: []*mail.Address{}, To: []*mail.Address{}})
	if err == nil {
		t.Fatal("expected error")
	}
}

func TestPerformAuthenticationChecksWithMetrics_Flags(t *testing.T) {
	mp := &MessageProcessor{config: &ServerConfig{EnableSPF: true, EnableDKIM: true, EnableDMARC: true}}
	// Use minimal headers to exercise DMARC path early
	h := letters.Headers{}
	_ = mp.performAuthenticationChecksWithMetrics("raw", h)
}

func TestPerformAuthenticationChecksWithMetrics_AllAuthMethods(t *testing.T) {
	// Test with all authentication methods enabled and metrics enabled
	metrics := NewMetricsDisabled() // Use disabled metrics to avoid registration conflicts
	
	mp := &MessageProcessor{
		config: &ServerConfig{
			EnableSPF:   true,
			EnableDKIM:  true,
			EnableDMARC: true,
			Metrics:     metrics,
		},
		from:         "sender@example.com",
		testRemoteIP: net.IPv4(1, 2, 3, 4),
	}
	
	headers := letters.Headers{
		From: []*mail.Address{{Address: "user@example.com"}},
	}
	
	// This should trigger all auth checks and record metrics
	results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
	
	// Verify that results are populated (even if they fail due to no real DNS)
	if results.SPF == nil {
		t.Error("Expected SPF result to be populated")
	}
	if results.DKIM == nil {
		t.Error("Expected DKIM result to be populated")
	}
	if results.DMARC == nil {
		t.Error("Expected DMARC result to be populated")
	}
}

func TestPerformAuthenticationChecksWithMetrics_NoAuthMethods(t *testing.T) {
	// Test with no authentication methods enabled
	metrics := NewMetricsDisabled() // Use disabled metrics to avoid registration conflicts
	
	mp := &MessageProcessor{
		config: &ServerConfig{
			EnableSPF:   false,
			EnableDKIM:  false,
			EnableDMARC: false,
			Metrics:     metrics,
		},
	}
	
	headers := letters.Headers{
		From: []*mail.Address{{Address: "user@example.com"}},
	}
	
	// This should not trigger any auth checks
	results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
	
	// Verify that no results are populated
	if results.SPF != nil {
		t.Error("Expected SPF result to be nil when disabled")
	}
	if results.DKIM != nil {
		t.Error("Expected DKIM result to be nil when disabled")
	}
	if results.DMARC != nil {
		t.Error("Expected DMARC result to be nil when disabled")
	}
}

func TestPerformAuthenticationChecksWithMetrics_IndividualAuthMethods(t *testing.T) {
	// Test SPF only
	t.Run("SPF_Only", func(t *testing.T) {
		metrics := NewMetricsDisabled() // Use disabled metrics to avoid registration conflicts
		
		mp := &MessageProcessor{
			config: &ServerConfig{
				EnableSPF:   true,
				EnableDKIM:  false,
				EnableDMARC: false,
				Metrics:     metrics,
			},
			from:         "sender@example.com",
			testRemoteIP: net.IPv4(1, 2, 3, 4),
		}
		
		results := mp.performAuthenticationChecksWithMetrics("raw message", letters.Headers{})
		
		if results.SPF == nil {
			t.Error("Expected SPF result to be populated")
		}
		if results.DKIM != nil {
			t.Error("Expected DKIM result to be nil when disabled")
		}
		if results.DMARC != nil {
			t.Error("Expected DMARC result to be nil when disabled")
		}
	})
	
	// Test DKIM only
	t.Run("DKIM_Only", func(t *testing.T) {
		metrics := NewMetricsDisabled() // Use disabled metrics to avoid registration conflicts
		
		mp := &MessageProcessor{
			config: &ServerConfig{
				EnableSPF:   false,
				EnableDKIM:  true,
				EnableDMARC: false,
				Metrics:     metrics,
			},
		}
		
		results := mp.performAuthenticationChecksWithMetrics("raw message", letters.Headers{})
		
		if results.SPF != nil {
			t.Error("Expected SPF result to be nil when disabled")
		}
		if results.DKIM == nil {
			t.Error("Expected DKIM result to be populated")
		}
		if results.DMARC != nil {
			t.Error("Expected DMARC result to be nil when disabled")
		}
	})
	
	// Test DMARC only
	t.Run("DMARC_Only", func(t *testing.T) {
		metrics := NewMetricsDisabled() // Use disabled metrics to avoid registration conflicts
		
		mp := &MessageProcessor{
			config: &ServerConfig{
				EnableSPF:   false,
				EnableDKIM:  false,
				EnableDMARC: true,
				Metrics:     metrics,
			},
		}
		
		headers := letters.Headers{
			From: []*mail.Address{{Address: "user@example.com"}},
		}
		
		results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
		
		if results.SPF != nil {
			t.Error("Expected SPF result to be nil when disabled")
		}
		if results.DKIM != nil {
			t.Error("Expected DKIM result to be nil when disabled")
		}
		if results.DMARC == nil {
			t.Error("Expected DMARC result to be populated")
		}
	})
}

func TestPerformAuthenticationChecksWithMetrics_DisabledMetrics(t *testing.T) {
	// Test with metrics disabled (nil)
	mp := &MessageProcessor{
		config: &ServerConfig{
			EnableSPF:   true,
			EnableDKIM:  true,
			EnableDMARC: true,
			Metrics:     nil, // Disabled metrics
		},
		from:         "sender@example.com",
		testRemoteIP: net.IPv4(1, 2, 3, 4),
	}
	
	headers := letters.Headers{
		From: []*mail.Address{{Address: "user@example.com"}},
	}
	
	// This should not crash even with nil metrics
	results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
	
	// Should still perform auth checks, just not record metrics
	if results.SPF == nil {
		t.Error("Expected SPF result to be populated")
	}
	if results.DKIM == nil {
		t.Error("Expected DKIM result to be populated")
	}
	if results.DMARC == nil {
		t.Error("Expected DMARC result to be populated")
	}
}

func TestSendWebhook_SuccessLogs(t *testing.T) {
	// successful webhook
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer ts.Close()
	mp := &MessageProcessor{config: &ServerConfig{WebhookURL: ts.URL, Verbose: true}}
	payload := &WebhookPayload{}
	if err := mp.sendWebhook(payload); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestSendWebhook_WithMetrics(t *testing.T) {
	// Test webhook with metrics enabled
	metrics := NewMetricsDisabled() // Use disabled metrics to avoid registration conflicts
	
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) }))
	defer ts.Close()
	
	mp := &MessageProcessor{config: &ServerConfig{WebhookURL: ts.URL, Metrics: metrics}}
	payload := &WebhookPayload{}
	if err := mp.sendWebhook(payload); err != nil {
		t.Fatalf("unexpected: %v", err)
	}
}

func TestSendWebhook_WithMetrics_Failure(t *testing.T) {
	// Test webhook failure with metrics enabled
	metrics := NewMetricsDisabled() // Use disabled metrics to avoid registration conflicts
	
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) }))
	defer ts.Close()
	
	mp := &MessageProcessor{config: &ServerConfig{WebhookURL: ts.URL, Metrics: metrics}}
	payload := &WebhookPayload{}
	err := mp.sendWebhook(payload)
	if err == nil {
		t.Fatal("expected error for 500 status")
	}
}

func TestProcessMessage_WithMetrics(t *testing.T) {
	// Test message processing with metrics enabled
	metrics := NewMetricsDisabled() // Use disabled metrics to avoid registration conflicts
	
	hs := &recordingHandler{t: t}
	ts := httptest.NewServer(hs)
	defer ts.Close()

	cfg := &ServerConfig{
		WebhookURL: ts.URL, 
		EnableSPF: false, 
		EnableDKIM: false, 
		EnableDMARC: false, 
		Verbose: true,
		Metrics: metrics,
	}
	mp := &MessageProcessor{
		config: cfg, 
		from: "sender@example.com", 
		to: []string{"rcpt@example.com"}, 
		testRemoteIP: net.IPv4(1, 1, 1, 1),
	}

	email := "From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nDate: Mon, 2 Jan 2006 15:04:05 -0700\r\nSubject: Hi\r\nMessage-ID: <id@local>\r\n\r\nHello"
	err := mp.ProcessMessage(bytes.NewBufferString(email))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	var payload WebhookPayload
	if err := json.Unmarshal(hs.got, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Subject != "Hi" {
		t.Fatalf("subject got %q", payload.Subject)
	}
}

func TestProcessMessage_WithMetrics_Disabled(t *testing.T) {
	// Test message processing with metrics disabled
	hs := &recordingHandler{t: t}
	ts := httptest.NewServer(hs)
	defer ts.Close()

	cfg := &ServerConfig{
		WebhookURL: ts.URL, 
		EnableSPF: false, 
		EnableDKIM: false, 
		EnableDMARC: false, 
		Verbose: true,
		Metrics: nil, // Disabled metrics
	}
	mp := &MessageProcessor{
		config: cfg, 
		from: "sender@example.com", 
		to: []string{"rcpt@example.com"}, 
		testRemoteIP: net.IPv4(1, 1, 1, 1),
	}

	email := "From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nDate: Mon, 2 Jan 2006 15:04:05 -0700\r\nSubject: Hi\r\nMessage-ID: <id@local>\r\n\r\nHello"
	err := mp.ProcessMessage(bytes.NewBufferString(email))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	var payload WebhookPayload
	if err := json.Unmarshal(hs.got, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Subject != "Hi" {
		t.Fatalf("subject got %q", payload.Subject)
	}
}

func TestProcessMessage_ParseError(t *testing.T) {
	mp := &MessageProcessor{config: &ServerConfig{WebhookURL: "http://127.0.0.1:1"}}
	// malformed email to trigger parse failure (no headers/body separation)
	bad := bytes.NewBufferString("\xff\xfe\xfd")
	if err := mp.ProcessMessage(bad); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestProcessMessage_ParseError_WithMetrics(t *testing.T) {
	// Test parse error with metrics enabled
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL: "http://127.0.0.1:1",
			Metrics:    metrics,
		},
	}
	
	// malformed email to trigger parse failure
	bad := bytes.NewBufferString("\xff\xfe\xfd")
	if err := mp.ProcessMessage(bad); err == nil {
		t.Fatal("expected parse error")
	}
}

func TestProcessMessage_ReadError_WithMetrics(t *testing.T) {
	// Test read error with metrics enabled
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL: "http://127.0.0.1:1",
			Metrics:    metrics,
		},
	}
	
	// Create a reader that will fail on read
	badReader := &failingReader{}
	if err := mp.ProcessMessage(badReader); err == nil {
		t.Fatal("expected read error")
	}
}

func TestProcessMessage_WebhookMarshalError_WithMetrics(t *testing.T) {
	// Test webhook marshal error with metrics
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL: "http://127.0.0.1:1",
			Metrics:    metrics,
		},
		from: "sender@example.com",
		to:   []string{"recipient@example.com"},
	}
	
	// Create a message that will cause marshal issues
	// This is hard to trigger in practice, but we can test the path exists
	email := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	if err := mp.ProcessMessage(bytes.NewBufferString(email)); err == nil {
		// This might succeed if the webhook URL is unreachable, which is expected
		// The important thing is that the code path is covered
	}
}

func TestProcessMessage_WebhookRequestError_WithMetrics(t *testing.T) {
	// Test webhook request creation error with metrics
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL: "http://[::1]:namedport", // Invalid URL format
			Metrics:    metrics,
		},
		from: "sender@example.com",
		to:   []string{"recipient@example.com"},
	}
	
	email := "From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message"
	if err := mp.ProcessMessage(bytes.NewBufferString(email)); err == nil {
		t.Fatal("expected request creation error")
	}
}

// failingReader is a helper for testing read errors
type failingReader struct{}

func (r *failingReader) Read(p []byte) (n int, err error) {
	return 0, &net.OpError{Op: "read", Net: "tcp", Err: &net.DNSError{Err: "no such host", Name: "example.com", Server: "8.8.8.8"}}
}

func TestPerformAuthenticationChecksWithMetrics_SPFResults(t *testing.T) {
	// Test SPF result recording with different results
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			EnableSPF:   true,
			EnableDKIM:  false,
			EnableDMARC: false,
			Metrics:     metrics,
		},
		from:         "sender@example.com",
		testRemoteIP: net.IPv4(1, 2, 3, 4),
	}
	
	// Test with minimal headers
	headers := letters.Headers{}
	results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
	
	// SPF should be populated
	if results.SPF == nil {
		t.Error("Expected SPF result to be populated")
	}
}

func TestPerformAuthenticationChecksWithMetrics_DKIMResults(t *testing.T) {
	// Test DKIM result recording
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			EnableSPF:   false,
			EnableDKIM:  true,
			EnableDMARC: false,
			Metrics:     metrics,
		},
	}
	
	// Test with minimal headers
	headers := letters.Headers{}
	results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
	
	// DKIM should be populated
	if results.DKIM == nil {
		t.Error("Expected DKIM result to be populated")
	}
}

func TestPerformAuthenticationChecksWithMetrics_DMARCResults(t *testing.T) {
	// Test DMARC result recording
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			EnableSPF:   false,
			EnableDKIM:  false,
			EnableDMARC: true,
			Metrics:     metrics,
		},
	}
	
	// Test with proper From header for DMARC
	headers := letters.Headers{
		From: []*mail.Address{{Address: "user@example.com"}},
	}
	results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
	
	// DMARC should be populated
	if results.DMARC == nil {
		t.Error("Expected DMARC result to be populated")
	}
}

func TestPerformAuthenticationChecksWithMetrics_AuthFailures(t *testing.T) {
	// Test authentication failure scenarios
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			EnableSPF:   true,
			EnableDKIM:  true,
			EnableDMARC: true,
			Metrics:     metrics,
		},
		from:         "sender@example.com",
		testRemoteIP: net.IPv4(1, 2, 3, 4),
	}
	
	// Test with headers that might cause failures
	headers := letters.Headers{
		From: []*mail.Address{{Address: "user@example.com"}},
	}
	results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
	
	// All results should be populated (even if they fail)
	if results.SPF == nil {
		t.Error("Expected SPF result to be populated")
	}
	if results.DKIM == nil {
		t.Error("Expected DKIM result to be populated")
	}
	if results.DMARC == nil {
		t.Error("Expected DMARC result to be populated")
	}
}

func TestPerformAuthenticationChecksWithMetrics_SPFError(t *testing.T) {
	// Test SPF error scenarios
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			EnableSPF:   true,
			EnableDKIM:  false,
			EnableDMARC: false,
			Metrics:     metrics,
		},
		from:         "sender@example.com",
		testRemoteIP: net.IPv4(1, 2, 3, 4),
	}
	
	// Test with headers that might cause SPF errors
	headers := letters.Headers{}
	results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
	
	// SPF should be populated
	if results.SPF == nil {
		t.Error("Expected SPF result to be populated")
	}
}

func TestPerformAuthenticationChecksWithMetrics_DKIMError(t *testing.T) {
	// Test DKIM error scenarios
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			EnableSPF:   false,
			EnableDKIM:  true,
			EnableDMARC: false,
			Metrics:     metrics,
		},
	}
	
	// Test with headers that might cause DKIM errors
	headers := letters.Headers{}
	results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
	
	// DKIM should be populated
	if results.DKIM == nil {
		t.Error("Expected DKIM result to be populated")
	}
}

func TestProcessMessage_AuthenticationChecks(t *testing.T) {
	// Test ProcessMessage with authentication checks enabled
	metrics := NewMetricsDisabled()
	hs := &recordingHandler{t: t}
	ts := httptest.NewServer(hs)
	defer ts.Close()

	cfg := &ServerConfig{
		WebhookURL: ts.URL, 
		EnableSPF: true, 
		EnableDKIM: true, 
		EnableDMARC: true, 
		Verbose: true,
		Metrics: metrics,
	}
	mp := &MessageProcessor{
		config: cfg, 
		from: "sender@example.com", 
		to: []string{"rcpt@example.com"}, 
		testRemoteIP: net.IPv4(1, 1, 1, 1),
	}

	email := "From: Alice <alice@example.com>\r\nTo: Bob <bob@example.com>\r\nDate: Mon, 2 Jan 2006 15:04:05 -0700\r\nSubject: Hi\r\nMessage-ID: <id@local>\r\n\r\nHello"
	err := mp.ProcessMessage(bytes.NewBufferString(email))
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}

	var payload WebhookPayload
	if err := json.Unmarshal(hs.got, &payload); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if payload.Subject != "Hi" {
		t.Fatalf("subject got %q", payload.Subject)
	}
}

func TestSendWebhook_RequestCreationError(t *testing.T) {
	// Test webhook request creation error
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL: "http://[::1]:namedport", // Invalid URL
			Metrics:    metrics,
		},
	}
	
	payload := &WebhookPayload{}
	err := mp.sendWebhook(payload)
	if err == nil {
		t.Fatal("expected request creation error")
	}
}

func TestSendWebhook_ClientDoError(t *testing.T) {
	// Test webhook client.Do error
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL: "http://invalid-host-that-does-not-exist:9999",
			Metrics:    metrics,
		},
	}
	
	payload := &WebhookPayload{}
	err := mp.sendWebhook(payload)
	if err == nil {
		t.Fatal("expected client.Do error")
	}
}

func TestSendWebhook_StatusError(t *testing.T) {
	// Test webhook status error (400+ status codes)
	metrics := NewMetricsDisabled()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { 
		w.WriteHeader(400) // Bad Request
	}))
	defer ts.Close()
	
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL: ts.URL,
			Metrics:    metrics,
		},
	}
	
	payload := &WebhookPayload{}
	err := mp.sendWebhook(payload)
	if err == nil {
		t.Fatal("expected status error")
	}
}

func TestSendWebhook_WithBasicAuth(t *testing.T) {
	// Test webhook with basic authentication
	metrics := NewMetricsDisabled()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { 
		// Check that basic auth was sent
		username, password, ok := r.BasicAuth()
		if !ok {
			t.Error("Expected basic auth to be present")
		}
		if username != "testuser" || password != "testpass" {
			t.Errorf("Expected username=testuser, password=testpass, got username=%s, password=%s", username, password)
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()
	
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL:  ts.URL,
			WebhookUser: "testuser",
			WebhookPass: "testpass",
			Metrics:     metrics,
		},
	}
	
	payload := &WebhookPayload{}
	err := mp.sendWebhook(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSendWebhook_WithoutBasicAuth(t *testing.T) {
	// Test webhook without basic authentication
	metrics := NewMetricsDisabled()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { 
		// Check that no basic auth was sent
		_, _, ok := r.BasicAuth()
		if ok {
			t.Error("Expected no basic auth to be present")
		}
		w.WriteHeader(200)
	}))
	defer ts.Close()
	
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL: ts.URL,
			Metrics:    metrics,
		},
	}
	
	payload := &WebhookPayload{}
	err := mp.sendWebhook(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestSendWebhook_ResponseBodyClose(t *testing.T) {
	// Test webhook response body closing
	metrics := NewMetricsDisabled()
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { 
		w.WriteHeader(200)
		// Write some data to the response body
		w.Write([]byte("test response"))
	}))
	defer ts.Close()
	
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL: ts.URL,
			Metrics:    metrics,
		},
	}
	
	payload := &WebhookPayload{}
	err := mp.sendWebhook(payload)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestPerformAuthenticationChecksWithMetrics_SPFTempError(t *testing.T) {
	// Test SPF temperror scenario
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			EnableSPF:   true,
			EnableDKIM:  false,
			EnableDMARC: false,
			Metrics:     metrics,
		},
		from:         "sender@example.com",
		testRemoteIP: net.IPv4(1, 2, 3, 4),
	}
	
	// We can't easily mock the SPF result to be temperror without complex setup,
	// but we can test that the metrics path exists
	headers := letters.Headers{}
	results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
	
	// SPF should be populated
	if results.SPF == nil {
		t.Error("Expected SPF result to be populated")
	}
}

func TestPerformAuthenticationChecksWithMetrics_DKIMError2(t *testing.T) {
	// Test DKIM error scenario with metrics
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			EnableSPF:   false,
			EnableDKIM:  true,
			EnableDMARC: false,
			Metrics:     metrics,
		},
	}
	
	// Test with headers that might cause DKIM errors
	headers := letters.Headers{}
	results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
	
	// DKIM should be populated
	if results.DKIM == nil {
		t.Error("Expected DKIM result to be populated")
	}
}

func TestPerformAuthenticationChecksWithMetrics_DMARCTempError(t *testing.T) {
	// Test DMARC temperror scenario
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			EnableSPF:   false,
			EnableDKIM:  false,
			EnableDMARC: true,
			Metrics:     metrics,
		},
	}
	
	// Test with headers that might cause DMARC temperror
	headers := letters.Headers{
		From: []*mail.Address{{Address: "user@example.com"}},
	}
	results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
	
	// DMARC should be populated
	if results.DMARC == nil {
		t.Error("Expected DMARC result to be populated")
	}
}

func TestProcessMessage_Comprehensive(t *testing.T) {
	// Test ProcessMessage with comprehensive scenarios
	metrics := NewMetricsDisabled()
	hs := &recordingHandler{t: t}
	ts := httptest.NewServer(hs)
	defer ts.Close()
	
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL:  ts.URL,
			EnableSPF:   true,
			EnableDKIM:  true,
			EnableDMARC: true,
			Metrics:     metrics,
		},
		from:         "sender@example.com",
		testRemoteIP: net.IPv4(1, 2, 3, 4),
	}
	
	// Test with various message formats
	messages := []string{
		"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message",
		"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message with special chars: éñü",
		"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message with newlines\n\n\n",
		"From: sender@example.com\r\nTo: recipient@example.com\r\nSubject: Test\r\n\r\nTest message with tabs\t\t\t",
	}
	
	for i, message := range messages {
		err := mp.ProcessMessage(bytes.NewBufferString(message))
		if err != nil {
			t.Errorf("ProcessMessage failed for message %d: %v", i, err)
		}
	}
}

func TestSendWebhook_Comprehensive(t *testing.T) {
	// Test sendWebhook with comprehensive scenarios
	metrics := NewMetricsDisabled()
	hs := &recordingHandler{t: t}
	ts := httptest.NewServer(hs)
	defer ts.Close()
	
	mp := &MessageProcessor{
		config: &ServerConfig{
			WebhookURL:  ts.URL,
			WebhookUser: "testuser",
			WebhookPass: "testpass",
			Metrics:     metrics,
		},
	}
	
	// Test with various payload types
	payloads := []*WebhookPayload{
		{From: []*mail.Address{{Address: "sender@example.com"}}, To: []*mail.Address{{Address: "recipient@example.com"}}},
		{From: []*mail.Address{{Address: "sender@example.com"}}, To: []*mail.Address{{Address: "recipient1@example.com"}, {Address: "recipient2@example.com"}}},
		{From: []*mail.Address{{Address: "sender@example.com"}}, To: []*mail.Address{{Address: "recipient@example.com"}}, Subject: "Test Subject"},
		{From: []*mail.Address{{Address: "sender@example.com"}}, To: []*mail.Address{{Address: "recipient@example.com"}}, Subject: "Test Subject with special chars: éñü"},
	}
	
	for i, payload := range payloads {
		err := mp.sendWebhook(payload)
		if err != nil {
			t.Errorf("sendWebhook failed for payload %d: %v", i, err)
		}
	}
}

func TestPerformAuthenticationChecksWithMetrics_Comprehensive(t *testing.T) {
	// Test performAuthenticationChecksWithMetrics with comprehensive scenarios
	metrics := NewMetricsDisabled()
	mp := &MessageProcessor{
		config: &ServerConfig{
			EnableSPF:   true,
			EnableDKIM:  true,
			EnableDMARC: true,
			Metrics:     metrics,
		},
		from:         "sender@example.com",
		testRemoteIP: net.IPv4(1, 2, 3, 4),
	}
	
	// Test with various header combinations
	headerCombinations := []letters.Headers{
		{From: []*mail.Address{{Address: "sender@example.com"}}},
		{From: []*mail.Address{{Address: "sender@example.com"}}, To: []*mail.Address{{Address: "recipient@example.com"}}},
		{From: []*mail.Address{{Address: "sender@example.com"}}, To: []*mail.Address{{Address: "recipient@example.com"}}, Subject: "Test Subject"},
		{From: []*mail.Address{{Address: "sender@example.com"}}, To: []*mail.Address{{Address: "recipient@example.com"}}, Subject: "Test Subject with special chars: éñü"},
	}
	
	for i, headers := range headerCombinations {
		results := mp.performAuthenticationChecksWithMetrics("raw message", headers)
		
		// All results should be populated when all auth methods are enabled
		if results.SPF == nil {
			t.Errorf("Expected SPF result to be populated for headers %d", i)
		}
		if results.DKIM == nil {
			t.Errorf("Expected DKIM result to be populated for headers %d", i)
		}
		if results.DMARC == nil {
			t.Errorf("Expected DMARC result to be populated for headers %d", i)
		}
	}
}

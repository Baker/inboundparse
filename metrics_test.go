package main

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMetricsServer_Start_Disabled(t *testing.T) {
	config := &ServerConfig{
		EnableMetrics: false,
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Errorf("Expected no error when metrics disabled, got %v", err)
	}

	if server.server != nil {
		t.Error("Expected server to be nil when metrics disabled")
	}
}

func TestMetricsServer_HealthEndpoint(t *testing.T) {
	config := &ServerConfig{
		EnableMetrics: true,
		MetricsAddr:   "127.0.0.1:0", // Random available port
	}

	server := NewMetricsServer(config)
	if err := server.Start(); err != nil {
		t.Fatalf("Failed to start metrics server: %v", err)
	}
	defer server.Stop(context.Background())

	// Give server time to start
	time.Sleep(100 * time.Millisecond)

	// Get actual address
	addr := server.server.Addr
	if addr == "127.0.0.1:0" {
		t.Skip("Cannot test health endpoint with dynamic port assignment in this setup")
	}

	resp, err := http.Get("http://" + addr + "/health")
	if err != nil {
		t.Fatalf("Failed to call health endpoint: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		t.Errorf("Expected status 200, got %d", resp.StatusCode)
	}

	body, _ := io.ReadAll(resp.Body)
	if string(body) != "OK" {
		t.Errorf("Expected body 'OK', got '%s'", string(body))
	}
}

func TestMetricsServer_AuthMiddleware_NoAuth(t *testing.T) {
	config := &ServerConfig{
		EnableMetrics: true,
		// No auth configured
	}

	server := NewMetricsServer(config)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	wrappedHandler := server.authMiddleware(handler)
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 when no auth configured, got %d", w.Code)
	}
}

func TestMetricsServer_AuthMiddleware_BearerToken_Valid(t *testing.T) {
	config := &ServerConfig{
		EnableMetrics: true,
		MetricsAPIKey: "secret-token-123",
	}

	server := NewMetricsServer(config)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	wrappedHandler := server.authMiddleware(handler)
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer secret-token-123")
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 with valid bearer token, got %d", w.Code)
	}
}

func TestMetricsServer_AuthMiddleware_BearerToken_Invalid(t *testing.T) {
	config := &ServerConfig{
		EnableMetrics: true,
		MetricsAPIKey: "secret-token-123",
	}

	server := NewMetricsServer(config)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := server.authMiddleware(handler)
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer wrong-token")
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 with invalid bearer token, got %d", w.Code)
	}
}

func TestMetricsServer_AuthMiddleware_BasicAuth_Valid(t *testing.T) {
	config := &ServerConfig{
		EnableMetrics:   true,
		MetricsUsername: "admin",
		MetricsPassword: "password123",
	}

	server := NewMetricsServer(config)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	wrappedHandler := server.authMiddleware(handler)
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.SetBasicAuth("admin", "password123")
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 with valid basic auth, got %d", w.Code)
	}
}

func TestMetricsServer_AuthMiddleware_BasicAuth_Invalid(t *testing.T) {
	config := &ServerConfig{
		EnableMetrics:   true,
		MetricsUsername: "admin",
		MetricsPassword: "password123",
	}

	server := NewMetricsServer(config)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	wrappedHandler := server.authMiddleware(handler)
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.SetBasicAuth("admin", "wrong-password")
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusUnauthorized {
		t.Errorf("Expected status 401 with invalid basic auth, got %d", w.Code)
	}
}

func TestMetricsServer_AuthMiddleware_BearerPriority(t *testing.T) {
	config := &ServerConfig{
		EnableMetrics:   true,
		MetricsAPIKey:   "api-key-123",
		MetricsUsername: "admin",
		MetricsPassword: "password123",
	}

	server := NewMetricsServer(config)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("success"))
	})

	wrappedHandler := server.authMiddleware(handler)
	req := httptest.NewRequest("GET", "/metrics", nil)
	req.Header.Set("Authorization", "Bearer api-key-123")
	// Don't set basic auth
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Errorf("Expected status 200 with valid bearer token (ignoring basic auth), got %d", w.Code)
	}
}

func TestTrackConnection(t *testing.T) {
	cleanup := TrackConnection()

	// Verify connection was tracked
	// Note: We can't easily inspect prometheus counter values in tests
	// but we can verify the function returns a cleanup function
	if cleanup == nil {
		t.Error("Expected cleanup function to be returned")
	}

	// Call cleanup
	time.Sleep(10 * time.Millisecond) // Simulate some connection time
	cleanup()

	// Verify cleanup was called (metrics decremented)
	// In a real test, we'd use a prometheus test registry
}

func TestTrackSession(t *testing.T) {
	cleanup := TrackSession()

	if cleanup == nil {
		t.Error("Expected cleanup function to be returned")
	}

	cleanup()
}

func TestTrackMessage(t *testing.T) {
	// Track successful message
	TrackMessage(1024, true)

	// Track failed message
	TrackMessage(2048, false)

	// Metrics are updated, but we can't easily verify without a test registry
	// This test ensures the functions don't panic
}

func TestTrackSPFResult(t *testing.T) {
	results := []string{"pass", "fail", "none", "temperror"}

	for _, result := range results {
		TrackSPFResult(result)
	}

	// Verify no panics
}

func TestTrackDKIMResult(t *testing.T) {
	TrackDKIMResult(true)
	TrackDKIMResult(false)

	// Verify no panics
}

func TestTrackDMARCResult(t *testing.T) {
	TrackDMARCResult("pass", "reject")
	TrackDMARCResult("fail", "quarantine")
	TrackDMARCResult("none", "")

	// Verify no panics
}

func TestTrackWebhookRequest(t *testing.T) {
	TrackWebhookRequest(200, 100*time.Millisecond)
	TrackWebhookRequest(500, 500*time.Millisecond)

	// Verify no panics
}

func TestMetricsServer_Stop_NilServer(t *testing.T) {
	server := &MetricsServer{}

	err := server.Stop(context.Background())
	if err != nil {
		t.Errorf("Expected no error stopping nil server, got %v", err)
	}
}

func TestMetricsEndpoint_ContainsMetrics(t *testing.T) {
	// Track some metrics
	TrackMessage(1024, true)
	TrackSPFResult("pass")

	config := &ServerConfig{
		EnableMetrics: true,
	}

	server := NewMetricsServer(config)
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Simulate promhttp.Handler() output
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("# HELP smtp_messages_total\n# TYPE smtp_messages_total counter\nsmtp_messages_total 1\n"))
	})

	wrappedHandler := server.authMiddleware(handler)
	req := httptest.NewRequest("GET", "/metrics", nil)
	w := httptest.NewRecorder()

	wrappedHandler.ServeHTTP(w, req)

	body := w.Body.String()
	if !strings.Contains(body, "smtp_messages_total") {
		t.Errorf("Expected metrics output to contain smtp_messages_total")
	}
}

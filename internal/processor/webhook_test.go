package processor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
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

func TestWebhookSender_SendWebhook_Success(t *testing.T) {
	handler := &recordingHandler{t: t}
	server := httptest.NewServer(handler)
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}

	// Verify the payload was sent correctly
	var got map[string]interface{}
	if err := json.Unmarshal(handler.got, &got); err != nil {
		t.Fatalf("Failed to unmarshal payload: %v", err)
	}

	if got["test"] != "data" {
		t.Errorf("Expected test=data, got %v", got["test"])
	}
}

func TestWebhookSender_SendWebhook_WithAuth(t *testing.T) {
	handler := &recordingHandler{t: t}
	server := httptest.NewServer(handler)
	defer server.Close()

	config := WebhookConfig{
		URL:      server.URL,
		Username: "testuser",
		Password: "testpass",
		Timeout:  5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestWebhookSender_SendWebhook_ServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500)
	}))
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err == nil {
		t.Fatal("Expected error for 500 status")
	}
}

func TestWebhookSender_SendWebhook_Timeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(200)
	}))
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 100 * time.Millisecond,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err == nil {
		t.Fatal("Expected timeout error")
	}
}

func TestWebhookSender_SendWebhook_JSONMarshalError(t *testing.T) {
	config := WebhookConfig{
		URL:     "http://localhost:8080/webhook",
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	// Create a payload that will cause JSON marshal to fail
	payload := map[string]interface{}{
		"channel": make(chan int), // Channels cannot be marshaled to JSON
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err == nil {
		t.Fatal("Expected JSON marshal error")
	}
}

func TestWebhookSender_SendWebhook_RequestCreationError(t *testing.T) {
	config := WebhookConfig{
		URL:     "http://localhost:8080/webhook",
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	// Create a payload that will cause request creation to fail
	payload := map[string]interface{}{
		"test": "data",
	}

	// Test with invalid URL
	config.URL = "invalid-url"
	sender = NewWebhookSender(config)

	err := sender.SendWebhook(context.Background(), payload)
	if err == nil {
		t.Fatal("Expected request creation error")
	}
}

func TestWebhookSender_SendWebhook_ResponseBodyCloseError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(200)
		// Don't close the response body to simulate a close error
	}))
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestWebhookSender_SendWebhook_ErrorStatus(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(400) // Bad Request
	}))
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err == nil {
		t.Fatal("Expected error for 400 status")
	}
}

func TestWebhookSender_SendWebhook_NotFound(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(404) // Not Found
	}))
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err == nil {
		t.Fatal("Expected error for 404 status")
	}
}

func TestWebhookSender_SendWebhook_Unauthorized(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(401) // Unauthorized
	}))
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err == nil {
		t.Fatal("Expected error for 401 status")
	}
}

func TestWebhookSender_SendWebhook_Forbidden(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(403) // Forbidden
	}))
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err == nil {
		t.Fatal("Expected error for 403 status")
	}
}

func TestWebhookSender_SendWebhook_InternalServerError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(500) // Internal Server Error
	}))
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err == nil {
		t.Fatal("Expected error for 500 status")
	}
}

func TestWebhookSender_SendWebhook_BadGateway(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502) // Bad Gateway
	}))
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err == nil {
		t.Fatal("Expected error for 502 status")
	}
}

func TestWebhookSender_SendWebhook_ServiceUnavailable(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(503) // Service Unavailable
	}))
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err == nil {
		t.Fatal("Expected error for 503 status")
	}
}

func TestWebhookSender_SendWebhook_GatewayTimeout(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(504) // Gateway Timeout
	}))
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err == nil {
		t.Fatal("Expected error for 504 status")
	}
}

func TestWebhookSender_SendWebhook_NetworkError(t *testing.T) {
	config := WebhookConfig{
		URL:     "http://nonexistent-domain-that-should-fail.com/webhook",
		Timeout: 1 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err == nil {
		t.Fatal("Expected network error")
	}
}

func TestWebhookSender_SendWebhook_ContextCancellation(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(200)
	}))
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	// Create a cancelled context
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	err := sender.SendWebhook(ctx, payload)
	if err == nil {
		t.Fatal("Expected context cancellation error")
	}
}

func TestWebhookSender_SendWebhook_WithCustomHeaders(t *testing.T) {
	handler := &recordingHandler{t: t}
	server := httptest.NewServer(handler)
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{
		"test": "data",
	}

	err := sender.SendWebhook(context.Background(), payload)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestWebhookSender_SendWebhook_WithEmptyPayload(t *testing.T) {
	handler := &recordingHandler{t: t}
	server := httptest.NewServer(handler)
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	payload := map[string]interface{}{}

	err := sender.SendWebhook(context.Background(), payload)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

func TestWebhookSender_SendWebhook_WithNilPayload(t *testing.T) {
	handler := &recordingHandler{t: t}
	server := httptest.NewServer(handler)
	defer server.Close()

	config := WebhookConfig{
		URL:     server.URL,
		Timeout: 5 * time.Second,
	}

	sender := NewWebhookSender(config)

	var payload interface{} = nil

	err := sender.SendWebhook(context.Background(), payload)
	if err != nil {
		t.Fatalf("Expected no error, got %v", err)
	}
}

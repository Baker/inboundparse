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

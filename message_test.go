package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"testing"
	"time"

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

func TestPerformAuthenticationChecks_Flags(t *testing.T) {
	mp := &MessageProcessor{config: &ServerConfig{EnableSPF: true, EnableDKIM: true, EnableDMARC: true}}
	// Use minimal headers to exercise DMARC path early
	h := letters.Headers{}
	_ = mp.performAuthenticationChecks("raw", h)
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

func TestProcessMessage_ParseError(t *testing.T) {
	mp := &MessageProcessor{config: &ServerConfig{WebhookURL: "http://127.0.0.1:1"}}
	// malformed email to trigger parse failure (no headers/body separation)
	bad := bytes.NewBufferString("\xff\xfe\xfd")
	if err := mp.ProcessMessage(bad); err == nil {
		t.Fatal("expected parse error")
	}
}

package service

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/mail"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestWebhookService_SendWebhook(t *testing.T) {
	tests := []struct {
		name           string
		payload        *WebhookPayload
		serverResponse int
		serverBody     string
		username       string
		password       string
		wantErr        bool
	}{
		{
			name: "successful webhook",
			payload: &WebhookPayload{
				From:      []*mail.Address{{Address: "test@example.com"}},
				To:        []*mail.Address{{Address: "recipient@example.com"}},
				Subject:   "Test Subject",
				Body:      "Test Body",
				Headers:   map[string]string{"Message-ID": "test-id"},
				RemoteIP:  "127.0.0.1",
				Timestamp: time.Now(),
			},
			serverResponse: http.StatusOK,
			serverBody:     "OK",
			username:       "",
			password:       "",
			wantErr:        false,
		},
		{
			name: "webhook with basic auth",
			payload: &WebhookPayload{
				From:      []*mail.Address{{Address: "test@example.com"}},
				To:        []*mail.Address{{Address: "recipient@example.com"}},
				Subject:   "Test Subject",
				Body:      "Test Body",
				Headers:   map[string]string{"Message-ID": "test-id"},
				RemoteIP:  "127.0.0.1",
				Timestamp: time.Now(),
			},
			serverResponse: http.StatusOK,
			serverBody:     "OK",
			username:       "testuser",
			password:       "testpass",
			wantErr:        false,
		},
		{
			name: "webhook server error",
			payload: &WebhookPayload{
				From:      []*mail.Address{{Address: "test@example.com"}},
				To:        []*mail.Address{{Address: "recipient@example.com"}},
				Subject:   "Test Subject",
				Body:      "Test Body",
				Headers:   map[string]string{"Message-ID": "test-id"},
				RemoteIP:  "127.0.0.1",
				Timestamp: time.Now(),
			},
			serverResponse: http.StatusInternalServerError,
			serverBody:     "Internal Server Error",
			username:       "",
			password:       "",
			wantErr:        true,
		},
		{
			name: "webhook server not found",
			payload: &WebhookPayload{
				From:      []*mail.Address{{Address: "test@example.com"}},
				To:        []*mail.Address{{Address: "recipient@example.com"}},
				Subject:   "Test Subject",
				Body:      "Test Body",
				Headers:   map[string]string{"Message-ID": "test-id"},
				RemoteIP:  "127.0.0.1",
				Timestamp: time.Now(),
			},
			serverResponse: http.StatusNotFound,
			serverBody:     "Not Found",
			username:       "",
			password:       "",
			wantErr:        true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create test server
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				// Check basic auth if provided
				if tt.username != "" && tt.password != "" {
					username, password, ok := r.BasicAuth()
					if !ok || username != tt.username || password != tt.password {
						w.WriteHeader(http.StatusUnauthorized)
						return
					}
				}

				// Check content type
				if r.Header.Get("Content-Type") != "application/json" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				// Check user agent
				if r.Header.Get("User-Agent") != "inboundparse/1.0" {
					w.WriteHeader(http.StatusBadRequest)
					return
				}

				w.WriteHeader(tt.serverResponse)
				w.Write([]byte(tt.serverBody))
			}))
			defer server.Close()

			// Create webhook service
			webhookService := NewWebhookService(server.URL, tt.username, tt.password)

			// Send webhook
			ctx := context.Background()
			err := webhookService.SendWebhook(ctx, tt.payload)

			if tt.wantErr {
				assert.Error(t, err)
			} else {
				assert.NoError(t, err)
			}
		})
	}
}

func TestWebhookService_SendWebhook_InvalidURL(t *testing.T) {
	webhookService := NewWebhookService("invalid-url", "", "")
	payload := &WebhookPayload{
		From:      []*mail.Address{{Address: "test@example.com"}},
		To:        []*mail.Address{{Address: "recipient@example.com"}},
		Subject:   "Test Subject",
		Body:      "Test Body",
		Headers:   map[string]string{"Message-ID": "test-id"},
		RemoteIP:  "127.0.0.1",
		Timestamp: time.Now(),
	}

	ctx := context.Background()
	err := webhookService.SendWebhook(ctx, payload)
	assert.Error(t, err, "SendWebhook() expected error for invalid URL")
}

func TestWebhookService_SendWebhook_ContextCancellation(t *testing.T) {
	// Create test server that takes a long time to respond
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(2 * time.Second)
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()

	webhookService := NewWebhookService(server.URL, "", "")
	payload := &WebhookPayload{
		From:      []*mail.Address{{Address: "test@example.com"}},
		To:        []*mail.Address{{Address: "recipient@example.com"}},
		Subject:   "Test Subject",
		Body:      "Test Body",
		Headers:   map[string]string{"Message-ID": "test-id"},
		RemoteIP:  "127.0.0.1",
		Timestamp: time.Now(),
	}

	// Create context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	err := webhookService.SendWebhook(ctx, payload)
	assert.Error(t, err, "SendWebhook() expected error for context cancellation")
}
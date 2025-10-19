package service

import (
	"context"
	"net"
)

// mockWebhookService is a mock implementation of WebhookService for tests
type mockWebhookService struct {
	sendWebhookFunc func(ctx context.Context, payload *WebhookPayload) error
}

func (m *mockWebhookService) SendWebhook(ctx context.Context, payload *WebhookPayload) error {
	if m.sendWebhookFunc != nil {
		return m.sendWebhookFunc(ctx, payload)
	}
	return nil
}

// mockAuthService is a mock implementation of AuthService for tests
type mockAuthService struct {
	performAuthChecksFunc func(ctx context.Context, message []byte, remoteIP net.IP) (*AuthResult, error)
}

func (m *mockAuthService) PerformAuthenticationChecks(ctx context.Context, message []byte, remoteIP net.IP) (*AuthResult, error) {
	if m.performAuthChecksFunc != nil {
		return m.performAuthChecksFunc(ctx, message, remoteIP)
	}
	return &AuthResult{}, nil
}

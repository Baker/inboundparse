package service

import (
	"context"
	"net"

	"go.uber.org/zap"
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

// mockLoggerService is a mock implementation of LoggerService for tests
type mockLoggerService struct{}

func (m *mockLoggerService) Info(ctx context.Context, msg string, fields ...zap.Field)  {}
func (m *mockLoggerService) Error(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerService) Warn(ctx context.Context, msg string, fields ...zap.Field)  {}
func (m *mockLoggerService) Debug(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerService) Fatal(ctx context.Context, msg string, fields ...zap.Field) {}
func (m *mockLoggerService) With(fields ...zap.Field) LoggerService {
	return m
}

func (m *mockLoggerService) WithContext(ctx context.Context) LoggerService {
	return m
}

func (m *mockLoggerService) Close() error {
	return nil
}

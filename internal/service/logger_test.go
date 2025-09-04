package service

import (
	"context"
	"strings"
	"testing"

	"go.uber.org/zap"
)

func TestNewLoggerService(t *testing.T) {
	tests := []struct {
		name    string
		verbose bool
		wantErr bool
	}{
		{
			name:    "development logger",
			verbose: true,
			wantErr: false,
		},
		{
			name:    "production logger",
			verbose: false,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, err := NewLoggerService(tt.verbose)
			if (err != nil) != tt.wantErr {
				t.Errorf("NewLoggerService() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if logger == nil {
				t.Error("NewLoggerService() returned nil logger")
			}
		})
	}
}

func TestLoggerService_WithContext(t *testing.T) {
	tests := []struct {
		name        string
		ctx         context.Context
		correlationID string
		requestID   string
		userID      string
	}{
		{
			name:        "empty context",
			ctx:         context.Background(),
			correlationID: "",
			requestID:   "",
			userID:      "",
		},
		{
			name:        "context with correlation ID",
			ctx:         WithCorrelationID(context.Background(), "test-correlation-id"),
			correlationID: "test-correlation-id",
			requestID:   "",
			userID:      "",
		},
		{
			name:        "context with request ID",
			ctx:         WithRequestID(context.Background(), "test-request-id"),
			correlationID: "",
			requestID:   "test-request-id",
			userID:      "",
		},
		{
			name:        "context with user ID",
			ctx:         WithUserID(context.Background(), "test-user-id"),
			correlationID: "",
			requestID:   "",
			userID:      "test-user-id",
		},
		{
			name:        "context with all IDs",
			ctx:         WithUserID(WithRequestID(WithCorrelationID(context.Background(), "test-correlation-id"), "test-request-id"), "test-user-id"),
			correlationID: "test-correlation-id",
			requestID:   "test-request-id",
			userID:      "test-user-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewNopLogger()
			ctxLogger := logger.WithContext(tt.ctx)

			if ctxLogger == nil {
				t.Error("WithContext() returned nil logger")
			}
		})
	}
}

func TestLoggerService_With(t *testing.T) {
	tests := []struct {
		name   string
		fields []zap.Field
	}{
		{
			name:   "no fields",
			fields: []zap.Field{},
		},
		{
			name:   "single field",
			fields: []zap.Field{zap.String("key", "value")},
		},
		{
			name:   "multiple fields",
			fields: []zap.Field{
				zap.String("key1", "value1"),
				zap.Int("key2", 42),
				zap.Bool("key3", true),
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger := NewNopLogger()
			withLogger := logger.With(tt.fields...)

			if withLogger == nil {
				t.Error("With() returned nil logger")
			}
		})
	}
}

func TestWithCorrelationID(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{
			name: "empty ID",
			id:   "",
		},
		{
			name: "valid ID",
			id:   "test-correlation-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithCorrelationID(context.Background(), tt.id)
			if ctx == nil {
				t.Error("WithCorrelationID() returned nil context")
			}

			// Verify the value is stored in context
			if value := ctx.Value(CorrelationIDKey); value != tt.id {
				t.Errorf("WithCorrelationID() stored %v, want %v", value, tt.id)
			}
		})
	}
}

func TestWithRequestID(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{
			name: "empty ID",
			id:   "",
		},
		{
			name: "valid ID",
			id:   "test-request-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithRequestID(context.Background(), tt.id)
			if ctx == nil {
				t.Error("WithRequestID() returned nil context")
			}

			// Verify the value is stored in context
			if value := ctx.Value(RequestIDKey); value != tt.id {
				t.Errorf("WithRequestID() stored %v, want %v", value, tt.id)
			}
		})
	}
}

func TestWithUserID(t *testing.T) {
	tests := []struct {
		name string
		id   string
	}{
		{
			name: "empty ID",
			id:   "",
		},
		{
			name: "valid ID",
			id:   "test-user-id",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := WithUserID(context.Background(), tt.id)
			if ctx == nil {
				t.Error("WithUserID() returned nil context")
			}

			// Verify the value is stored in context
			if value := ctx.Value(UserIDKey); value != tt.id {
				t.Errorf("WithUserID() stored %v, want %v", value, tt.id)
			}
		})
	}
}

func TestLoggerService_LoggingMethods(t *testing.T) {
	tests := []struct {
		name     string
		level    string
		format   string
		expected bool
	}{
		{
			name:     "development logger",
			level:    "debug",
			format:   "console",
			expected: true,
		},
		{
			name:     "production logger",
			level:    "info",
			format:   "json",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			logger, _ := NewLoggerService(tt.level == "debug")
			if logger == nil {
				t.Error("NewLoggerService() returned nil")
			}

			ctx := context.Background()

			// Test all logging methods (except Fatal which would exit the program)
			logger.Info(ctx, "test info message")
			logger.Error(ctx, "test error message")
			logger.Warn(ctx, "test warn message")
			logger.Debug(ctx, "test debug message")
			// Note: Fatal is not tested as it would exit the program

			// Test Close method (ignore sync errors in test environment)
			err := logger.Close()
			if err != nil && !strings.Contains(err.Error(), "sync") {
				t.Errorf("Close() error = %v", err)
			}
		})
	}
}

func TestNewDevelopmentLogger(t *testing.T) {
	logger := NewDevelopmentLogger()
	if logger == nil {
		t.Error("NewDevelopmentLogger() returned nil")
	}

	// Test that it can be closed (ignore sync errors in test environment)
	err := logger.Close()
	if err != nil && !strings.Contains(err.Error(), "sync") {
		t.Errorf("Close() error = %v", err)
	}
}

func TestNewProductionLogger(t *testing.T) {
	logger := NewProductionLogger()
	if logger == nil {
		t.Error("NewProductionLogger() returned nil")
	}

	// Test that it can be closed (ignore sync errors in test environment)
	err := logger.Close()
	if err != nil && !strings.Contains(err.Error(), "sync") {
		t.Errorf("Close() error = %v", err)
	}
}

// TestLoggerService_Fatal is skipped because Fatal calls os.Exit() which terminates the test
// In a real test environment, you'd need to use subprocess testing to test the exit behavior
func TestLoggerService_Fatal_Skipped(t *testing.T) {
	t.Skip("Fatal method calls os.Exit() which terminates the test process")
}

func TestLoggerService_GetContextFields(t *testing.T) {
	logger, _ := NewLoggerService(false)
	if logger == nil {
		t.Error("NewLoggerService() returned nil")
	}

	// Test with various context scenarios
	tests := []struct {
		name string
		ctx  context.Context
	}{
		{
			name: "empty context",
			ctx:  context.Background(),
		},
		{
			name: "context with correlation ID",
			ctx:  WithCorrelationID(context.Background(), "test-correlation-id"),
		},
		{
			name: "context with request ID",
			ctx:  WithRequestID(context.Background(), "test-request-id"),
		},
		{
			name: "context with user ID",
			ctx:  WithUserID(context.Background(), "test-user-id"),
		},
		{
			name: "context with all IDs",
			ctx: func() context.Context {
				ctx := WithCorrelationID(context.Background(), "test-correlation-id")
				ctx = WithRequestID(ctx, "test-request-id")
				ctx = WithUserID(ctx, "test-user-id")
				return ctx
			}(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Test WithContext method which uses getContextFields internally
			contextLogger := logger.WithContext(tt.ctx)
			if contextLogger == nil {
				t.Error("WithContext() returned nil")
			}

			// Test With method
			withLogger := logger.With(zap.String("test", "value"))
			if withLogger == nil {
				t.Error("With() returned nil")
			}
		})
	}

	// Test that it can be closed (ignore sync errors in test environment)
	err := logger.Close()
	if err != nil && !strings.Contains(err.Error(), "sync") {
		t.Errorf("Close() error = %v", err)
	}
}
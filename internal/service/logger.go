package service

import (
	"context"

	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
)

// LoggerService defines the interface for structured logging
type LoggerService interface {
	Info(ctx context.Context, msg string, fields ...zap.Field)
	Error(ctx context.Context, msg string, fields ...zap.Field)
	Warn(ctx context.Context, msg string, fields ...zap.Field)
	Debug(ctx context.Context, msg string, fields ...zap.Field)
	Fatal(ctx context.Context, msg string, fields ...zap.Field)
	With(fields ...zap.Field) LoggerService
	WithContext(ctx context.Context) LoggerService
	Close() error
}

// loggerService implements the LoggerService interface
type loggerService struct {
	logger *zap.Logger
}

// NewLoggerService creates a new structured logger service
func NewLoggerService(verbose bool) (LoggerService, error) {
	var config zap.Config

	if verbose {
		// Development configuration
		config = zap.NewDevelopmentConfig()
		config.EncoderConfig.EncodeLevel = zapcore.CapitalColorLevelEncoder
		// In development, show stack traces for errors
		config.Development = true
	} else {
		// Production configuration
		config = zap.NewProductionConfig()
		config.EncoderConfig.TimeKey = "timestamp"
		config.EncoderConfig.EncodeTime = zapcore.ISO8601TimeEncoder

		// Disable stack traces for Error level in production (only for DPanic/Panic/Fatal)
		config.DisableStacktrace = false

		// Enable sampling to reduce log volume
		config.Sampling = &zap.SamplingConfig{
			Initial:    100, // Log first 100 entries per second
			Thereafter: 100, // Then 1 in every 100
		}

		// Disable caller info in production for cleaner logs
		config.DisableCaller = true
	}

	// Add custom fields
	config.InitialFields = map[string]interface{}{
		"service": "inboundparse",
		"version": "1.0.0",
	}

	// Build logger with options to control stack traces
	logger, err := config.Build(
		// Only add stack traces for DPanic and above (not for Error)
		zap.AddStacktrace(zapcore.DPanicLevel),
	)
	if err != nil {
		return nil, err
	}

	// Replace global logger
	zap.ReplaceGlobals(logger)

	return &loggerService{logger: logger}, nil
}

// Info logs an info message
func (l *loggerService) Info(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, l.getContextFields(ctx)...)
	l.logger.Info(msg, fields...)
}

// Error logs an error message
func (l *loggerService) Error(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, l.getContextFields(ctx)...)
	l.logger.Error(msg, fields...)
}

// Warn logs a warning message
func (l *loggerService) Warn(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, l.getContextFields(ctx)...)
	l.logger.Warn(msg, fields...)
}

// Debug logs a debug message
func (l *loggerService) Debug(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, l.getContextFields(ctx)...)
	l.logger.Debug(msg, fields...)
}

// Fatal logs a fatal message and exits
func (l *loggerService) Fatal(ctx context.Context, msg string, fields ...zap.Field) {
	fields = append(fields, l.getContextFields(ctx)...)
	l.logger.Fatal(msg, fields...)
}

// With creates a new logger with additional fields
func (l *loggerService) With(fields ...zap.Field) LoggerService {
	return &loggerService{logger: l.logger.With(fields...)}
}

// WithContext creates a new logger with context fields
func (l *loggerService) WithContext(ctx context.Context) LoggerService {
	return &loggerService{logger: l.logger.With(l.getContextFields(ctx)...)}
}

// getContextFields extracts fields from context
func (l *loggerService) getContextFields(ctx context.Context) []zap.Field {
	var fields []zap.Field

	// Add correlation ID if present
	if correlationID := ctx.Value("correlation_id"); correlationID != nil {
		if id, ok := correlationID.(string); ok {
			fields = append(fields, zap.String("correlation_id", id))
		}
	}

	// Add request ID if present
	if requestID := ctx.Value("request_id"); requestID != nil {
		if id, ok := requestID.(string); ok {
			fields = append(fields, zap.String("request_id", id))
		}
	}

	// Add user ID if present
	if userID := ctx.Value("user_id"); userID != nil {
		if id, ok := userID.(string); ok {
			fields = append(fields, zap.String("user_id", id))
		}
	}

	return fields
}

// NewDevelopmentLogger creates a development logger
func NewDevelopmentLogger() LoggerService {
	logger, _ := zap.NewDevelopment()
	return &loggerService{logger: logger}
}

// NewProductionLogger creates a production logger
func NewProductionLogger() LoggerService {
	logger, _ := zap.NewProduction()
	return &loggerService{logger: logger}
}

// NewNopLogger creates a no-op logger for testing
func NewNopLogger() LoggerService {
	return &loggerService{logger: zap.NewNop()}
}

// Context keys for structured logging
type contextKey string

const (
	CorrelationIDKey contextKey = "correlation_id"
	RequestIDKey     contextKey = "request_id"
	UserIDKey        contextKey = "user_id"
)

// WithCorrelationID adds a correlation ID to context
func WithCorrelationID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, CorrelationIDKey, id)
}

// WithRequestID adds a request ID to context
func WithRequestID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, RequestIDKey, id)
}

// WithUserID adds a user ID to context
func WithUserID(ctx context.Context, id string) context.Context {
	return context.WithValue(ctx, UserIDKey, id)
}

// Close closes the logger and flushes any buffered log entries
func (l *loggerService) Close() error {
	return l.logger.Sync()
}

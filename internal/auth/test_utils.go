package auth

import (
	"io"

	"github.com/rs/zerolog"
)

// MockLogger implements observability.Logger for testing
type MockLogger struct{}

func (m *MockLogger) Debug() *zerolog.Event {
	// Return a properly initialized zerolog event that discards output
	logger := zerolog.New(io.Discard)
	return logger.Debug()
}

func (m *MockLogger) Info() *zerolog.Event {
	logger := zerolog.New(io.Discard)
	return logger.Info()
}

func (m *MockLogger) Warn() *zerolog.Event {
	logger := zerolog.New(io.Discard)
	return logger.Warn()
}

func (m *MockLogger) Error() *zerolog.Event {
	logger := zerolog.New(io.Discard)
	return logger.Error()
}

func (m *MockLogger) Fatal() *zerolog.Event {
	logger := zerolog.New(io.Discard)
	return logger.Fatal()
}

func (m *MockLogger) With() zerolog.Context {
	// Return a no-op context for testing
	logger := zerolog.New(io.Discard)
	return logger.With()
}

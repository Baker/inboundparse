package config

import (
	"testing"
)

func TestNew(t *testing.T) {
	config := New()

	if config.ListenAddr != DefaultListenAddr {
		t.Errorf("Expected ListenAddr %s, got %s", DefaultListenAddr, config.ListenAddr)
	}

	if config.ListenAddrTLS != DefaultListenAddrTLS {
		t.Errorf("Expected ListenAddrTLS %s, got %s", DefaultListenAddrTLS, config.ListenAddrTLS)
	}

	if config.MaxMessageSize != DefaultMaxMessageSize {
		t.Errorf("Expected MaxMessageSize %d, got %d", DefaultMaxMessageSize, config.MaxMessageSize)
	}

	if config.ReadTimeout != DefaultReadTimeout {
		t.Errorf("Expected ReadTimeout %v, got %v", DefaultReadTimeout, config.ReadTimeout)
	}

	if config.WriteTimeout != DefaultWriteTimeout {
		t.Errorf("Expected WriteTimeout %v, got %v", DefaultWriteTimeout, config.WriteTimeout)
	}
}

func TestWithOptions(t *testing.T) {
	config := New(
		WithListenAddr(":2525"),
		WithWebhookURL("http://test.com/webhook"),
		WithVerbose(true),
	)

	if config.ListenAddr != ":2525" {
		t.Errorf("Expected ListenAddr :2525, got %s", config.ListenAddr)
	}

	if config.WebhookURL != "http://test.com/webhook" {
		t.Errorf("Expected WebhookURL http://test.com/webhook, got %s", config.WebhookURL)
	}

	if !config.Verbose {
		t.Error("Expected Verbose to be true")
	}
}

func TestValidate(t *testing.T) {
	tests := []struct {
		name    string
		config  *Config
		wantErr bool
	}{
		{
			name: "valid config",
			config: &Config{
				WebhookURL: "http://test.com/webhook",
			},
			wantErr: false,
		},
		{
			name: "missing webhook URL",
			config: &Config{
				WebhookURL: "",
			},
			wantErr: true,
		},
		{
			name: "cert file without key file",
			config: &Config{
				WebhookURL: "http://test.com/webhook",
				CertFile:   "cert.pem",
				KeyFile:    "",
			},
			wantErr: true,
		},
		{
			name: "key file without cert file",
			config: &Config{
				WebhookURL: "http://test.com/webhook",
				CertFile:   "",
				KeyFile:    "key.pem",
			},
			wantErr: true,
		},
		{
			name: "sentry enabled without DSN",
			config: &Config{
				WebhookURL:   "http://test.com/webhook",
				EnableSentry: true,
				SentryDSN:    "",
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

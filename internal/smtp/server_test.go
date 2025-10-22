package smtp

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"inboundparse/internal/domain"
	"inboundparse/internal/observability"
	"inboundparse/internal/processor"
	"io"
	"math/big"
	"net"
	"os"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
	"github.com/mnako/letters"
)

// Helper functions and mocks

func createTempCertFiles(t *testing.T) (string, string) {
	// Generate a private key
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("Failed to generate private key: %v", err)
	}

	// Create a self-signed certificate
	template := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	// Create temporary files
	certFile, err := os.CreateTemp("", "test-cert-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp cert file: %v", err)
	}
	defer certFile.Close()

	keyFile, err := os.CreateTemp("", "test-key-*.pem")
	if err != nil {
		t.Fatalf("Failed to create temp key file: %v", err)
	}
	defer keyFile.Close()

	// Write certificate
	if err := pem.Encode(certFile, &pem.Block{Type: "CERTIFICATE", Bytes: certDER}); err != nil {
		t.Fatalf("Failed to encode certificate: %v", err)
	}

	// Write private key
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		t.Fatalf("Failed to marshal private key: %v", err)
	}
	if err := pem.Encode(keyFile, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
		t.Fatalf("Failed to encode private key: %v", err)
	}

	return certFile.Name(), keyFile.Name()
}

// createMockBackend creates a mock backend for testing
func createMockBackend() *Backend {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := observability.NewMetricsCollector()
	logger := observability.DefaultLogger()

	return NewBackend(config, messageProcessor, metrics, logger)
}

// createMockMessageProcessor creates a mock message processor for testing
func createMockMessageProcessor() *processor.MessageProcessor {
	// Create a minimal processor config
	config := processor.ProcessorConfig{
		EnableSPF:   false,
		EnableDKIM:  false,
		EnableDMARC: false,
	}

	// Create mock dependencies
	authChecker := &mockAuthChecker{}
	webhookSender := &mockWebhookSender{}
	metrics := observability.NewMetricsCollector()
	sentry := observability.NewSentryClient()
	logger := observability.DefaultLogger()

	return processor.NewMessageProcessor(
		config,
		authChecker,
		webhookSender,
		metrics,
		sentry,
		logger,
	)
}

// Mock auth checker for testing
type mockAuthChecker struct{}

func (m *mockAuthChecker) CheckSPF(ctx context.Context, remoteIP net.IP, domainName, from string) (*domain.SPFResult, error) {
	return nil, nil
}

func (m *mockAuthChecker) CheckDKIM(ctx context.Context, rawMessage string) (*domain.DKIMResult, error) {
	return nil, nil
}

func (m *mockAuthChecker) CheckDMARC(ctx context.Context, rawMessage string, headers letters.Headers, spfResult *domain.SPFResult, dkimResult *domain.DKIMResult) (*domain.DMARCResult, error) {
	return nil, nil
}

// Mock webhook sender for testing
type mockWebhookSender struct{}

func (m *mockWebhookSender) SendWebhook(ctx context.Context, payload interface{}) error {
	return nil
}

// Mock session for testing
type mockSession struct{}

func (m *mockSession) AuthPlain(username, password string) error      { return nil }
func (m *mockSession) Mail(from string, opts *smtp.MailOptions) error { return nil }
func (m *mockSession) Rcpt(to string, opts *smtp.RcptOptions) error   { return nil }
func (m *mockSession) Data(r io.Reader) error                         { return nil }
func (m *mockSession) Reset()                                         {}
func (m *mockSession) Logout() error                                  { return nil }

// Mock app config for testing
type mockAppConfig struct {
	ListenAddr     string
	ListenAddrTLS  string
	ServerName     string
	MaxMessageSize int64
	ReadTimeout    time.Duration
	WriteTimeout   time.Duration
	CertFile       string
	KeyFile        string
}

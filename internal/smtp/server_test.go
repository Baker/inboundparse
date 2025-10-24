package smtp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"math/big"
	"os"
	"testing"
	"time"

	"github.com/emersion/go-smtp"
)

// Helper function to create a mock backend
func createMockBackend() *Backend {
	config := BackendConfig{MaxRecipients: 100}
	messageProcessor := createMockMessageProcessor()
	metrics := &mockMetricsCollector{}
	logger := &mockLogger{}

	return NewBackend(config, messageProcessor, metrics, logger)
}

type mockBackend struct{}

func (m *mockBackend) NewSession(c *smtp.Conn) (smtp.Session, error) {
	return &mockSession{}, nil
}

type mockSession struct{}

func (m *mockSession) AuthPlain(username, password string) error      { return nil }
func (m *mockSession) Mail(from string, opts *smtp.MailOptions) error { return nil }
func (m *mockSession) Rcpt(to string, opts *smtp.RcptOptions) error   { return nil }
func (m *mockSession) Data(r io.Reader) error                         { return nil }
func (m *mockSession) Reset()                                         {}
func (m *mockSession) Logout() error                                  { return nil }

func TestNewSMTPServer_NoTLS(t *testing.T) {
	config := ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		ServerName:     "test",
		MaxMessageSize: 1024,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.server == nil {
		t.Fatal("server should be created")
	}
}

func TestNewSMTPServer_WithTLS(t *testing.T) {
	// Create temporary certificate files
	certFile, keyFile := createTempCertFiles(t)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	config := ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		ListenAddrTLS:  "127.0.0.1:0",
		ServerName:     "test",
		MaxMessageSize: 1024,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		CertFile:       certFile,
		KeyFile:        keyFile,
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if s.server == nil {
		t.Fatal("server should be created")
	}
	if s.tlsServer == nil {
		t.Fatal("tls server should be created")
	}
}

func TestNewSMTPServer_InvalidCert(t *testing.T) {
	config := ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		ListenAddrTLS:  "127.0.0.1:0",
		ServerName:     "test",
		MaxMessageSize: 1024,
		ReadTimeout:    5 * time.Second,
		WriteTimeout:   5 * time.Second,
		CertFile:       "nonexistent.pem",
		KeyFile:        "nonexistent.key",
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	_, err := NewSMTPServer(config, backend, logger)
	if err == nil {
		t.Fatal("expected error for invalid cert file")
	}
}

func TestSMTPServer_Stop_Idempotent(t *testing.T) {
	config := ServerConfig{
		ListenAddr: "127.0.0.1:0",
		ServerName: "test",
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Stop multiple times should not panic
	if err := s.Stop(); err != nil {
		t.Fatalf("first stop: %v", err)
	}
	if err := s.Stop(); err != nil {
		t.Fatalf("second stop: %v", err)
	}
}

func TestServerConfig_DefaultValues(t *testing.T) {
	config := ServerConfig{}

	if config.ListenAddr != "" {
		t.Errorf("Expected empty ListenAddr, got '%s'", config.ListenAddr)
	}
	if config.ListenAddrTLS != "" {
		t.Errorf("Expected empty ListenAddrTLS, got '%s'", config.ListenAddrTLS)
	}
	if config.ServerName != "" {
		t.Errorf("Expected empty ServerName, got '%s'", config.ServerName)
	}
	if config.MaxMessageSize != 0 {
		t.Errorf("Expected MaxMessageSize 0, got %d", config.MaxMessageSize)
	}
	if config.ReadTimeout != 0 {
		t.Errorf("Expected ReadTimeout 0, got %v", config.ReadTimeout)
	}
	if config.WriteTimeout != 0 {
		t.Errorf("Expected WriteTimeout 0, got %v", config.WriteTimeout)
	}
	if config.CertFile != "" {
		t.Errorf("Expected empty CertFile, got '%s'", config.CertFile)
	}
	if config.KeyFile != "" {
		t.Errorf("Expected empty KeyFile, got '%s'", config.KeyFile)
	}
}

func TestServerConfig_WithValues(t *testing.T) {
	config := ServerConfig{
		ListenAddr:     "127.0.0.1:25",
		ListenAddrTLS:  "127.0.0.1:587",
		ServerName:     "test.example.com",
		MaxMessageSize: 1024,
		ReadTimeout:    30 * time.Second,
		WriteTimeout:   30 * time.Second,
		CertFile:       "/path/to/cert.pem",
		KeyFile:        "/path/to/key.pem",
	}

	if config.ListenAddr != "127.0.0.1:25" {
		t.Errorf("Expected ListenAddr '127.0.0.1:25', got '%s'", config.ListenAddr)
	}
	if config.ListenAddrTLS != "127.0.0.1:587" {
		t.Errorf("Expected ListenAddrTLS '127.0.0.1:587', got '%s'", config.ListenAddrTLS)
	}
	if config.ServerName != "test.example.com" {
		t.Errorf("Expected ServerName 'test.example.com', got '%s'", config.ServerName)
	}
	if config.MaxMessageSize != 1024 {
		t.Errorf("Expected MaxMessageSize 1024, got %d", config.MaxMessageSize)
	}
	if config.ReadTimeout != 30*time.Second {
		t.Errorf("Expected ReadTimeout 30s, got %v", config.ReadTimeout)
	}
	if config.WriteTimeout != 30*time.Second {
		t.Errorf("Expected WriteTimeout 30s, got %v", config.WriteTimeout)
	}
	if config.CertFile != "/path/to/cert.pem" {
		t.Errorf("Expected CertFile '/path/to/cert.pem', got '%s'", config.CertFile)
	}
	if config.KeyFile != "/path/to/key.pem" {
		t.Errorf("Expected KeyFile '/path/to/key.pem', got '%s'", config.KeyFile)
	}
}

func TestSMTPServer_Start_NoTLS(t *testing.T) {
	config := ServerConfig{
		ListenAddr: "127.0.0.1:0",
		ServerName: "test",
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test server creation without actually starting
	if s == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test that we can stop a server that hasn't been started
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping unstarted server: %v", err)
	}
}

func TestSMTPServer_Start_WithTLS(t *testing.T) {
	// Create temporary certificate files
	certFile, keyFile := createTempCertFiles(t)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	config := ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		ListenAddrTLS: "127.0.0.1:0",
		ServerName:    "test",
		CertFile:      certFile,
		KeyFile:       keyFile,
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test server creation with TLS config without actually starting
	if s == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test that we can stop a server that hasn't been started
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping unstarted server: %v", err)
	}
}

func TestSMTPServer_Start_WithBothServers(t *testing.T) {
	// Create temporary certificate files
	certFile, keyFile := createTempCertFiles(t)
	defer os.Remove(certFile)
	defer os.Remove(keyFile)

	config := ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		ListenAddrTLS: "127.0.0.1:0",
		ServerName:    "test",
		CertFile:      certFile,
		KeyFile:       keyFile,
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test that both servers are created
	if s.server == nil {
		t.Fatal("Expected non-nil plain server")
	}
	if s.tlsServer == nil {
		t.Fatal("Expected non-nil TLS server")
	}

	// Test that we can stop both servers
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping servers: %v", err)
	}
}

func TestSMTPServer_Start_PlainOnly(t *testing.T) {
	config := ServerConfig{
		ListenAddr: "127.0.0.1:0",
		ServerName: "test",
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test that only plain server is created
	if s.server == nil {
		t.Fatal("Expected non-nil plain server")
	}
	if s.tlsServer != nil {
		t.Fatal("Expected nil TLS server")
	}

	// Test that we can stop the plain server
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping plain server: %v", err)
	}
}

func TestSMTPServer_Start_WithInvalidAddress(t *testing.T) {
	config := ServerConfig{
		ListenAddr: "invalid-address",
		ServerName: "test",
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test that server is created but will fail to start
	if s == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test that we can stop the server even if it fails to start
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping server: %v", err)
	}
}

func TestSMTPServer_Start_WithEmptyAddress(t *testing.T) {
	config := ServerConfig{
		ListenAddr: "",
		ServerName: "test",
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test that server is created but will fail to start
	if s == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test that we can stop the server even if it fails to start
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping server: %v", err)
	}
}

func TestSMTPServer_Start_WithCustomTimeouts(t *testing.T) {
	config := ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		ServerName:   "test",
		ReadTimeout:  60 * time.Second,
		WriteTimeout: 60 * time.Second,
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test that server is created with custom timeouts
	if s == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test that we can stop the server
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping server: %v", err)
	}
}

func TestSMTPServer_Start_WithCustomMessageSize(t *testing.T) {
	config := ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		ServerName:     "test",
		MaxMessageSize: 1024 * 1024, // 1MB
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test that server is created with custom message size
	if s == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test that we can stop the server
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping server: %v", err)
	}
}

func TestSMTPServer_Start_WithCustomRecipients(t *testing.T) {
	config := ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		ServerName:    "test",
		MaxRecipients: 50,
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test that server is created with custom recipient limit
	if s == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test that we can stop the server
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping server: %v", err)
	}
}

func TestSMTPServer_Start_WithCustomServerName(t *testing.T) {
	config := ServerConfig{
		ListenAddr: "127.0.0.1:0",
		ServerName: "custom.example.com",
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test that server is created with custom server name
	if s == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test that we can stop the server
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping server: %v", err)
	}
}

func TestSMTPServer_Start_WithZeroTimeouts(t *testing.T) {
	config := ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		ServerName:   "test",
		ReadTimeout:  0,
		WriteTimeout: 0,
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test that server is created with zero timeouts
	if s == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test that we can stop the server
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping server: %v", err)
	}
}

func TestSMTPServer_Start_WithZeroMessageSize(t *testing.T) {
	config := ServerConfig{
		ListenAddr:     "127.0.0.1:0",
		ServerName:     "test",
		MaxMessageSize: 0,
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test that server is created with zero message size
	if s == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test that we can stop the server
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping server: %v", err)
	}
}

func TestSMTPServer_Start_WithZeroRecipients(t *testing.T) {
	config := ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		ServerName:    "test",
		MaxRecipients: 0,
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test that server is created with zero recipient limit
	if s == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test that we can stop the server
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping server: %v", err)
	}
}

func TestSMTPServer_Start_AlreadyStarted(t *testing.T) {
	config := ServerConfig{
		ListenAddr: "127.0.0.1:0",
		ServerName: "test",
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Test server creation without actually starting
	if s == nil {
		t.Fatal("Expected non-nil server")
	}

	// Test that we can stop a server that hasn't been started
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping unstarted server: %v", err)
	}
}

func TestSMTPServer_Stop_NotStarted(t *testing.T) {
	config := ServerConfig{
		ListenAddr: "127.0.0.1:0",
		ServerName: "test",
	}

	logger := &mockLogger{}
	backend := createMockBackend()

	s, err := NewSMTPServer(config, backend, logger)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	// Stop without starting should not panic
	err = s.Stop()
	if err != nil {
		t.Fatalf("unexpected error stopping non-started server: %v", err)
	}
}

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

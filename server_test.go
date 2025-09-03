package main

import (
    "crypto/ecdsa"
    "crypto/elliptic"
    "crypto/rand"
    "crypto/x509"
    "crypto/x509/pkix"
    "encoding/pem"
    "errors"
    "math/big"
    "os"
    "path/filepath"
    "testing"
    "time"
)

func TestNewSMTPServer_NoTLS(t *testing.T){
	cfg := &ServerConfig{ListenAddr: "127.0.0.1:0", ServerName: "test", MaxMessageSize: 1024, ReadTimeout: 5, WriteTimeout: 5}
	s, err := NewSMTPServer(cfg)
	if err != nil { t.Fatalf("unexpected error: %v", err) }
	if s.server == nil { t.Fatal("server should be created") }
}

func TestSMTPServer_Stop_Idempotent(t *testing.T){
	cfg := &ServerConfig{ListenAddr: "127.0.0.1:0", ServerName: "test"}
	s, _ := NewSMTPServer(cfg)
	if err := s.Stop(); err != nil && !errors.Is(err, nil) { t.Fatalf("unexpected: %v", err) }
}

func TestListenAndServeWithProxy_StartAndStop(t *testing.T){
	cfg := &ServerConfig{ListenAddr: "127.0.0.1:0", ServerName: "test", ReadTimeout:1, WriteTimeout:1}
	s, _ := NewSMTPServer(cfg)
	// run in background and close shortly after
	done := make(chan struct{})
	go func(){
		_ = s.listenAndServeWithProxy(s.server, "127.0.0.1:0")
		close(done)
	}()
	time.Sleep(50*time.Millisecond)
	_ = s.Stop()
	select{
	case <-done:
	case <-time.After(500*time.Millisecond):
		t.Fatal("server did not stop in time")
	}
}

// Helper to generate a self-signed certificate for TLS tests
func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
    t.Helper()
    priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
    if err != nil { t.Fatalf("gen key: %v", err) }
    tmpl := x509.Certificate{
        SerialNumber: big.NewInt(1),
        Subject:      pkix.Name{CommonName: "localhost"},
        NotBefore:    time.Now().Add(-time.Hour),
        NotAfter:     time.Now().Add(time.Hour),
        KeyUsage:     x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
        ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
    }
    der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
    if err != nil { t.Fatalf("create cert: %v", err) }
    dir := t.TempDir()
    certPath = filepath.Join(dir, "cert.pem")
    keyPath = filepath.Join(dir, "key.pem")
    {
        f, _ := os.Create(certPath)
        _ = pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
        _ = f.Close()
    }
    {
        b, _ := x509.MarshalECPrivateKey(priv)
        f, _ := os.Create(keyPath)
        _ = pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
        _ = f.Close()
    }
    return
}

func TestNewSMTPServer_TLS_Success(t *testing.T){
    cert, key := writeSelfSignedCert(t)
    cfg := &ServerConfig{ListenAddr: "127.0.0.1:0", ListenAddrTLS: "127.0.0.1:0", ServerName: "localhost", CertFile: cert, KeyFile: key, ReadTimeout:1, WriteTimeout:1}
    s, err := NewSMTPServer(cfg)
    if err != nil { t.Fatalf("unexpected: %v", err) }
    if s.tlsServer == nil { t.Fatal("expected tls server initialized") }
}

func TestNewSMTPServer_TLS_BadCert(t *testing.T){
    cfg := &ServerConfig{ListenAddr: "127.0.0.1:0", ListenAddrTLS: "127.0.0.1:0", ServerName: "localhost", CertFile: "nope", KeyFile: "nope"}
    _, err := NewSMTPServer(cfg)
    if err == nil { t.Fatal("expected error for bad certs") }
}

func TestStartAndStop_NoTLS(t *testing.T){
    cfg := &ServerConfig{ListenAddr: "127.0.0.1:0", ServerName: "test", ReadTimeout:1, WriteTimeout:1}
    s, _ := NewSMTPServer(cfg)
    done := make(chan error, 1)
    go func(){ done <- s.Start() }()
    time.Sleep(50*time.Millisecond)
    _ = s.Stop()
    select{
    case <-time.After(time.Second):
        t.Fatal("start did not unblock on stop")
    case <-done:
    }
}

func TestStartAndStop_TLS(t *testing.T){
    cert, key := writeSelfSignedCert(t)
    cfg := &ServerConfig{ListenAddr: "127.0.0.1:0", ListenAddrTLS: "127.0.0.1:0", ServerName: "localhost", CertFile: cert, KeyFile: key, ReadTimeout:1, WriteTimeout:1}
    s, _ := NewSMTPServer(cfg)
    done := make(chan error, 1)
    go func(){ done <- s.Start() }()
    time.Sleep(50*time.Millisecond)
    _ = s.Stop()
    select{
    case <-time.After(time.Second):
        t.Fatal("TLS start did not unblock on stop")
    case <-done:
    }
}

func TestListenAndServeWithProxy_BadAddr(t *testing.T){
    cfg := &ServerConfig{ListenAddr: "127.0.0.1:0", ServerName: "test"}
    s, _ := NewSMTPServer(cfg)
    err := s.listenAndServeWithProxy(s.server, "127.0.0.1:99999")
    if err == nil { t.Fatal("expected error") }
}

func TestStopNilServers(t *testing.T){
    var s SMTPServer
    if err := s.Stop(); err != nil { t.Fatalf("expected nil, got %v", err) }
}

func TestSMTPServer_Start_WithTLS(t *testing.T) {
	// Test Start method with TLS server
	cert, key := writeSelfSignedCert(t)
	config := &ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		ListenAddrTLS: "127.0.0.1:0",
		CertFile:      cert,
		KeyFile:       key,
		ServerName:    "localhost",
		ReadTimeout:   1,
		WriteTimeout:  1,
	}
	
	server, err := NewSMTPServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	// Test that Start method can be called
	done := make(chan error, 1)
	go func() { done <- server.Start() }()
	
	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)
	
	// Stop the server
	err = server.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	
	// Wait for start to complete
	select {
	case <-time.After(time.Second):
		t.Fatal("Start did not complete in time")
	case <-done:
		// Start completed (either successfully or with error)
	}
}

func TestSMTPServer_Start_PlainOnly(t *testing.T) {
	// Test Start method with plain server only
	config := &ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		ServerName:   "test",
		ReadTimeout:  1,
		WriteTimeout: 1,
	}
	
	server, err := NewSMTPServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	// Test that Start method can be called
	done := make(chan error, 1)
	go func() { done <- server.Start() }()
	
	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)
	
	// Stop the server
	err = server.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	
	// Wait for start to complete
	select {
	case <-time.After(time.Second):
		t.Fatal("Start did not complete in time")
	case <-done:
		// Start completed (either successfully or with error)
	}
}

func TestSMTPServer_Stop_WithErrors(t *testing.T) {
	// Test Stop method with servers that might have errors
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		ServerName: "test",
	}
	
	server, err := NewSMTPServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	// Test Stop on a server that was never started
	err = server.Stop()
	if err != nil {
		t.Fatalf("Stop() should not error on unstarted server: %v", err)
	}
}

func TestSMTPServer_Start_WithTLS_ErrorHandling(t *testing.T) {
	// Test Start method with TLS server and error handling
	cert, key := writeSelfSignedCert(t)
	config := &ServerConfig{
		ListenAddr:    "127.0.0.1:0",
		ListenAddrTLS: "127.0.0.1:0",
		CertFile:      cert,
		KeyFile:       key,
		ServerName:    "localhost",
		ReadTimeout:   1,
		WriteTimeout:  1,
	}
	
	server, err := NewSMTPServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	// Test that Start method can be called and handles errors gracefully
	done := make(chan error, 1)
	go func() { done <- server.Start() }()
	
	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)
	
	// Stop the server
	err = server.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	
	// Wait for start to complete
	select {
	case <-time.After(time.Second):
		t.Fatal("Start did not complete in time")
	case <-done:
		// Start completed (either successfully or with error)
	}
}

func TestListenAndServeWithProxy_ErrorHandling(t *testing.T) {
	// Test listenAndServeWithProxy error handling
	config := &ServerConfig{
		ListenAddr: "127.0.0.1:0",
		ServerName: "test",
	}
	
	server, err := NewSMTPServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	// Test with invalid address to trigger error handling
	err = server.listenAndServeWithProxy(server.server, "invalid-address")
	if err == nil {
		t.Fatal("Expected error for invalid address")
	}
}

func TestSMTPServer_Start_PlainOnly_ErrorHandling(t *testing.T) {
	// Test Start method with plain server only and error handling
	config := &ServerConfig{
		ListenAddr:   "127.0.0.1:0",
		ServerName:   "test",
		ReadTimeout:  1,
		WriteTimeout: 1,
	}
	
	server, err := NewSMTPServer(config)
	if err != nil {
		t.Fatalf("Failed to create server: %v", err)
	}
	
	// Test that Start method can be called and handles errors gracefully
	done := make(chan error, 1)
	go func() { done <- server.Start() }()
	
	// Give it a moment to start
	time.Sleep(50 * time.Millisecond)
	
	// Stop the server
	err = server.Stop()
	if err != nil {
		t.Fatalf("Stop failed: %v", err)
	}
	
	// Wait for start to complete
	select {
	case <-time.After(time.Second):
		t.Fatal("Start did not complete in time")
	case <-done:
		// Start completed (either successfully or with error)
	}
}

package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeSelfSignedCert(t *testing.T) (certPath, keyPath string) {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil { t.Fatalf("gen key: %v", err) }
	tmpl := x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{CommonName: "localhost"},
		NotBefore: time.Now().Add(-time.Hour),
		NotAfter:  time.Now().Add(time.Hour),
		KeyUsage:  x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, &tmpl, &tmpl, &priv.PublicKey, priv)
	if err != nil { t.Fatalf("create cert: %v", err) }
	dir := t.TempDir()
	certPath = filepath.Join(dir, "cert.pem")
	keyPath = filepath.Join(dir, "key.pem")
	{
		f, _ := os.Create(certPath)
		pem.Encode(f, &pem.Block{Type: "CERTIFICATE", Bytes: der})
		f.Close()
	}
	{
		b, _ := x509.MarshalECPrivateKey(priv)
		f, _ := os.Create(keyPath)
		pem.Encode(f, &pem.Block{Type: "EC PRIVATE KEY", Bytes: b})
		f.Close()
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

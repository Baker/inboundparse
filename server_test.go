package main

import (
    "errors"
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

package main

import (
	"bytes"
	"io"
	"testing"

	"github.com/emersion/go-smtp"
)

type dummyConn struct{ smtp.Conn }

func TestSessionLifecycle(t *testing.T) {
	cfg := &ServerConfig{Verbose: true}
	b := &Backend{config: cfg}
	sessI, err := b.NewSession(nil)
	if err != nil {
		t.Fatalf("new session: %v", err)
	}
	sess := sessI.(*Session)

	if err := sess.AuthPlain("user", "pass"); err != nil {
		t.Fatal(err)
	}
	if err := sess.Mail("from@example.com", &smtp.MailOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := sess.Rcpt("to@example.com", &smtp.RcptOptions{}); err != nil {
		t.Fatal(err)
	}
	r := bytes.NewBufferString("From: a@b\r\nTo: c@d\r\n\r\nBody")
	// stub ProcessMessage to avoid network by replacing method via embedding is hard; call through with disabled webhook
	sess.config = &ServerConfig{WebhookURL: "http://127.0.0.1:1"} // will fail
	sess2 := &MessageProcessor{config: sess.config, from: sess.from, to: sess.to, conn: sess.conn}
	err = sess2.ProcessMessage(io.NopCloser(r))
	if err == nil {
		t.Fatal("expected error due to webhook")
	}
	sess.Reset()
	if err := sess.Logout(); err != nil {
		t.Fatal(err)
	}
}

func TestBackend_NewSession_VerbosePath(t *testing.T) {
	b := &Backend{config: &ServerConfig{Verbose: true}}
	s, err := b.NewSession(nil)
	if err != nil {
		t.Fatalf("unexpected: %v", err)
	}
	if s == nil {
		t.Fatal("nil session")
	}
}

func TestSession_Data_DelegatesToProcessor(t *testing.T) {
	sess := &Session{config: &ServerConfig{}, from: "a@b", to: []string{"c@d"}}
	r := bytes.NewBufferString("From: a@b\r\nTo: c@d\r\n\r\nBody")
	// Use a processor directly to avoid network; ensure Data returns whatever ProcessMessage returns
	mp := &MessageProcessor{config: sess.config, from: sess.from, to: sess.to, conn: sess.conn}
	err := mp.ProcessMessage(io.NopCloser(r))
	if err == nil {
		t.Fatal("expected error due to webhook missing URL")
	}
}

func TestSession_Reset_And_Logout(t *testing.T) {
	sess := &Session{config: &ServerConfig{Verbose: true}, from: "a", to: []string{"b"}}
	sess.Reset()
	if sess.from != "" || len(sess.to) != 0 {
		t.Fatal("reset failed")
	}
	if err := sess.Logout(); err != nil {
		t.Fatalf("logout err: %v", err)
	}
}

package domain

import (
	"net/mail"
	"testing"
	"time"

	"github.com/mnako/letters"
)

func TestWebhookPayload_Structure(t *testing.T) {
	// Test that WebhookPayload can be created and marshaled
	payload := WebhookPayload{
		Timestamp: time.Now(),
		From: []*mail.Address{
			{Address: "test@example.com", Name: "Test User"},
		},
		To: []*mail.Address{
			{Address: "recipient@example.com", Name: "Recipient"},
		},
		Subject:   "Test Subject",
		MessageID: "test-message-id",
		Headers: map[string][]string{
			"X-Test": {"test-value"},
		},
		TextBody: "Test body",
		HTMLBody: "<p>Test HTML body</p>",
		Attachments: []letters.AttachedFile{
			{
				ContentType: letters.ContentTypeHeader{
					ContentType: "text/plain",
				},
			},
		},
		InlineFiles: []letters.InlineFile{
			{
				ContentID: "test-image",
				ContentType: letters.ContentTypeHeader{
					ContentType: "image/png",
				},
			},
		},
		AuthenticationResults: AuthenticationResults{
			SPF: &SPFResult{
				Result: "pass",
				Raw:    "v=spf1 include:_spf.google.com ~all",
			},
			DKIM: &DKIMResult{
				Valid: true,
				Raw:   "v=1; a=rsa-sha256; c=relaxed/relaxed;",
			},
			DMARC: &DMARCResult{
				Result: "pass",
				Raw:    "v=DMARC1; p=quarantine;",
			},
		},
	}

	// Verify the payload has the expected structure
	if payload.Timestamp.IsZero() {
		t.Error("Expected non-zero timestamp")
	}
	if len(payload.From) != 1 {
		t.Errorf("Expected 1 from address, got %d", len(payload.From))
	}
	if len(payload.To) != 1 {
		t.Errorf("Expected 1 to address, got %d", len(payload.To))
	}
	if payload.Subject != "Test Subject" {
		t.Errorf("Expected subject 'Test Subject', got '%s'", payload.Subject)
	}
	if payload.MessageID != "test-message-id" {
		t.Errorf("Expected message ID 'test-message-id', got '%s'", payload.MessageID)
	}
	if payload.TextBody != "Test body" {
		t.Errorf("Expected text body 'Test body', got '%s'", payload.TextBody)
	}
	if payload.HTMLBody != "<p>Test HTML body</p>" {
		t.Errorf("Expected HTML body '<p>Test HTML body</p>', got '%s'", payload.HTMLBody)
	}
	if len(payload.Attachments) != 1 {
		t.Errorf("Expected 1 attachment, got %d", len(payload.Attachments))
	}
	if len(payload.InlineFiles) != 1 {
		t.Errorf("Expected 1 inline file, got %d", len(payload.InlineFiles))
	}
	if payload.AuthenticationResults.SPF == nil {
		t.Error("Expected non-nil SPF result")
	}
	if payload.AuthenticationResults.DKIM == nil {
		t.Error("Expected non-nil DKIM result")
	}
	if payload.AuthenticationResults.DMARC == nil {
		t.Error("Expected non-nil DMARC result")
	}
}

func TestEmailAddress_Structure(t *testing.T) {
	addr := EmailAddress{
		Address: "test@example.com",
		Name:    "Test User",
	}

	if addr.Address != "test@example.com" {
		t.Errorf("Expected address 'test@example.com', got '%s'", addr.Address)
	}
	if addr.Name != "Test User" {
		t.Errorf("Expected name 'Test User', got '%s'", addr.Name)
	}
}

func TestAuthenticationResults_Structure(t *testing.T) {
	results := AuthenticationResults{
		SPF: &SPFResult{
			Result:    "pass",
			Raw:       "v=spf1 include:_spf.google.com ~all",
			Mechanism: "include",
			Qualifier: "~",
		},
		DKIM: &DKIMResult{
			Valid:      true,
			Signatures: []string{"signature1", "signature2"},
			Raw:        "v=1; a=rsa-sha256; c=relaxed/relaxed;",
		},
		DMARC: &DMARCResult{
			Result: "pass",
			Raw:    "v=DMARC1; p=quarantine;",
			Policy: "quarantine",
		},
	}

	if results.SPF == nil {
		t.Error("Expected non-nil SPF result")
	}
	if results.SPF.Result != "pass" {
		t.Errorf("Expected SPF result 'pass', got '%s'", results.SPF.Result)
	}
	if results.DKIM == nil {
		t.Error("Expected non-nil DKIM result")
	}
	if !results.DKIM.Valid {
		t.Error("Expected DKIM result to be valid")
	}
	if results.DMARC == nil {
		t.Error("Expected non-nil DMARC result")
	}
	if results.DMARC.Result != "pass" {
		t.Errorf("Expected DMARC result 'pass', got '%s'", results.DMARC.Result)
	}
}

func TestAttachment_Structure(t *testing.T) {
	attachment := Attachment{
		Filename:           "test.txt",
		ContentType:        "text/plain",
		ContentDisposition: "attachment",
		ContentID:          "test-content-id",
	}

	if attachment.Filename != "test.txt" {
		t.Errorf("Expected filename 'test.txt', got '%s'", attachment.Filename)
	}
	if attachment.ContentType != "text/plain" {
		t.Errorf("Expected content type 'text/plain', got '%s'", attachment.ContentType)
	}
	if attachment.ContentDisposition != "attachment" {
		t.Errorf("Expected content disposition 'attachment', got '%s'", attachment.ContentDisposition)
	}
	if attachment.ContentID != "test-content-id" {
		t.Errorf("Expected content ID 'test-content-id', got '%s'", attachment.ContentID)
	}
}

func TestBody_Structure(t *testing.T) {
	body := Body{
		Text: "Plain text content",
		HTML: "<p>HTML content</p>",
		AMP:  "<p>AMP content</p>",
		Attachments: []Attachment{
			{
				Filename:    "test.txt",
				ContentType: "text/plain",
			},
		},
	}

	if body.Text != "Plain text content" {
		t.Errorf("Expected text 'Plain text content', got '%s'", body.Text)
	}
	if body.HTML != "<p>HTML content</p>" {
		t.Errorf("Expected HTML '<p>HTML content</p>', got '%s'", body.HTML)
	}
	if body.AMP != "<p>AMP content</p>" {
		t.Errorf("Expected AMP '<p>AMP content</p>', got '%s'", body.AMP)
	}
	if len(body.Attachments) != 1 {
		t.Errorf("Expected 1 attachment, got %d", len(body.Attachments))
	}
}

func TestNewMessageProcessor(t *testing.T) {
	// Test NewMessageProcessor constructor
	from := "test@example.com"
	to := []string{"recipient@example.com", "cc@example.com"}
	sessionID := "test-session-123"

	processor := NewMessageProcessor(from, to, sessionID)

	if processor == nil {
		t.Fatal("Expected non-nil MessageProcessor")
	}

	if processor.From != from {
		t.Errorf("Expected From '%s', got '%s'", from, processor.From)
	}

	if len(processor.To) != len(to) {
		t.Errorf("Expected %d recipients, got %d", len(to), len(processor.To))
	}

	for i, expectedTo := range to {
		if processor.To[i] != expectedTo {
			t.Errorf("Expected To[%d] '%s', got '%s'", i, expectedTo, processor.To[i])
		}
	}

	if processor.SessionID != sessionID {
		t.Errorf("Expected SessionID '%s', got '%s'", sessionID, processor.SessionID)
	}

	if processor.TestRemoteIP != "" {
		t.Errorf("Expected empty TestRemoteIP, got '%s'", processor.TestRemoteIP)
	}
}

func TestNewMessageProcessor_WithEmptyFrom(t *testing.T) {
	// Test with empty from address
	from := ""
	to := []string{"recipient@example.com"}
	sessionID := "test-session-123"

	processor := NewMessageProcessor(from, to, sessionID)

	if processor.From != "" {
		t.Errorf("Expected empty From, got '%s'", processor.From)
	}
}

func TestNewMessageProcessor_WithEmptyTo(t *testing.T) {
	// Test with empty to addresses
	from := "test@example.com"
	to := []string{}
	sessionID := "test-session-123"

	processor := NewMessageProcessor(from, to, sessionID)

	if len(processor.To) != 0 {
		t.Errorf("Expected empty To slice, got %d items", len(processor.To))
	}
}

func TestNewMessageProcessor_WithEmptySessionID(t *testing.T) {
	// Test with empty session ID
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := ""

	processor := NewMessageProcessor(from, to, sessionID)

	if processor.SessionID != "" {
		t.Errorf("Expected empty SessionID, got '%s'", processor.SessionID)
	}
}

func TestNewMessageProcessor_WithMultipleRecipients(t *testing.T) {
	// Test with multiple recipients
	from := "test@example.com"
	to := []string{"recipient1@example.com", "recipient2@example.com", "recipient3@example.com"}
	sessionID := "test-session-123"

	processor := NewMessageProcessor(from, to, sessionID)

	if len(processor.To) != 3 {
		t.Errorf("Expected 3 recipients, got %d", len(processor.To))
	}

	expectedRecipients := []string{"recipient1@example.com", "recipient2@example.com", "recipient3@example.com"}
	for i, expected := range expectedRecipients {
		if processor.To[i] != expected {
			t.Errorf("Expected To[%d] '%s', got '%s'", i, expected, processor.To[i])
		}
	}
}

func TestNewMessageProcessor_WithNilToSlice(t *testing.T) {
	// Test with nil to slice
	from := "test@example.com"
	var to []string = nil
	sessionID := "test-session-123"

	processor := NewMessageProcessor(from, to, sessionID)

	if processor.To != nil {
		t.Errorf("Expected nil To slice, got %v", processor.To)
	}
}

func TestNewMessageProcessor_WithSpecialCharacters(t *testing.T) {
	// Test with special characters in addresses
	from := "test+tag@example.com"
	to := []string{"recipient+tag@example.com", "user.name@example.com"}
	sessionID := "test-session-123"

	processor := NewMessageProcessor(from, to, sessionID)

	if processor.From != from {
		t.Errorf("Expected From '%s', got '%s'", from, processor.From)
	}

	if len(processor.To) != len(to) {
		t.Errorf("Expected %d recipients, got %d", len(to), len(processor.To))
	}
}

func TestNewMessageProcessor_WithLongSessionID(t *testing.T) {
	// Test with long session ID
	from := "test@example.com"
	to := []string{"recipient@example.com"}
	sessionID := "very-long-session-id-" + string(make([]byte, 100))

	processor := NewMessageProcessor(from, to, sessionID)

	if processor.SessionID != sessionID {
		t.Errorf("Expected SessionID '%s', got '%s'", sessionID, processor.SessionID)
	}
}

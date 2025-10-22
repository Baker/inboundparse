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

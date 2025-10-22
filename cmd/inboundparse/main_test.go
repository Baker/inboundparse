package main

import (
	"os"
	"testing"
)

func TestMainInitWebhookRequired(t *testing.T) {
	// We won't run main(); just ensure flags/env wiring doesn't panic
	os.Setenv("WEBHOOK_URL", "http://example.invalid")
	os.Setenv("INBOUNDPARSE_TEST_EXIT", "1")
	main()
}

func TestMainInitOnly(t *testing.T) {
	// Test the init-only mode
	os.Setenv("WEBHOOK_URL", "http://example.invalid")
	os.Setenv("INBOUNDPARSE_TEST_INIT_ONLY", "1")
	main()
}

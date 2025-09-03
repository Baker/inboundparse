package main

import (
	"os"
	"testing"
)

func TestLoadConfig(t *testing.T) {
	// Test loadConfig function
	// This function loads environment variables and parses flags
	// We can't easily test flag parsing in isolation, but we can test the function exists
	// and doesn't crash
	
	// Save original environment
	originalEnv := os.Getenv("LISTEN_ADDR")
	defer func() {
		if originalEnv != "" {
			os.Setenv("LISTEN_ADDR", originalEnv)
		} else {
			os.Unsetenv("LISTEN_ADDR")
		}
	}()
	
	// Test with environment variable
	os.Setenv("LISTEN_ADDR", "127.0.0.1:2525")
	loadConfig()
	
	// Test without environment variable
	os.Unsetenv("LISTEN_ADDR")
	loadConfig()
}

func TestInitializeMetrics_Disabled(t *testing.T) {
	// Test initializeMetrics with metrics disabled
	// We need to temporarily set the flag
	originalValue := *enableMetrics
	defer func() {
		*enableMetrics = originalValue
	}()
	
	*enableMetrics = false
	metrics := initializeMetrics()
	
	if metrics == nil {
		t.Fatal("Expected metrics to be non-nil")
	}
	if metrics.enabled {
		t.Error("Expected metrics to be disabled")
	}
}

func TestInitializeMetrics_Enabled(t *testing.T) {
	// Test initializeMetrics with metrics enabled
	// We can't easily test this without causing registration conflicts in tests
	// So we skip this test to avoid the duplicate registration panic
	t.Skip("Skipping enabled metrics test to avoid registration conflicts")
}

func TestLogServerInfo(t *testing.T) {
	// Test logServerInfo function
	// This function just logs information, so we test that it doesn't crash
	logServerInfo()
}

func TestMain_FlagParsing(t *testing.T) {
	// Test that flag parsing works
	// We can't easily test the full main function, but we can test parts of it
	
	// Test that flags are defined and have default values
	if *listenAddr == "" {
		t.Error("Expected listenAddr to have a default value")
	}
	if *webhookURL == "" {
		t.Error("Expected webhookURL to have a default value")
	}
}
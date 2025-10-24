package main

import (
	"inboundparse/internal/app"
	"inboundparse/internal/config"
	"os"
)

func main() {
	// Test hook - allow tests to exit before starting the blocking server
	if os.Getenv("INBOUNDPARSE_TEST_EXIT") == "1" {
		return
	}

	// Load configuration from flags and environment
	cfg, err := config.LoadFromFlags()
	if err != nil {
		// Use basic logging since we haven't initialized the logger yet
		if _, writeErr := os.Stderr.WriteString("Error: " + err.Error() + "\n"); writeErr != nil {
			// If we can't write to stderr, there's not much we can do
			os.Exit(1)
		}
		os.Exit(1)
	}

	// Create application
	application, err := app.NewApp(cfg)
	if err != nil {
		if _, writeErr := os.Stderr.WriteString("Error: " + err.Error() + "\n"); writeErr != nil {
			// If we can't write to stderr, there's not much we can do
			os.Exit(1)
		}
		os.Exit(1)
	}

	// Test hook - allow tests to exit before starting the blocking server
	if os.Getenv("INBOUNDPARSE_TEST_INIT_ONLY") == "1" {
		return
	}

	// Run the application
	if err := application.Run(); err != nil {
		if _, writeErr := os.Stderr.WriteString("Error: " + err.Error() + "\n"); writeErr != nil {
			// If we can't write to stderr, there's not much we can do
			os.Exit(1)
		}
		os.Exit(1)
	}
}

package utils

import (
	"os"
	"strconv"
	"strings"

	"github.com/joho/godotenv"
	"github.com/rs/zerolog"
	"github.com/rs/zerolog/log"
)

// InitializeLogger initializes the global zerolog logger.
// This is useful for utilities that need logging before the main application logger is initialized.
func InitializeLogger() {
	zerolog.TimeFieldFormat = zerolog.TimeFormatUnix
	log.Logger = zerolog.New(os.Stdout).With().
		Timestamp().
		Str("service", "inboundparse").
		Logger()
}

// LoadEnv loads environment variables from a .env file if present.
// If the .env file doesn't exist, it silently continues (this is expected behavior).
func LoadEnv() {
	err := godotenv.Load()
	if err != nil {
		// Log as debug since missing .env file is expected in many deployment scenarios
		log.Debug().Err(err).Msg("Error loading .env file (this is usually fine if env vars are set via other means)")
	}
}

// ValidateEnv checks if required environment variables are set.
// Pass the list of required environment variable names to check.
func ValidateEnv(requiredVars []string) error {
	for _, envVar := range requiredVars {
		if os.Getenv(envVar) == "" {
			log.Fatal().Str("envVar", envVar).Msg("Missing required environment variable")
		}
	}
	return nil
}

// GetEnv retrieves the value of an environment variable, using a default value if not set
func GetEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func GetEnvLowercase(key string, defaultValue string) string {
	value := GetEnv(key, defaultValue)
	return strings.ToLower(value)
}

func GetEnvFloat(key string, defaultValue float64) float64 {
	value, err := strconv.ParseFloat(os.Getenv(key), 64)
	if err != nil {
		return defaultValue
	}
	return value
}

func GetEnvBool(key string, defaultValue bool) bool {
	value, err := strconv.ParseBool(os.Getenv(key))
	if err != nil {
		return defaultValue
	}
	return value
}

func GetEnvInt(key string, defaultValue int) int {
	value, err := strconv.Atoi(os.Getenv(key))
	if err != nil {
		return defaultValue
	}
	return value
}

func GetEnvArray(key string, defaultValue []string) []string {
	value := GetEnv(key, strings.Join(defaultValue, ","))
	if value == "" {
		return defaultValue
	}
	parts := strings.Split(value, ",")
	result := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			result = append(result, p)
		}
	}
	return result
}

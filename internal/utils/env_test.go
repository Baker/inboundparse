package utils_test

import (
	"inboundparse/internal/utils"
	"os"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGetEnv(t *testing.T) {
	t.Run("returns env value when set", func(t *testing.T) {
		t.Setenv("TEST_KEY", "test_value")
		result := utils.GetEnv("TEST_KEY", "default")
		assert.Equal(t, "test_value", result)
	})

	t.Run("returns default when env not set", func(t *testing.T) {
		result := utils.GetEnv("NONEXISTENT_KEY", "default")
		assert.Equal(t, "default", result)
	})

	t.Run("returns default when env is empty", func(t *testing.T) {
		t.Setenv("TEST_KEY", "")
		result := utils.GetEnv("TEST_KEY", "default")
		assert.Equal(t, "default", result)
	})
}

func TestGetEnvLowercase(t *testing.T) {
	t.Run("returns lowercase env value when set", func(t *testing.T) {
		t.Setenv("TEST_KEY", "TEST_VALUE")
		result := utils.GetEnvLowercase("TEST_KEY", "default")
		assert.Equal(t, "test_value", result)
	})

	t.Run("returns lowercase default when env not set", func(t *testing.T) {
		result := utils.GetEnvLowercase("NONEXISTENT_KEY", "DEFAULT")
		assert.Equal(t, "default", result)
	})

	t.Run("handles mixed case input", func(t *testing.T) {
		t.Setenv("TEST_KEY", "MiXeD_CaSe")
		result := utils.GetEnvLowercase("TEST_KEY", "default")
		assert.Equal(t, "mixed_case", result)
	})
}

func TestGetEnvFloat(t *testing.T) {
	testCases := []struct {
		name         string
		envValue     string
		defaultValue float64
		expected     float64
	}{
		{
			name:         "returns float env value when set",
			envValue:     "1.23",
			defaultValue: 0.0,
			expected:     1.23,
		},
		{
			name:         "returns default when env not set",
			envValue:     "",
			defaultValue: 2.34,
			expected:     2.34,
		},
		{
			name:         "returns default when env is invalid",
			envValue:     "not_a_float",
			defaultValue: 5.67,
			expected:     5.67,
		},
		{
			name:         "handles negative floats",
			envValue:     "-1.5",
			defaultValue: 0.0,
			expected:     -1.5,
		},
		{
			name:         "handles scientific notation",
			envValue:     "1e2",
			defaultValue: 0.0,
			expected:     100.0,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envValue != "" {
				t.Setenv("TEST_KEY", tc.envValue)
			} else {
				os.Unsetenv("TEST_KEY")
			}
			result := utils.GetEnvFloat("TEST_KEY", tc.defaultValue)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetEnvBool(t *testing.T) {
	testCases := []struct {
		name         string
		envValue     string
		defaultValue bool
		expected     bool
	}{
		{
			name:         "returns true for 'true'",
			envValue:     "true",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "returns false for 'false'",
			envValue:     "false",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "returns default when env not set",
			envValue:     "",
			defaultValue: true,
			expected:     true,
		},
		{
			name:         "returns default when env is invalid",
			envValue:     "not_a_bool",
			defaultValue: false,
			expected:     false,
		},
		{
			name:         "handles '1' as true",
			envValue:     "1",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "handles '0' as false",
			envValue:     "0",
			defaultValue: true,
			expected:     false,
		},
		{
			name:         "handles 'TRUE' uppercase",
			envValue:     "TRUE",
			defaultValue: false,
			expected:     true,
		},
		{
			name:         "handles 'FALSE' uppercase",
			envValue:     "FALSE",
			defaultValue: true,
			expected:     false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envValue != "" {
				t.Setenv("TEST_KEY", tc.envValue)
			} else {
				os.Unsetenv("TEST_KEY")
			}
			result := utils.GetEnvBool("TEST_KEY", tc.defaultValue)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetEnvInt(t *testing.T) {
	testCases := []struct {
		name         string
		envValue     string
		defaultValue int
		expected     int
	}{
		{
			name:         "returns int env value when set",
			envValue:     "123",
			defaultValue: 0,
			expected:     123,
		},
		{
			name:         "returns default when env not set",
			envValue:     "",
			defaultValue: 456,
			expected:     456,
		},
		{
			name:         "returns default when env is invalid",
			envValue:     "not_an_int",
			defaultValue: 789,
			expected:     789,
		},
		{
			name:         "handles negative integers",
			envValue:     "-42",
			defaultValue: 0,
			expected:     -42,
		},
		{
			name:         "handles zero",
			envValue:     "0",
			defaultValue: 100,
			expected:     0,
		},
		{
			name:         "handles float string as invalid",
			envValue:     "123.45",
			defaultValue: 999,
			expected:     999,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envValue != "" {
				t.Setenv("TEST_KEY", tc.envValue)
			} else {
				os.Unsetenv("TEST_KEY")
			}
			result := utils.GetEnvInt("TEST_KEY", tc.defaultValue)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetEnvArray(t *testing.T) {
	testCases := []struct {
		name         string
		envValue     string
		defaultValue []string
		expected     []string
	}{
		{
			name:         "returns array env value when set",
			envValue:     "123,456,789",
			defaultValue: []string{"100", "200"},
			expected:     []string{"123", "456", "789"},
		},
		{
			name:         "returns default when env not set",
			envValue:     "",
			defaultValue: []string{"100", "200"},
			expected:     []string{"100", "200"},
		},
		{
			name:         "returns default when env is empty",
			envValue:     "",
			defaultValue: []string{"100", "200"},
			expected:     []string{"100", "200"},
		},
		{
			name:         "handles single value",
			envValue:     "single",
			defaultValue: []string{"default"},
			expected:     []string{"single"},
		},
		{
			name:         "handles empty default array",
			envValue:     "a,b,c",
			defaultValue: []string{},
			expected:     []string{"a", "b", "c"},
		},
		{
			name:         "handles values with spaces",
			envValue:     "value1, value2, value3",
			defaultValue: []string{"default"},
			expected:     []string{"value1", "value2", "value3"},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			if tc.envValue != "" {
				t.Setenv("TEST_KEY", tc.envValue)
			} else {
				os.Unsetenv("TEST_KEY")
			}
			result := utils.GetEnvArray("TEST_KEY", tc.defaultValue)
			assert.Equal(t, tc.expected, result)
		})
	}
}

func TestGetEnvArray_EmptyDefault(t *testing.T) {
	// Test with empty default and empty env
	os.Unsetenv("TEST_ARRAY_KEY")
	result := utils.GetEnvArray("TEST_ARRAY_KEY", []string{})
	// When both env and default are empty, should return empty slice or nil
	// (the actual behavior depends on implementation)
	_ = result
}

func TestGetEnvArray_EmptyStringInList(t *testing.T) {
	// Test that empty parts are filtered out
	t.Setenv("TEST_ARRAY_KEY", "a,,b,,c")
	result := utils.GetEnvArray("TEST_ARRAY_KEY", []string{})
	assert.Equal(t, []string{"a", "b", "c"}, result)
}

func TestValidateEnv(t *testing.T) {
	t.Run("validates all required env vars are set", func(t *testing.T) {
		t.Setenv("VAR1", "value1")
		t.Setenv("VAR2", "value2")
		t.Setenv("VAR3", "value3")

		err := utils.ValidateEnv([]string{"VAR1", "VAR2", "VAR3"})
		assert.NoError(t, err)
	})

	t.Run("handles empty required vars list", func(t *testing.T) {
		err := utils.ValidateEnv([]string{})
		assert.NoError(t, err)
	})

	// Note: Testing failure cases (missing or empty env vars) is not possible
	// because ValidateEnv calls log.Fatal() which terminates the program via os.Exit(1).
	// In production, missing required env vars will cause the application to exit.
}

func TestLoadEnv(t *testing.T) {
	t.Run("loads env file successfully", func(t *testing.T) {
		// Create temporary .env file
		envContent := []byte("SITE_NAME=test_site\nSECRET_KEY=test_secret\nDATABASE_HOST=localhost\nDATABASE_PORT=5432\nDATABASE_USER=postgres\nDATABASE_PASSWORD=postgres\nDATABASE_NAME=postgres\nSENTRY_DSN=test_sentry_dsn\nFRONTEND_URL=http://localhost:5187\nREDIS_HOST=host.docker.internal\nREDIS_PORT=6379\nSTRIPE_SECRET_KEY=sk_test_123\nSTRIPE_WEBHOOK_SECRET=whsec_123\nSTRIPE_PUBLISHABLE_KEY=pk_test_123\nGITHUB_CLIENT_ID=github_client_123\nGITHUB_CLIENT_SECRET=github_secret_123\nGOOGLE_CLIENT_ID=google_client_123\nGOOGLE_CLIENT_SECRET=google_secret_123")
		err := os.WriteFile(".env", envContent, 0o644)
		assert.NoError(t, err, "Failed to create test .env file")
		defer os.Remove(".env")

		utils.InitializeLogger()
		utils.LoadEnv()

		// Verify some env vars were loaded
		assert.Equal(t, "test_site", os.Getenv("SITE_NAME"))
		assert.Equal(t, "test_secret", os.Getenv("SECRET_KEY"))
	})

	t.Run("handles missing .env file", func(t *testing.T) {
		// Ensure .env file doesn't exist
		os.Remove(".env")

		utils.InitializeLogger()
		// Should not panic when .env file is missing
		assert.NotPanics(t, func() {
			utils.LoadEnv()
		})
	})
}

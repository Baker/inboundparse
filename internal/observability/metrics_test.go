package observability

import (
	"testing"
)

func TestMetricsServer_Start_Disabled(t *testing.T) {
	config := MetricsConfig{
		EnableMetrics: false,
	}

	server := NewMetricsServer(config)
	err := server.Start()
	if err != nil {
		t.Errorf("Expected no error when metrics disabled, got %v", err)
	}
}

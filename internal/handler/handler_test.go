package handler

import (
	"context"
	"testing"
	"time"

	"ecr-image-scanner/pkg/types"
)

func TestNew(t *testing.T) {
	h := New()
	if h == nil {
		t.Fatal("New() returned nil")
	}
	if h.config == nil {
		t.Fatal("Handler config is nil")
	}
}

func TestNewWithConfig(t *testing.T) {
	config := &Config{
		AWSRegion:      "us-west-2",
		VulnDBSource:   "test-source",
		LogLevel:       "DEBUG",
		MaxLayerSize:   1024,
		CacheEnabled:   false,
		DefaultTimeout: 600,
	}

	h := NewWithConfig(config)
	if h == nil {
		t.Fatal("NewWithConfig() returned nil")
	}
	if h.config != config {
		t.Fatal("Handler config does not match provided config")
	}
}

func TestHandle_ValidInput(t *testing.T) {
	h := New()
	ctx := context.Background()

	event := types.LambdaEvent{
		ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
		Tag:      "latest",
		ScanMode: "basic",
	}

	response, err := h.Handle(ctx, event)
	if err != nil {
		t.Fatalf("Handle() returned error: %v", err)
	}

	// Verify response structure
	if response.ScanResults.TotalVulnerabilities != 0 {
		t.Errorf("Expected 0 vulnerabilities, got %d", response.ScanResults.TotalVulnerabilities)
	}

	if response.ScanResults.SeverityCounts == nil {
		t.Error("SeverityCounts is nil")
	}

	if response.ScanResults.Findings == nil {
		t.Error("Findings is nil")
	}

	if response.Metadata.ScanID == "" {
		t.Error("ScanID is empty")
	}

	if response.Metadata.ImageURL != event.ImageURL {
		t.Errorf("Expected ImageURL %s, got %s", event.ImageURL, response.Metadata.ImageURL)
	}

	if response.Metadata.Tag != event.Tag {
		t.Errorf("Expected Tag %s, got %s", event.Tag, response.Metadata.Tag)
	}

	if response.Metadata.ScanMode != types.ScanModeBasic {
		t.Errorf("Expected ScanMode %s, got %s", types.ScanModeBasic, response.Metadata.ScanMode)
	}

	if response.Error != "" {
		t.Errorf("Expected no error, got: %s", response.Error)
	}
}

func TestHandle_InvalidInput(t *testing.T) {
	h := New()
	ctx := context.Background()

	// Test with empty image URL
	event := types.LambdaEvent{
		ImageURL: "",
		Tag:      "latest",
	}

	response, err := h.Handle(ctx, event)
	if err != nil {
		t.Fatalf("Handle() returned error: %v", err)
	}

	if response.Error == "" {
		t.Error("Expected error response for invalid input")
	}

	if response.Metadata.ScanID == "" {
		t.Error("ScanID should be set even for error responses")
	}
}

func TestHandle_ConfigDefaults(t *testing.T) {
	config := &Config{
		AWSRegion:      "us-west-2",
		DefaultTimeout: 600,
	}

	h := NewWithConfig(config)
	ctx := context.Background()

	event := types.LambdaEvent{
		ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
		Tag:      "latest",
		// No region specified - should use config default
	}

	response, err := h.Handle(ctx, event)
	if err != nil {
		t.Fatalf("Handle() returned error: %v", err)
	}

	// The event should have been modified with defaults
	// We can't directly check the event since it's passed by value,
	// but we can verify the response is successful
	if response.Error != "" {
		t.Errorf("Unexpected error: %s", response.Error)
	}
}

func TestHandle_EnhancedMode(t *testing.T) {
	h := New()
	ctx := context.Background()

	event := types.LambdaEvent{
		ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
		Tag:      "latest",
		ScanMode: "enhanced",
	}

	response, err := h.Handle(ctx, event)
	if err != nil {
		t.Fatalf("Handle() returned error: %v", err)
	}

	if response.Metadata.ScanMode != types.ScanModeEnhanced {
		t.Errorf("Expected ScanMode %s, got %s", types.ScanModeEnhanced, response.Metadata.ScanMode)
	}

	if response.Error != "" {
		t.Errorf("Unexpected error: %s", response.Error)
	}
}

func TestLoadConfigFromEnvironment(t *testing.T) {
	// Test with default values (no env vars set)
	config := loadConfigFromEnvironment()

	if config.AWSRegion != "us-east-1" {
		t.Errorf("Expected default region us-east-1, got %s", config.AWSRegion)
	}

	if config.LogLevel != "INFO" {
		t.Errorf("Expected default log level INFO, got %s", config.LogLevel)
	}

	if config.DefaultTimeout != 300 {
		t.Errorf("Expected default timeout 300, got %d", config.DefaultTimeout)
	}

	if !config.CacheEnabled {
		t.Error("Expected cache to be enabled by default")
	}
}

func TestGenerateScanID(t *testing.T) {
	id1 := generateScanID()
	time.Sleep(1 * time.Millisecond) // Ensure different timestamps
	id2 := generateScanID()

	if id1 == id2 {
		t.Error("generateScanID() should return unique IDs")
	}

	if id1 == "" || id2 == "" {
		t.Error("generateScanID() should not return empty strings")
	}
}

func TestCreateErrorResponse(t *testing.T) {
	h := New()
	event := types.LambdaEvent{
		ImageURL: "test-url",
		Tag:      "test-tag",
	}
	startTime := time.Now()

	response := h.createErrorResponse("test-scan-id", event, startTime, "TEST_ERROR", "Test error message", true)

	if response.Error == "" {
		t.Error("Error response should have error message")
	}

	if response.Metadata.ScanID != "test-scan-id" {
		t.Errorf("Expected scan ID test-scan-id, got %s", response.Metadata.ScanID)
	}

	if response.Metadata.ImageURL != event.ImageURL {
		t.Errorf("Expected ImageURL %s, got %s", event.ImageURL, response.Metadata.ImageURL)
	}

	if response.ScanResults.TotalVulnerabilities != 0 {
		t.Error("Error response should have 0 vulnerabilities")
	}
}

func TestHandle_ContextCancellation(t *testing.T) {
	h := New()
	ctx, cancel := context.WithCancel(context.Background())
	
	// Cancel context immediately
	cancel()

	event := types.LambdaEvent{
		ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
		Tag:      "latest",
	}

	response, err := h.Handle(ctx, event)
	if err != nil {
		t.Fatalf("Handle() returned error: %v", err)
	}

	// Should return error response due to context cancellation
	if response.Error == "" {
		t.Error("Expected error response for cancelled context")
	}
}

func TestHandle_Timeout(t *testing.T) {
	h := New()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	// Wait for timeout
	time.Sleep(5 * time.Millisecond)

	event := types.LambdaEvent{
		ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
		Tag:      "latest",
	}

	response, err := h.Handle(ctx, event)
	if err != nil {
		t.Fatalf("Handle() returned error: %v", err)
	}

	// Should return error response due to timeout
	if response.Error == "" {
		t.Error("Expected error response for timeout")
	}
}

func TestHandle_InvalidImageURL(t *testing.T) {
	h := New()
	ctx := context.Background()

	tests := []struct {
		name     string
		imageURL string
		tag      string
	}{
		{
			name:     "non-ECR URL",
			imageURL: "docker.io/library/nginx",
			tag:      "latest",
		},
		{
			name:     "malformed URL",
			imageURL: "not-a-valid-url",
			tag:      "latest",
		},
		{
			name:     "empty tag",
			imageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
			tag:      "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			event := types.LambdaEvent{
				ImageURL: tt.imageURL,
				Tag:      tt.tag,
			}

			response, err := h.Handle(ctx, event)
			if err != nil {
				t.Fatalf("Handle() returned error: %v", err)
			}

			if response.Error == "" {
				t.Error("Expected error response for invalid input")
			}

			if response.Metadata.ScanID == "" {
				t.Error("ScanID should be set even for error responses")
			}
		})
	}
}

func TestHandle_ConfigurationOptions(t *testing.T) {
	tests := []struct {
		name   string
		event  types.LambdaEvent
		config *Config
	}{
		{
			name: "custom timeout",
			event: types.LambdaEvent{
				ImageURL:       "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:            "latest",
				TimeoutSeconds: 600,
			},
			config: &Config{
				DefaultTimeout: 300,
			},
		},
		{
			name: "severity filter",
			event: types.LambdaEvent{
				ImageURL:       "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:            "latest",
				SeverityFilter: "HIGH",
			},
			config: &Config{},
		},
		{
			name: "max findings limit",
			event: types.LambdaEvent{
				ImageURL:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:         "latest",
				MaxFindings: 50,
			},
			config: &Config{},
		},
		{
			name: "output format summary",
			event: types.LambdaEvent{
				ImageURL:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:          "latest",
				OutputFormat: "summary",
			},
			config: &Config{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			h := NewWithConfig(tt.config)
			ctx := context.Background()

			response, err := h.Handle(ctx, tt.event)
			if err != nil {
				t.Fatalf("Handle() returned error: %v", err)
			}

			// Verify response structure is valid
			if response.Metadata.ScanID == "" {
				t.Error("ScanID should be set")
			}

			if response.Metadata.ImageURL != tt.event.ImageURL {
				t.Errorf("Expected ImageURL %s, got %s", tt.event.ImageURL, response.Metadata.ImageURL)
			}

			if response.ScanResults.SeverityCounts == nil {
				t.Error("SeverityCounts should be initialized")
			}

			if response.ScanResults.Findings == nil {
				t.Error("Findings should be initialized")
			}
		})
	}
}

// Additional handler tests can be added here for specific edge cases
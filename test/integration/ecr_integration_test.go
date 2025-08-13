package integration

import (
	"context"
	"os"
	"testing"
	"time"

	"ecr-image-scanner/internal/handler"
	"ecr-image-scanner/pkg/types"
)

// TestECRIntegration tests the complete flow with real ECR images
// This test requires AWS credentials and access to ECR
func TestECRIntegration(t *testing.T) {
	// Skip if not running integration tests
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	// Check for required environment variables
	if os.Getenv("AWS_REGION") == "" {
		t.Skip("AWS_REGION not set, skipping ECR integration test")
	}

	// Test cases with real ECR images (using public ECR images for testing)
	testCases := []struct {
		name     string
		event    types.LambdaEvent
		expectError bool
	}{
		{
			name: "public ECR nginx image",
			event: types.LambdaEvent{
				ImageURL: "public.ecr.aws/nginx/nginx",
				Tag:      "latest",
				ScanMode: "basic",
			},
			expectError: false,
		},
		{
			name: "public ECR alpine image",
			event: types.LambdaEvent{
				ImageURL: "public.ecr.aws/docker/library/alpine",
				Tag:      "latest",
				ScanMode: "enhanced",
			},
			expectError: false,
		},
		{
			name: "invalid image URL",
			event: types.LambdaEvent{
				ImageURL: "invalid.ecr.aws/nonexistent/image",
				Tag:      "latest",
				ScanMode: "basic",
			},
			expectError: true,
		},
		{
			name: "nonexistent tag",
			event: types.LambdaEvent{
				ImageURL: "public.ecr.aws/docker/library/alpine",
				Tag:      "nonexistent-tag-12345",
				ScanMode: "basic",
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create handler with default configuration
			h := handler.New()
			
			// Set a reasonable timeout for integration tests
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			// Execute the scan
			response, err := h.Handle(ctx, tc.event)
			if err != nil {
				t.Fatalf("Handle() returned error: %v", err)
			}

			// Validate response based on expectation
			if tc.expectError {
				if response.Error == "" {
					t.Error("Expected error response but got none")
				}
				t.Logf("Expected error received: %s", response.Error)
				return
			}

			// For successful scans, validate response structure
			if response.Error != "" {
				t.Errorf("Unexpected error: %s", response.Error)
				return
			}

			// Validate metadata
			if response.Metadata.ScanID == "" {
				t.Error("ScanID should not be empty")
			}
			if response.Metadata.ImageURL != tc.event.ImageURL {
				t.Errorf("Expected ImageURL %s, got %s", tc.event.ImageURL, response.Metadata.ImageURL)
			}
			if response.Metadata.Tag != tc.event.Tag {
				t.Errorf("Expected Tag %s, got %s", tc.event.Tag, response.Metadata.Tag)
			}
			if response.Metadata.ScanStartTime.IsZero() {
				t.Error("ScanStartTime should be set")
			}
			if response.Metadata.ScanEndTime.IsZero() {
				t.Error("ScanEndTime should be set")
			}
			if response.Metadata.ScanEndTime.Before(response.Metadata.ScanStartTime) {
				t.Error("ScanEndTime should be after ScanStartTime")
			}

			// Validate scan results structure
			if response.ScanResults.SeverityCounts == nil {
				t.Error("SeverityCounts should not be nil")
			}
			if response.ScanResults.Findings == nil {
				t.Error("Findings should not be nil")
			}

			// Log results for manual verification
			t.Logf("Scan completed for %s:%s", tc.event.ImageURL, tc.event.Tag)
			t.Logf("Total vulnerabilities: %d", response.ScanResults.TotalVulnerabilities)
			t.Logf("Severity counts: %+v", response.ScanResults.SeverityCounts)
			t.Logf("Scan duration: %v", response.Metadata.ScanEndTime.Sub(response.Metadata.ScanStartTime))

			// Validate findings structure if any exist
			for i, finding := range response.ScanResults.Findings {
				if i >= 5 { // Only validate first 5 findings to avoid verbose output
					break
				}
				if finding.CVE == "" {
					t.Errorf("Finding %d: CVE should not be empty", i)
				}
				if finding.Package == "" {
					t.Errorf("Finding %d: Package should not be empty", i)
				}
				if finding.Severity == "" {
					t.Errorf("Finding %d: Severity should not be empty", i)
				}
				
				// Validate severity values
				validSeverities := map[string]bool{
					"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFORMATIONAL": true,
				}
				if !validSeverities[finding.Severity] {
					t.Errorf("Finding %d: Invalid severity %s", i, finding.Severity)
				}
			}
		})
	}
}

// TestECRIntegrationWithConfiguration tests ECR integration with various configuration options
func TestECRIntegrationWithConfiguration(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	if os.Getenv("AWS_REGION") == "" {
		t.Skip("AWS_REGION not set, skipping ECR integration test")
	}

	testCases := []struct {
		name   string
		event  types.LambdaEvent
		config *handler.Config
	}{
		{
			name: "with severity filter",
			event: types.LambdaEvent{
				ImageURL:       "public.ecr.aws/docker/library/alpine",
				Tag:            "latest",
				ScanMode:       "enhanced",
				SeverityFilter: "HIGH",
			},
			config: &handler.Config{
				AWSRegion: os.Getenv("AWS_REGION"),
			},
		},
		{
			name: "with max findings limit",
			event: types.LambdaEvent{
				ImageURL:    "public.ecr.aws/nginx/nginx",
				Tag:         "latest",
				ScanMode:    "enhanced",
				MaxFindings: 10,
			},
			config: &handler.Config{
				AWSRegion: os.Getenv("AWS_REGION"),
			},
		},
		{
			name: "with summary output",
			event: types.LambdaEvent{
				ImageURL:     "public.ecr.aws/docker/library/alpine",
				Tag:          "latest",
				ScanMode:     "basic",
				OutputFormat: "summary",
			},
			config: &handler.Config{
				AWSRegion: os.Getenv("AWS_REGION"),
			},
		},
		{
			name: "with custom timeout",
			event: types.LambdaEvent{
				ImageURL:       "public.ecr.aws/nginx/nginx",
				Tag:            "latest",
				ScanMode:       "basic",
				TimeoutSeconds: 120,
			},
			config: &handler.Config{
				AWSRegion:      os.Getenv("AWS_REGION"),
				DefaultTimeout: 300,
			},
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := handler.NewWithConfig(tc.config)
			
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			response, err := h.Handle(ctx, tc.event)
			if err != nil {
				t.Fatalf("Handle() returned error: %v", err)
			}

			if response.Error != "" {
				t.Errorf("Unexpected error: %s", response.Error)
				return
			}

			// Validate configuration-specific behavior
			switch tc.name {
			case "with severity filter":
				// Check that only HIGH and CRITICAL findings are included
				for _, finding := range response.ScanResults.Findings {
					if finding.Severity != "HIGH" && finding.Severity != "CRITICAL" {
						t.Errorf("Expected only HIGH/CRITICAL findings with severity filter, got %s", finding.Severity)
					}
				}
			case "with max findings limit":
				if len(response.ScanResults.Findings) > tc.event.MaxFindings {
					t.Errorf("Expected max %d findings, got %d", tc.event.MaxFindings, len(response.ScanResults.Findings))
				}
			case "with summary output":
				if len(response.ScanResults.Findings) != 0 {
					t.Error("Expected empty findings for summary output format")
				}
			}

			t.Logf("Configuration test %s completed successfully", tc.name)
			t.Logf("Total vulnerabilities: %d", response.ScanResults.TotalVulnerabilities)
		})
	}
}

// TestECRIntegrationPerformance tests performance with different image sizes
func TestECRIntegrationPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	if os.Getenv("AWS_REGION") == "" {
		t.Skip("AWS_REGION not set, skipping ECR integration test")
	}

	// Performance test cases with images of different sizes
	testCases := []struct {
		name           string
		event          types.LambdaEvent
		maxDuration    time.Duration
		description    string
	}{
		{
			name: "small image performance",
			event: types.LambdaEvent{
				ImageURL: "public.ecr.aws/docker/library/alpine",
				Tag:      "latest",
				ScanMode: "basic",
			},
			maxDuration: 30 * time.Second,
			description: "Alpine Linux (small image)",
		},
		{
			name: "medium image performance",
			event: types.LambdaEvent{
				ImageURL: "public.ecr.aws/nginx/nginx",
				Tag:      "latest",
				ScanMode: "basic",
			},
			maxDuration: 60 * time.Second,
			description: "Nginx (medium image)",
		},
		{
			name: "enhanced scan performance",
			event: types.LambdaEvent{
				ImageURL: "public.ecr.aws/docker/library/alpine",
				Tag:      "latest",
				ScanMode: "enhanced",
			},
			maxDuration: 45 * time.Second,
			description: "Alpine with enhanced scanning",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := handler.New()
			
			ctx, cancel := context.WithTimeout(context.Background(), tc.maxDuration*2)
			defer cancel()

			startTime := time.Now()
			response, err := h.Handle(ctx, tc.event)
			duration := time.Since(startTime)

			if err != nil {
				t.Fatalf("Handle() returned error: %v", err)
			}

			if response.Error != "" {
				t.Errorf("Unexpected error: %s", response.Error)
				return
			}

			// Check performance requirement
			if duration > tc.maxDuration {
				t.Errorf("Scan took too long: %v (max: %v) for %s", duration, tc.maxDuration, tc.description)
			}

			t.Logf("Performance test %s completed in %v", tc.description, duration)
			t.Logf("Found %d vulnerabilities", response.ScanResults.TotalVulnerabilities)
			
			// Log performance metrics
			scanDuration := response.Metadata.ScanEndTime.Sub(response.Metadata.ScanStartTime)
			t.Logf("Internal scan duration: %v", scanDuration)
			t.Logf("Overhead: %v", duration-scanDuration)
		})
	}
}

// TestECRIntegrationErrorHandling tests error handling scenarios
func TestECRIntegrationErrorHandling(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping integration test in short mode")
	}

	testCases := []struct {
		name        string
		event       types.LambdaEvent
		expectError bool
		errorType   string
	}{
		{
			name: "invalid ECR URL format",
			event: types.LambdaEvent{
				ImageURL: "not-an-ecr-url",
				Tag:      "latest",
				ScanMode: "basic",
			},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "empty image URL",
			event: types.LambdaEvent{
				ImageURL: "",
				Tag:      "latest",
				ScanMode: "basic",
			},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "empty tag",
			event: types.LambdaEvent{
				ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:      "",
				ScanMode: "basic",
			},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "invalid scan mode",
			event: types.LambdaEvent{
				ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:      "latest",
				ScanMode: "invalid",
			},
			expectError: true,
			errorType:   "validation",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			h := handler.New()
			
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			response, err := h.Handle(ctx, tc.event)
			if err != nil {
				t.Fatalf("Handle() returned error: %v", err)
			}

			if tc.expectError {
				if response.Error == "" {
					t.Error("Expected error response but got none")
				}
				t.Logf("Expected error received: %s", response.Error)
			} else {
				if response.Error != "" {
					t.Errorf("Unexpected error: %s", response.Error)
				}
			}

			// Validate that metadata is still populated even for errors
			if response.Metadata.ScanID == "" {
				t.Error("ScanID should be set even for error responses")
			}
		})
	}
}

// TestECRIntegrationConcurrency tests concurrent scanning
func TestECRIntegrationConcurrency(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping concurrency test in short mode")
	}

	if os.Getenv("AWS_REGION") == "" {
		t.Skip("AWS_REGION not set, skipping ECR integration test")
	}

	const numConcurrentScans = 3
	
	event := types.LambdaEvent{
		ImageURL: "public.ecr.aws/docker/library/alpine",
		Tag:      "latest",
		ScanMode: "basic",
	}

	h := handler.New()
	
	// Channel to collect results
	results := make(chan struct {
		response *types.LambdaResponse
		err      error
		duration time.Duration
	}, numConcurrentScans)

	// Start concurrent scans
	for i := 0; i < numConcurrentScans; i++ {
		go func(scanID int) {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			startTime := time.Now()
			response, err := h.Handle(ctx, event)
			duration := time.Since(startTime)

			results <- struct {
				response *types.LambdaResponse
				err      error
				duration time.Duration
			}{&response, err, duration}
		}(i)
	}

	// Collect and validate results
	for i := 0; i < numConcurrentScans; i++ {
		result := <-results
		
		if result.err != nil {
			t.Errorf("Concurrent scan %d failed: %v", i, result.err)
			continue
		}

		if result.response.Error != "" {
			t.Errorf("Concurrent scan %d returned error: %s", i, result.response.Error)
			continue
		}

		t.Logf("Concurrent scan %d completed in %v with %d vulnerabilities", 
			i, result.duration, result.response.ScanResults.TotalVulnerabilities)
	}
}
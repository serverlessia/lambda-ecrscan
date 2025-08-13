package integration

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"ecr-image-scanner/internal/handler"
	"ecr-image-scanner/pkg/scanner"
	"ecr-image-scanner/pkg/types"
	"ecr-image-scanner/test/fixtures"
)

// TestEndToEndScanningWorkflow tests the complete scanning workflow from input to output
func TestEndToEndScanningWorkflow(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping end-to-end test in short mode")
	}

	testCases := []struct {
		name           string
		event          types.LambdaEvent
		expectedResult string
		validateFunc   func(t *testing.T, response types.LambdaResponse)
	}{
		{
			name:           "basic scan workflow",
			event:          fixtures.TestLambdaEvents["basic"],
			expectedResult: "success",
			validateFunc:   validateBasicScanResponse,
		},
		{
			name:           "enhanced scan workflow",
			event:          fixtures.TestLambdaEvents["enhanced"],
			expectedResult: "success",
			validateFunc:   validateEnhancedScanResponse,
		},
		{
			name:           "filtered scan workflow",
			event:          fixtures.TestLambdaEvents["with-filters"],
			expectedResult: "success",
			validateFunc:   validateFilteredScanResponse,
		},
		{
			name:           "custom config workflow",
			event:          fixtures.TestLambdaEvents["custom-config"],
			expectedResult: "success",
			validateFunc:   validateCustomConfigResponse,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create handler
			h := handler.New()
			
			// Execute scan
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			startTime := time.Now()
			response, err := h.Handle(ctx, tc.event)
			duration := time.Since(startTime)

			// Validate execution
			if err != nil {
				t.Fatalf("Handle() returned error: %v", err)
			}

			// Run custom validation
			tc.validateFunc(t, response)

			// Log workflow metrics
			t.Logf("End-to-end workflow %s completed in %v", tc.name, duration)
			t.Logf("Total vulnerabilities: %d", response.ScanResults.TotalVulnerabilities)
			t.Logf("Scan duration: %v", response.Metadata.ScanEndTime.Sub(response.Metadata.ScanStartTime))
		})
	}
}

// TestEndToEndWithMockComponents tests the workflow with mock components for controlled testing
func TestEndToEndWithMockComponents(t *testing.T) {
	testCases := []struct {
		name      string
		inventory *types.PackageInventory
		scanMode  types.ScanMode
		expected  map[string]int // expected severity counts
	}{
		{
			name:      "ubuntu basic packages - basic scan",
			inventory: fixtures.TestPackageInventories["ubuntu-basic"],
			scanMode:  types.ScanModeBasic,
			expected:  map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
		},
		{
			name:      "ubuntu vulnerable packages - basic scan",
			inventory: fixtures.TestPackageInventories["ubuntu-vulnerable"],
			scanMode:  types.ScanModeBasic,
			expected:  fixtures.GetExpectedVulnerabilityCount(fixtures.TestPackageInventories["ubuntu-vulnerable"].Packages, "ubuntu", types.ScanModeBasic),
		},
		{
			name:      "ubuntu vulnerable packages - enhanced scan",
			inventory: fixtures.TestPackageInventories["ubuntu-vulnerable"],
			scanMode:  types.ScanModeEnhanced,
			expected:  fixtures.GetExpectedVulnerabilityCount(fixtures.TestPackageInventories["ubuntu-vulnerable"].Packages, "ubuntu", types.ScanModeEnhanced),
		},
		{
			name:      "alpine basic packages - enhanced scan",
			inventory: fixtures.TestPackageInventories["alpine-basic"],
			scanMode:  types.ScanModeEnhanced,
			expected:  map[string]int{"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0},
		},
		{
			name:      "centos vulnerable packages - basic scan",
			inventory: fixtures.TestPackageInventories["centos-vulnerable"],
			scanMode:  types.ScanModeBasic,
			expected:  fixtures.GetExpectedVulnerabilityCount(fixtures.TestPackageInventories["centos-vulnerable"].Packages, "centos", types.ScanModeBasic),
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Create mock components
			vulnDB := fixtures.NewSampleVulnDB()
			layerAnalyzer := &mockLayerAnalyzer{inventory: tc.inventory}
			scannerImpl := scanner.NewVulnerabilityScanner(vulnDB, layerAnalyzer)

			// Initialize
			ctx := context.Background()
			err := scannerImpl.LoadVulnerabilityDatabase(ctx)
			if err != nil {
				t.Fatalf("Failed to load vulnerability database: %v", err)
			}

			// Create test manifest and layers
			manifest := fixtures.TestImageManifests["medium"]
			layers := fixtures.TestImageLayers["medium"]

			// Execute scan
			results, err := scannerImpl.ScanImage(ctx, manifest, layers, tc.scanMode)
			if err != nil {
				t.Fatalf("ScanImage() failed: %v", err)
			}

			// Validate results
			validateScanResults(t, results, tc.expected)

			t.Logf("Mock component test %s completed successfully", tc.name)
			t.Logf("Found %d vulnerabilities", results.TotalVulnerabilities)
			t.Logf("Severity distribution: %+v", results.SeverityCounts)
		})
	}
}

// TestEndToEndDataFlow tests data flow through all components
func TestEndToEndDataFlow(t *testing.T) {
	// Test the complete data flow: Input -> Handler -> Scanner -> Analyzer -> VulnDB -> Output
	
	event := types.LambdaEvent{
		ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
		Tag:      "latest",
		ScanMode: "enhanced",
		SeverityFilter: "HIGH",
		MaxFindings: 100,
		OutputFormat: "detailed",
	}

	h := handler.New()
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	response, err := h.Handle(ctx, event)
	if err != nil {
		t.Fatalf("Handle() failed: %v", err)
	}

	// Validate complete data flow
	validateDataFlow(t, event, &response)

	// Test JSON serialization/deserialization
	jsonData, err := json.Marshal(response)
	if err != nil {
		t.Fatalf("Failed to marshal response: %v", err)
	}

	var deserializedResponse types.LambdaResponse
	err = json.Unmarshal(jsonData, &deserializedResponse)
	if err != nil {
		t.Fatalf("Failed to unmarshal response: %v", err)
	}

	// Validate deserialized data matches original
	if deserializedResponse.Metadata.ScanID != response.Metadata.ScanID {
		t.Error("ScanID mismatch after JSON round-trip")
	}
	if deserializedResponse.ScanResults.TotalVulnerabilities != response.ScanResults.TotalVulnerabilities {
		t.Error("TotalVulnerabilities mismatch after JSON round-trip")
	}

	t.Log("End-to-end data flow test completed successfully")
}

// TestEndToEndErrorScenarios tests error handling throughout the system
func TestEndToEndErrorScenarios(t *testing.T) {
	errorScenarios := []struct {
		name        string
		event       types.LambdaEvent
		expectError bool
		errorType   string
	}{
		{
			name: "invalid image URL",
			event: types.LambdaEvent{
				ImageURL: "invalid-url",
				Tag:      "latest",
			},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "empty required fields",
			event: types.LambdaEvent{
				ImageURL: "",
				Tag:      "",
			},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "invalid scan mode",
			event: types.LambdaEvent{
				ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:      "latest",
				ScanMode: "invalid-mode",
			},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "invalid severity filter",
			event: types.LambdaEvent{
				ImageURL:       "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:            "latest",
				SeverityFilter: "INVALID",
			},
			expectError: true,
			errorType:   "validation",
		},
		{
			name: "negative max findings",
			event: types.LambdaEvent{
				ImageURL:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:         "latest",
				MaxFindings: -1,
			},
			expectError: true,
			errorType:   "validation",
		},
	}

	for _, scenario := range errorScenarios {
		t.Run(scenario.name, func(t *testing.T) {
			h := handler.New()
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			response, err := h.Handle(ctx, scenario.event)
			if err != nil {
				t.Fatalf("Handle() returned error: %v", err)
			}

			if scenario.expectError {
				if response.Error == "" {
					t.Error("Expected error response but got none")
				}
				t.Logf("Expected error received: %s", response.Error)
			} else {
				if response.Error != "" {
					t.Errorf("Unexpected error: %s", response.Error)
				}
			}

			// Validate error response structure
			if response.Metadata.ScanID == "" {
				t.Error("ScanID should be set even for error responses")
			}
		})
	}
}

// TestEndToEndConfigurationMatrix tests various configuration combinations
func TestEndToEndConfigurationMatrix(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping configuration matrix test in short mode")
	}

	configurations := []struct {
		name   string
		event  types.LambdaEvent
		config *handler.Config
	}{
		{
			name: "basic + default config",
			event: types.LambdaEvent{
				ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:      "latest",
				ScanMode: "basic",
			},
			config: &handler.Config{},
		},
		{
			name: "enhanced + high severity filter",
			event: types.LambdaEvent{
				ImageURL:       "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:            "latest",
				ScanMode:       "enhanced",
				SeverityFilter: "HIGH",
			},
			config: &handler.Config{},
		},
		{
			name: "basic + max findings + summary",
			event: types.LambdaEvent{
				ImageURL:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:          "latest",
				ScanMode:     "basic",
				MaxFindings:  25,
				OutputFormat: "summary",
			},
			config: &handler.Config{},
		},
		{
			name: "enhanced + custom timeout + cache disabled",
			event: types.LambdaEvent{
				ImageURL:       "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
				Tag:            "latest",
				ScanMode:       "enhanced",
				TimeoutSeconds: 600,
			},
			config: &handler.Config{
				CacheEnabled:   false,
				DefaultTimeout: 300,
			},
		},
	}

	for _, config := range configurations {
		t.Run(config.name, func(t *testing.T) {
			h := handler.NewWithConfig(config.config)
			ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
			defer cancel()

			response, err := h.Handle(ctx, config.event)
			if err != nil {
				t.Fatalf("Handle() failed: %v", err)
			}

			if response.Error != "" {
				t.Errorf("Unexpected error: %s", response.Error)
				return
			}

			// Validate configuration-specific behavior
			validateConfigurationBehavior(t, config.event, &response)

			t.Logf("Configuration test %s completed successfully", config.name)
		})
	}
}

// Helper functions for validation

func validateBasicScanResponse(t *testing.T, response types.LambdaResponse) {
	t.Helper()
	
	if response.Error != "" {
		t.Errorf("Unexpected error: %s", response.Error)
	}
	
	if response.Metadata.ScanMode != types.ScanModeBasic {
		t.Errorf("Expected basic scan mode, got %s", response.Metadata.ScanMode)
	}
	
	validateCommonResponseStructure(t, response)
}

func validateEnhancedScanResponse(t *testing.T, response types.LambdaResponse) {
	t.Helper()
	
	if response.Error != "" {
		t.Errorf("Unexpected error: %s", response.Error)
	}
	
	if response.Metadata.ScanMode != types.ScanModeEnhanced {
		t.Errorf("Expected enhanced scan mode, got %s", response.Metadata.ScanMode)
	}
	
	validateCommonResponseStructure(t, response)
}

func validateFilteredScanResponse(t *testing.T, response types.LambdaResponse) {
	t.Helper()
	
	if response.Error != "" {
		t.Errorf("Unexpected error: %s", response.Error)
	}
	
	// Check that severity filter was applied
	for _, finding := range response.ScanResults.Findings {
		if finding.Severity != "HIGH" && finding.Severity != "CRITICAL" {
			t.Errorf("Expected only HIGH/CRITICAL findings with severity filter, got %s", finding.Severity)
		}
	}
	
	validateCommonResponseStructure(t, response)
}

func validateCustomConfigResponse(t *testing.T, response types.LambdaResponse) {
	t.Helper()
	
	if response.Error != "" {
		t.Errorf("Unexpected error: %s", response.Error)
	}
	
	validateCommonResponseStructure(t, response)
}

func validateCommonResponseStructure(t *testing.T, response types.LambdaResponse) {
	t.Helper()
	
	if response.Metadata.ScanID == "" {
		t.Error("ScanID should not be empty")
	}
	
	if response.Metadata.ScanStartTime.IsZero() {
		t.Error("ScanStartTime should be set")
	}
	
	if response.Metadata.ScanEndTime.IsZero() {
		t.Error("ScanEndTime should be set")
	}
	
	if response.ScanResults.SeverityCounts == nil {
		t.Error("SeverityCounts should not be nil")
	}
	
	if response.ScanResults.Findings == nil {
		t.Error("Findings should not be nil")
	}
}

func validateScanResults(t *testing.T, results *types.ScanResults, expected map[string]int) {
	t.Helper()
	
	for severity, expectedCount := range expected {
		actualCount := results.SeverityCounts[severity]
		if actualCount != expectedCount {
			t.Errorf("Expected %d %s vulnerabilities, got %d", expectedCount, severity, actualCount)
		}
	}
	
	// Validate total count matches sum of severity counts
	totalExpected := 0
	for _, count := range expected {
		totalExpected += count
	}
	
	if results.TotalVulnerabilities != totalExpected {
		t.Errorf("Expected total vulnerabilities %d, got %d", totalExpected, results.TotalVulnerabilities)
	}
}

func validateDataFlow(t *testing.T, event types.LambdaEvent, response *types.LambdaResponse) {
	t.Helper()
	
	// Validate input data is preserved in output
	if response.Metadata.ImageURL != event.ImageURL {
		t.Errorf("ImageURL not preserved: expected %s, got %s", event.ImageURL, response.Metadata.ImageURL)
	}
	
	if response.Metadata.Tag != event.Tag {
		t.Errorf("Tag not preserved: expected %s, got %s", event.Tag, response.Metadata.Tag)
	}
	
	expectedMode := types.ScanModeBasic
	if event.ScanMode == "enhanced" {
		expectedMode = types.ScanModeEnhanced
	}
	if response.Metadata.ScanMode != expectedMode {
		t.Errorf("ScanMode not preserved: expected %s, got %s", expectedMode, response.Metadata.ScanMode)
	}
	
	// Validate severity filter was applied
	if event.SeverityFilter != "" {
		for _, finding := range response.ScanResults.Findings {
			if !isHighPrioritySeverity(finding.Severity) && event.SeverityFilter == "HIGH" {
				t.Errorf("Severity filter not applied correctly: found %s severity", finding.Severity)
			}
		}
	}
	
	// Validate max findings limit
	if event.MaxFindings > 0 && len(response.ScanResults.Findings) > event.MaxFindings {
		t.Errorf("MaxFindings limit not applied: expected max %d, got %d", event.MaxFindings, len(response.ScanResults.Findings))
	}
	
	// Validate output format
	if event.OutputFormat == "summary" && len(response.ScanResults.Findings) > 0 {
		t.Error("Summary format should not include detailed findings")
	}
}

func validateConfigurationBehavior(t *testing.T, event types.LambdaEvent, response *types.LambdaResponse) {
	t.Helper()
	
	// Validate severity filter behavior
	if event.SeverityFilter != "" {
		for _, finding := range response.ScanResults.Findings {
			if event.SeverityFilter == "HIGH" && !isHighPrioritySeverity(finding.Severity) {
				t.Errorf("Severity filter not working: found %s severity with HIGH filter", finding.Severity)
			}
		}
	}
	
	// Validate max findings behavior
	if event.MaxFindings > 0 && len(response.ScanResults.Findings) > event.MaxFindings {
		t.Errorf("Max findings limit exceeded: %d > %d", len(response.ScanResults.Findings), event.MaxFindings)
	}
	
	// Validate output format behavior
	if event.OutputFormat == "summary" && len(response.ScanResults.Findings) > 0 {
		t.Error("Summary format should not include findings")
	}
}

func isHighPrioritySeverity(severity string) bool {
	return severity == "CRITICAL" || severity == "HIGH"
}

// Mock layer analyzer for controlled testing
type mockLayerAnalyzer struct {
	inventory *types.PackageInventory
}

func (m *mockLayerAnalyzer) AnalyzeLayers(ctx context.Context, layers []types.ImageLayer) (*types.PackageInventory, error) {
	if m.inventory != nil {
		return m.inventory, nil
	}
	return &types.PackageInventory{
		Packages:  []types.Package{},
		OS:        "ubuntu",
		OSVersion: "20.04",
	}, nil
}

func (m *mockLayerAnalyzer) ExtractPackages(ctx context.Context, layer types.ImageLayer) ([]types.Package, error) {
	return []types.Package{}, nil
}
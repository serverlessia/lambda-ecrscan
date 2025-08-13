package integration

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"ecr-image-scanner/pkg/types"
	"ecr-image-scanner/test/fixtures"
)

// TestLocalBinaryExecution tests the compiled binary with sample inputs
func TestLocalBinaryExecution(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping local binary test in short mode")
	}

	// Build the binary first
	binaryPath := buildTestBinary(t)
	defer os.Remove(binaryPath)

	testCases := []struct {
		name        string
		input       types.LambdaEvent
		expectError bool
	}{
		{
			name:        "basic scan",
			input:       fixtures.TestLambdaEvents["basic"],
			expectError: false,
		},
		{
			name:        "enhanced scan",
			input:       fixtures.TestLambdaEvents["enhanced"],
			expectError: false,
		},
		{
			name:        "with filters",
			input:       fixtures.TestLambdaEvents["with-filters"],
			expectError: false,
		},
		{
			name:        "custom config",
			input:       fixtures.TestLambdaEvents["custom-config"],
			expectError: false,
		},
		{
			name: "invalid input",
			input: types.LambdaEvent{
				ImageURL: "",
				Tag:      "latest",
			},
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Prepare input JSON
			inputJSON, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("Failed to marshal input: %v", err)
			}

			// Execute binary with input
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			cmd := exec.CommandContext(ctx, binaryPath)
			cmd.Stdin = bytes.NewReader(inputJSON)
			
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err = cmd.Run()
			
			// For validation errors, the binary should exit with non-zero code
			if tc.expectError {
				if err == nil {
					t.Error("Expected binary to exit with error, but it succeeded")
				}
				t.Logf("Expected error output: %s", stderr.String())
				return
			}

			if err != nil {
				t.Fatalf("Binary execution failed: %v\nStderr: %s", err, stderr.String())
			}

			// Parse output
			var response types.LambdaResponse
			if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse binary output: %v\nOutput: %s", err, stdout.String())
			}

			// Validate response structure
			validateLambdaResponse(t, &response, tc.input)

			t.Logf("Binary test %s completed successfully", tc.name)
			t.Logf("Total vulnerabilities: %d", response.ScanResults.TotalVulnerabilities)
		})
	}
}

// TestLocalBinaryWithEnvironmentVariables tests binary with different environment configurations
func TestLocalBinaryWithEnvironmentVariables(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping local binary test in short mode")
	}

	binaryPath := buildTestBinary(t)
	defer os.Remove(binaryPath)

	testCases := []struct {
		name    string
		envVars map[string]string
		input   types.LambdaEvent
	}{
		{
			name: "with AWS region",
			envVars: map[string]string{
				"AWS_REGION": "us-west-2",
			},
			input: fixtures.TestLambdaEvents["basic"],
		},
		{
			name: "with log level",
			envVars: map[string]string{
				"LOG_LEVEL": "DEBUG",
			},
			input: fixtures.TestLambdaEvents["basic"],
		},
		{
			name: "with custom timeout",
			envVars: map[string]string{
				"DEFAULT_TIMEOUT": "600",
			},
			input: fixtures.TestLambdaEvents["basic"],
		},
		{
			name: "with cache disabled",
			envVars: map[string]string{
				"CACHE_ENABLED": "false",
			},
			input: fixtures.TestLambdaEvents["basic"],
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Set environment variables
			originalEnv := make(map[string]string)
			for key, value := range tc.envVars {
				originalEnv[key] = os.Getenv(key)
				os.Setenv(key, value)
			}
			
			// Restore environment after test
			defer func() {
				for key, originalValue := range originalEnv {
					if originalValue == "" {
						os.Unsetenv(key)
					} else {
						os.Setenv(key, originalValue)
					}
				}
			}()

			// Prepare input
			inputJSON, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("Failed to marshal input: %v", err)
			}

			// Execute binary
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			cmd := exec.CommandContext(ctx, binaryPath)
			cmd.Stdin = bytes.NewReader(inputJSON)
			
			// Copy current environment and add test variables
			cmd.Env = os.Environ()
			for key, value := range tc.envVars {
				cmd.Env = append(cmd.Env, key+"="+value)
			}

			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err = cmd.Run()
			if err != nil {
				t.Fatalf("Binary execution failed: %v\nStderr: %s", err, stderr.String())
			}

			// Parse and validate output
			var response types.LambdaResponse
			if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse binary output: %v\nOutput: %s", err, stdout.String())
			}

			validateLambdaResponse(t, &response, tc.input)
			t.Logf("Environment test %s completed successfully", tc.name)
		})
	}
}

// TestLocalBinaryInputFormats tests different input formats and edge cases
func TestLocalBinaryInputFormats(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping local binary test in short mode")
	}

	binaryPath := buildTestBinary(t)
	defer os.Remove(binaryPath)

	testCases := []struct {
		name        string
		input       string
		expectError bool
	}{
		{
			name:        "valid JSON input",
			input:       `{"imageUrl":"123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo","tag":"latest","scanMode":"basic"}`,
			expectError: false,
		},
		{
			name:        "minimal JSON input",
			input:       `{"imageUrl":"123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo","tag":"latest"}`,
			expectError: false,
		},
		{
			name:        "invalid JSON",
			input:       `{"imageUrl":"test","tag":}`,
			expectError: true,
		},
		{
			name:        "empty input",
			input:       ``,
			expectError: true,
		},
		{
			name:        "null input",
			input:       `null`,
			expectError: true,
		},
		{
			name:        "array input",
			input:       `[]`,
			expectError: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
			defer cancel()

			cmd := exec.CommandContext(ctx, binaryPath)
			cmd.Stdin = bytes.NewReader([]byte(tc.input))
			
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err := cmd.Run()
			
			if tc.expectError {
				if err == nil {
					t.Error("Expected binary to exit with error for invalid input")
				}
				t.Logf("Expected error: %s", stderr.String())
				return
			}

			if err != nil {
				t.Fatalf("Binary execution failed: %v\nStderr: %s", err, stderr.String())
			}

			// For valid inputs, verify we get valid JSON output
			var response types.LambdaResponse
			if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse binary output: %v\nOutput: %s", err, stdout.String())
			}

			t.Logf("Input format test %s completed successfully", tc.name)
		})
	}
}

// TestLocalBinaryPerformance tests binary performance with different scenarios
func TestLocalBinaryPerformance(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping performance test in short mode")
	}

	binaryPath := buildTestBinary(t)
	defer os.Remove(binaryPath)

	testCases := []struct {
		name        string
		input       types.LambdaEvent
		maxDuration time.Duration
	}{
		{
			name:        "basic scan performance",
			input:       fixtures.TestLambdaEvents["basic"],
			maxDuration: 30 * time.Second,
		},
		{
			name:        "enhanced scan performance",
			input:       fixtures.TestLambdaEvents["enhanced"],
			maxDuration: 45 * time.Second,
		},
		{
			name:        "filtered scan performance",
			input:       fixtures.TestLambdaEvents["with-filters"],
			maxDuration: 35 * time.Second,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			inputJSON, err := json.Marshal(tc.input)
			if err != nil {
				t.Fatalf("Failed to marshal input: %v", err)
			}

			startTime := time.Now()
			
			ctx, cancel := context.WithTimeout(context.Background(), tc.maxDuration*2)
			defer cancel()

			cmd := exec.CommandContext(ctx, binaryPath)
			cmd.Stdin = bytes.NewReader(inputJSON)
			
			var stdout, stderr bytes.Buffer
			cmd.Stdout = &stdout
			cmd.Stderr = &stderr

			err = cmd.Run()
			duration := time.Since(startTime)

			if err != nil {
				t.Fatalf("Binary execution failed: %v\nStderr: %s", err, stderr.String())
			}

			if duration > tc.maxDuration {
				t.Errorf("Binary execution took too long: %v (max: %v)", duration, tc.maxDuration)
			}

			// Parse output to verify it's valid
			var response types.LambdaResponse
			if err := json.Unmarshal(stdout.Bytes(), &response); err != nil {
				t.Fatalf("Failed to parse binary output: %v", err)
			}

			t.Logf("Performance test %s completed in %v", tc.name, duration)
			t.Logf("Found %d vulnerabilities", response.ScanResults.TotalVulnerabilities)
		})
	}
}

// TestLocalBinaryStdinStdout tests that binary properly handles stdin/stdout
func TestLocalBinaryStdinStdout(t *testing.T) {
	if testing.Short() {
		t.Skip("Skipping local binary test in short mode")
	}

	binaryPath := buildTestBinary(t)
	defer os.Remove(binaryPath)

	input := fixtures.TestLambdaEvents["basic"]
	inputJSON, err := json.Marshal(input)
	if err != nil {
		t.Fatalf("Failed to marshal input: %v", err)
	}

	// Test that binary reads from stdin and writes to stdout
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	cmd := exec.CommandContext(ctx, binaryPath)
	
	// Set up pipes
	stdin, err := cmd.StdinPipe()
	if err != nil {
		t.Fatalf("Failed to create stdin pipe: %v", err)
	}
	
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("Failed to create stdout pipe: %v", err)
	}
	
	stderr, err := cmd.StderrPipe()
	if err != nil {
		t.Fatalf("Failed to create stderr pipe: %v", err)
	}

	// Start the command
	if err := cmd.Start(); err != nil {
		t.Fatalf("Failed to start command: %v", err)
	}

	// Write input
	go func() {
		defer stdin.Close()
		stdin.Write(inputJSON)
	}()

	// Read output
	var stdoutBuf, stderrBuf bytes.Buffer
	go func() {
		stdoutBuf.ReadFrom(stdout)
	}()
	go func() {
		stderrBuf.ReadFrom(stderr)
	}()

	// Wait for completion
	if err := cmd.Wait(); err != nil {
		t.Fatalf("Command failed: %v\nStderr: %s", err, stderrBuf.String())
	}

	// Validate output
	var response types.LambdaResponse
	if err := json.Unmarshal(stdoutBuf.Bytes(), &response); err != nil {
		t.Fatalf("Failed to parse output: %v\nOutput: %s", err, stdoutBuf.String())
	}

	validateLambdaResponse(t, &response, input)
	t.Log("Stdin/stdout test completed successfully")
}

// buildTestBinary builds the scanner binary for testing
func buildTestBinary(t *testing.T) string {
	t.Helper()

	// Create temporary directory for binary
	tmpDir, err := os.MkdirTemp("", "scanner-test-*")
	if err != nil {
		t.Fatalf("Failed to create temp directory: %v", err)
	}

	binaryPath := filepath.Join(tmpDir, "scanner-test")

	// Build the binary
	cmd := exec.Command("go", "build", "-o", binaryPath, "../../cmd/scanner")
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	
	var stderr bytes.Buffer
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		os.RemoveAll(tmpDir)
		t.Fatalf("Failed to build binary: %v\nStderr: %s", err, stderr.String())
	}

	return binaryPath
}

// validateLambdaResponse validates the structure of a Lambda response
func validateLambdaResponse(t *testing.T, response *types.LambdaResponse, input types.LambdaEvent) {
	t.Helper()

	// Basic structure validation
	if response.Metadata.ScanID == "" {
		t.Error("ScanID should not be empty")
	}
	
	if response.Metadata.ImageURL != input.ImageURL {
		t.Errorf("Expected ImageURL %s, got %s", input.ImageURL, response.Metadata.ImageURL)
	}
	
	if response.Metadata.Tag != input.Tag {
		t.Errorf("Expected Tag %s, got %s", input.Tag, response.Metadata.Tag)
	}

	if response.ScanResults.SeverityCounts == nil {
		t.Error("SeverityCounts should not be nil")
	}
	
	if response.ScanResults.Findings == nil {
		t.Error("Findings should not be nil")
	}

	// Validate scan mode
	expectedMode := types.ScanModeBasic
	if input.ScanMode == "enhanced" {
		expectedMode = types.ScanModeEnhanced
	}
	if response.Metadata.ScanMode != expectedMode {
		t.Errorf("Expected ScanMode %s, got %s", expectedMode, response.Metadata.ScanMode)
	}

	// Validate timestamps
	if response.Metadata.ScanStartTime.IsZero() {
		t.Error("ScanStartTime should be set")
	}
	if response.Metadata.ScanEndTime.IsZero() {
		t.Error("ScanEndTime should be set")
	}
	if response.Metadata.ScanEndTime.Before(response.Metadata.ScanStartTime) {
		t.Error("ScanEndTime should be after ScanStartTime")
	}

	// Validate findings structure
	for i, finding := range response.ScanResults.Findings {
		if i >= 3 { // Only validate first few findings
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
	}
}
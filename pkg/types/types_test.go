package types

import (
	"strings"
	"testing"
	"time"
)

func TestLambdaEvent_Validate(t *testing.T) {
	tests := []struct {
		name        string
		event       *LambdaEvent
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid event",
			event: &LambdaEvent{
				ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
				Tag:      "latest",
				ScanMode: "basic",
			},
			expectError: false,
		},
		{
			name: "missing image URL",
			event: &LambdaEvent{
				Tag: "latest",
			},
			expectError: true,
			errorMsg:    "imageUrl is required",
		},
		{
			name: "empty image URL",
			event: &LambdaEvent{
				ImageURL: "   ",
				Tag:      "latest",
			},
			expectError: true,
			errorMsg:    "imageUrl is required",
		},
		{
			name: "missing tag",
			event: &LambdaEvent{
				ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
			},
			expectError: true,
			errorMsg:    "tag is required",
		},
		{
			name: "invalid scan mode",
			event: &LambdaEvent{
				ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
				Tag:      "latest",
				ScanMode: "invalid",
			},
			expectError: true,
			errorMsg:    "invalid scanMode",
		},
		{
			name: "valid enhanced mode",
			event: &LambdaEvent{
				ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
				Tag:      "latest",
				ScanMode: "enhanced",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLambdaEvent_GetScanMode(t *testing.T) {
	tests := []struct {
		name     string
		event    *LambdaEvent
		expected ScanMode
	}{
		{
			name: "basic mode",
			event: &LambdaEvent{
				ScanMode: "basic",
			},
			expected: ScanModeBasic,
		},
		{
			name: "enhanced mode",
			event: &LambdaEvent{
				ScanMode: "enhanced",
			},
			expected: ScanModeEnhanced,
		},
		{
			name: "empty mode defaults to basic",
			event: &LambdaEvent{
				ScanMode: "",
			},
			expected: ScanModeBasic,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.event.GetScanMode()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestScanMode_IsValid(t *testing.T) {
	tests := []struct {
		name     string
		mode     ScanMode
		expected bool
	}{
		{
			name:     "basic mode is valid",
			mode:     ScanModeBasic,
			expected: true,
		},
		{
			name:     "enhanced mode is valid",
			mode:     ScanModeEnhanced,
			expected: true,
		},
		{
			name:     "invalid mode",
			mode:     ScanMode("invalid"),
			expected: false,
		},
		{
			name:     "empty mode is invalid",
			mode:     ScanMode(""),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := tt.mode.IsValid()
			if result != tt.expected {
				t.Errorf("expected %t, got %t", tt.expected, result)
			}
		})
	}
}

func TestPackage_Validate(t *testing.T) {
	tests := []struct {
		name        string
		pkg         *Package
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid package",
			pkg: &Package{
				Name:    "curl",
				Version: "7.68.0-1ubuntu2.7",
				Type:    "deb",
			},
			expectError: false,
		},
		{
			name: "missing name",
			pkg: &Package{
				Version: "7.68.0-1ubuntu2.7",
				Type:    "deb",
			},
			expectError: true,
			errorMsg:    "package name is required",
		},
		{
			name: "missing version",
			pkg: &Package{
				Name: "curl",
				Type: "deb",
			},
			expectError: true,
			errorMsg:    "package version is required",
		},
		{
			name: "missing type",
			pkg: &Package{
				Name:    "curl",
				Version: "7.68.0-1ubuntu2.7",
			},
			expectError: true,
			errorMsg:    "package type is required",
		},
		{
			name: "invalid type",
			pkg: &Package{
				Name:    "curl",
				Version: "7.68.0-1ubuntu2.7",
				Type:    "invalid",
			},
			expectError: true,
			errorMsg:    "invalid package type",
		},
		{
			name: "valid rpm package",
			pkg: &Package{
				Name:    "curl",
				Version: "7.68.0-1.el8",
				Type:    "rpm",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.pkg.Validate()

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestVulnerabilityFinding_Validate(t *testing.T) {
	tests := []struct {
		name        string
		finding     *VulnerabilityFinding
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid finding",
			finding: &VulnerabilityFinding{
				CVE:         "CVE-2021-1234",
				Package:     "curl",
				Version:     "7.68.0-1ubuntu2.7",
				Severity:    "HIGH",
				Description: "Test vulnerability",
			},
			expectError: false,
		},
		{
			name: "missing CVE",
			finding: &VulnerabilityFinding{
				Package:     "curl",
				Version:     "7.68.0-1ubuntu2.7",
				Severity:    "HIGH",
				Description: "Test vulnerability",
			},
			expectError: true,
			errorMsg:    "CVE is required",
		},
		{
			name: "invalid severity",
			finding: &VulnerabilityFinding{
				CVE:         "CVE-2021-1234",
				Package:     "curl",
				Version:     "7.68.0-1ubuntu2.7",
				Severity:    "INVALID",
				Description: "Test vulnerability",
			},
			expectError: true,
			errorMsg:    "invalid severity",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.finding.Validate()

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestScanResults_Validate(t *testing.T) {
	tests := []struct {
		name        string
		results     *ScanResults
		expectError bool
		errorMsg    string
	}{
		{
			name: "valid results",
			results: &ScanResults{
				TotalVulnerabilities: 1,
				SeverityCounts:      map[string]int{"HIGH": 1},
				Findings: []VulnerabilityFinding{
					{
						CVE:         "CVE-2021-1234",
						Package:     "curl",
						Version:     "7.68.0-1ubuntu2.7",
						Severity:    "HIGH",
						Description: "Test vulnerability",
					},
				},
			},
			expectError: false,
		},
		{
			name: "negative total vulnerabilities",
			results: &ScanResults{
				TotalVulnerabilities: -1,
				SeverityCounts:      map[string]int{},
				Findings:            []VulnerabilityFinding{},
			},
			expectError: true,
			errorMsg:    "totalVulnerabilities cannot be negative",
		},
		{
			name: "nil severity counts",
			results: &ScanResults{
				TotalVulnerabilities: 0,
				SeverityCounts:      nil,
				Findings:            []VulnerabilityFinding{},
			},
			expectError: true,
			errorMsg:    "severityCounts cannot be nil",
		},
		{
			name: "mismatch between total and findings count",
			results: &ScanResults{
				TotalVulnerabilities: 2,
				SeverityCounts:      map[string]int{"HIGH": 1},
				Findings: []VulnerabilityFinding{
					{
						CVE:         "CVE-2021-1234",
						Package:     "curl",
						Version:     "7.68.0-1ubuntu2.7",
						Severity:    "HIGH",
						Description: "Test vulnerability",
					},
				},
			},
			expectError: true,
			errorMsg:    "totalVulnerabilities (2) does not match findings count (1)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.results.Validate()

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestLambdaEvent_ValidateAdvanced(t *testing.T) {
	tests := []struct {
		name        string
		event       *LambdaEvent
		expectError bool
		errorMsg    string
	}{
		{
			name: "invalid severity filter",
			event: &LambdaEvent{
				ImageURL:       "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
				Tag:            "latest",
				SeverityFilter: "INVALID",
			},
			expectError: true,
			errorMsg:    "invalid severityFilter",
		},
		{
			name: "valid severity filter - case insensitive",
			event: &LambdaEvent{
				ImageURL:       "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
				Tag:            "latest",
				SeverityFilter: "high",
			},
			expectError: false,
		},
		{
			name: "negative max findings",
			event: &LambdaEvent{
				ImageURL:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
				Tag:         "latest",
				MaxFindings: -1,
			},
			expectError: true,
			errorMsg:    "maxFindings cannot be negative",
		},
		{
			name: "negative timeout",
			event: &LambdaEvent{
				ImageURL:       "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
				Tag:            "latest",
				TimeoutSeconds: -1,
			},
			expectError: true,
			errorMsg:    "timeoutSeconds cannot be negative",
		},
		{
			name: "timeout exceeds maximum",
			event: &LambdaEvent{
				ImageURL:       "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
				Tag:            "latest",
				TimeoutSeconds: 1000,
			},
			expectError: true,
			errorMsg:    "timeoutSeconds cannot exceed 900 seconds",
		},
		{
			name: "invalid output format",
			event: &LambdaEvent{
				ImageURL:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
				Tag:          "latest",
				OutputFormat: "invalid",
			},
			expectError: true,
			errorMsg:    "invalid outputFormat",
		},
		{
			name: "valid output format - case insensitive",
			event: &LambdaEvent{
				ImageURL:     "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
				Tag:          "latest",
				OutputFormat: "DETAILED",
			},
			expectError: false,
		},
		{
			name: "invalid region format",
			event: &LambdaEvent{
				ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
				Tag:      "latest",
				Region:   "us",
			},
			expectError: true,
			errorMsg:    "invalid region format",
		},
		{
			name: "valid region format",
			event: &LambdaEvent{
				ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
				Tag:      "latest",
				Region:   "us-east-1",
			},
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.event.Validate()

			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
					return
				}
				if tt.errorMsg != "" && !strings.Contains(err.Error(), tt.errorMsg) {
					t.Errorf("expected error message to contain '%s', got '%s'", tt.errorMsg, err.Error())
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
			}
		})
	}
}

func TestPackage_ValidateAllTypes(t *testing.T) {
	validTypes := []string{"deb", "rpm", "apk", "jar", "npm", "pip", "gem", "go"}

	for _, pkgType := range validTypes {
		t.Run("valid_type_"+pkgType, func(t *testing.T) {
			pkg := &Package{
				Name:    "test-package",
				Version: "1.0.0",
				Type:    pkgType,
			}

			err := pkg.Validate()
			if err != nil {
				t.Errorf("expected no error for valid type %s, got %v", pkgType, err)
			}
		})
	}

	// Test case insensitive validation
	t.Run("case_insensitive_type", func(t *testing.T) {
		pkg := &Package{
			Name:    "test-package",
			Version: "1.0.0",
			Type:    "DEB",
		}

		err := pkg.Validate()
		if err != nil {
			t.Errorf("expected no error for uppercase type, got %v", err)
		}
	})
}

func TestVulnerabilityFinding_ValidateAllSeverities(t *testing.T) {
	validSeverities := []string{"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"}

	for _, severity := range validSeverities {
		t.Run("valid_severity_"+severity, func(t *testing.T) {
			finding := &VulnerabilityFinding{
				CVE:         "CVE-2021-1234",
				Package:     "test-package",
				Version:     "1.0.0",
				Severity:    severity,
				Description: "Test vulnerability",
			}

			err := finding.Validate()
			if err != nil {
				t.Errorf("expected no error for valid severity %s, got %v", severity, err)
			}
		})
	}

	// Test case insensitive validation
	t.Run("case_insensitive_severity", func(t *testing.T) {
		finding := &VulnerabilityFinding{
			CVE:         "CVE-2021-1234",
			Package:     "test-package",
			Version:     "1.0.0",
			Severity:    "high",
			Description: "Test vulnerability",
		}

		err := finding.Validate()
		if err != nil {
			t.Errorf("expected no error for lowercase severity, got %v", err)
		}
	})
}

func TestScanResults_ValidateWithInvalidFindings(t *testing.T) {
	results := &ScanResults{
		TotalVulnerabilities: 2,
		SeverityCounts:      map[string]int{"HIGH": 1, "INVALID": 1},
		Findings: []VulnerabilityFinding{
			{
				CVE:         "CVE-2021-1234",
				Package:     "test-package",
				Version:     "1.0.0",
				Severity:    "HIGH",
				Description: "Valid finding",
			},
			{
				CVE:         "", // Invalid - empty CVE
				Package:     "test-package",
				Version:     "1.0.0",
				Severity:    "HIGH",
				Description: "Invalid finding",
			},
		},
	}

	err := results.Validate()
	if err == nil {
		t.Error("expected error for invalid finding but got none")
		return
	}

	if !strings.Contains(err.Error(), "finding 1 is invalid") {
		t.Errorf("expected error message about invalid finding, got %s", err.Error())
	}
}

func TestScanMode_String(t *testing.T) {
	tests := []struct {
		mode     ScanMode
		expected string
	}{
		{ScanModeBasic, "basic"},
		{ScanModeEnhanced, "enhanced"},
		{ScanMode("custom"), "custom"},
	}

	for _, tt := range tests {
		t.Run(string(tt.mode), func(t *testing.T) {
			result := tt.mode.String()
			if result != tt.expected {
				t.Errorf("expected %s, got %s", tt.expected, result)
			}
		})
	}
}

func TestComplexValidationScenarios(t *testing.T) {
	t.Run("complete_valid_event", func(t *testing.T) {
		event := &LambdaEvent{
			ImageURL:        "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
			Tag:             "v1.2.3",
			ScanMode:        "enhanced",
			Region:          "us-east-1",
			SeverityFilter:  "HIGH",
			MaxFindings:     100,
			TimeoutSeconds:  600,
			OutputFormat:    "detailed",
			Config:          map[string]string{"key": "value"},
		}

		err := event.Validate()
		if err != nil {
			t.Errorf("expected no error for complete valid event, got %v", err)
		}
	})

	t.Run("whitespace_handling", func(t *testing.T) {
		event := &LambdaEvent{
			ImageURL: "  123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo  ",
			Tag:      "  latest  ",
		}

		// Should fail because TrimSpace is used in validation
		err := event.Validate()
		if err != nil {
			t.Errorf("expected no error for event with whitespace, got %v", err)
		}
	})

	t.Run("edge_case_values", func(t *testing.T) {
		event := &LambdaEvent{
			ImageURL:       "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
			Tag:            "latest",
			MaxFindings:    0,     // Zero should be valid
			TimeoutSeconds: 900,   // Maximum allowed
		}

		err := event.Validate()
		if err != nil {
			t.Errorf("expected no error for edge case values, got %v", err)
		}
	})
}

func TestDataStructureInitialization(t *testing.T) {
	t.Run("lambda_response_initialization", func(t *testing.T) {
		response := &LambdaResponse{
			ScanResults: ScanResults{
				TotalVulnerabilities: 0,
				SeverityCounts:      make(map[string]int),
				Findings:            []VulnerabilityFinding{},
			},
			Metadata: ScanMetadata{
				ScanID:        "test-scan-123",
				ImageURL:      "test-image",
				Tag:           "latest",
				ScanMode:      ScanModeBasic,
				ScanStartTime: time.Now(),
				ScanEndTime:   time.Now(),
				DatabaseInfo: DatabaseInfo{
					LastUpdated: time.Now(),
					Version:     "1.0.0",
					Sources:     []string{"test-source"},
				},
			},
		}

		// Verify structure is properly initialized
		if response.ScanResults.SeverityCounts == nil {
			t.Error("SeverityCounts should be initialized")
		}
		if response.ScanResults.Findings == nil {
			t.Error("Findings should be initialized")
		}
		if response.Metadata.ScanID == "" {
			t.Error("ScanID should be set")
		}
	})

	t.Run("package_inventory_initialization", func(t *testing.T) {
		inventory := &PackageInventory{
			Packages:  []Package{},
			OS:        "ubuntu",
			OSVersion: "20.04",
		}

		if inventory.Packages == nil {
			t.Error("Packages should be initialized")
		}
		if len(inventory.Packages) != 0 {
			t.Error("Packages should be empty initially")
		}
	})
}

// Helper function to check if a string contains a substring
func contains(s, substr string) bool {
	return strings.Contains(s, substr)
}
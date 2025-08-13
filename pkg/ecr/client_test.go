package ecr

import (
	"context"
	"testing"

	appErrors "ecr-image-scanner/pkg/errors"
)

func TestParseRepositoryFromImageURL(t *testing.T) {
	tests := []struct {
		name        string
		imageURL    string
		expected    string
		expectError bool
	}{
		{
			name:        "valid ECR URL",
			imageURL:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
			expected:    "my-repo",
			expectError: false,
		},
		{
			name:        "valid ECR URL with nested repo",
			imageURL:    "123456789012.dkr.ecr.us-west-2.amazonaws.com/team/my-app",
			expected:    "team/my-app",
			expectError: false,
		},
		{
			name:        "invalid URL - no slash",
			imageURL:    "123456789012.dkr.ecr.us-east-1.amazonaws.com",
			expected:    "",
			expectError: true,
		},
		{
			name:        "invalid URL - empty repo",
			imageURL:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/",
			expected:    "",
			expectError: true,
		},
		{
			name:        "empty URL",
			imageURL:    "",
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseRepositoryFromImageURL(tt.imageURL)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("expected %s, got %s", tt.expected, result)
				}
			}
		})
	}
}

func TestParseRegionFromImageURL(t *testing.T) {
	tests := []struct {
		name        string
		imageURL    string
		expected    string
		expectError bool
	}{
		{
			name:        "valid ECR URL - us-east-1",
			imageURL:    "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
			expected:    "us-east-1",
			expectError: false,
		},
		{
			name:        "valid ECR URL - us-west-2",
			imageURL:    "123456789012.dkr.ecr.us-west-2.amazonaws.com/team/my-app",
			expected:    "us-west-2",
			expectError: false,
		},
		{
			name:        "valid ECR URL - eu-west-1",
			imageURL:    "123456789012.dkr.ecr.eu-west-1.amazonaws.com/my-repo",
			expected:    "eu-west-1",
			expectError: false,
		},
		{
			name:        "invalid URL - not ECR format",
			imageURL:    "docker.io/library/nginx",
			expected:    "",
			expectError: true,
		},
		{
			name:        "invalid URL - missing parts",
			imageURL:    "123456789012.amazonaws.com/my-repo",
			expected:    "",
			expectError: true,
		},
		{
			name:        "empty URL",
			imageURL:    "",
			expected:    "",
			expectError: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := ParseRegionFromImageURL(tt.imageURL)
			
			if tt.expectError {
				if err == nil {
					t.Errorf("expected error but got none")
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
				}
				if result != tt.expected {
					t.Errorf("expected %s, got %s", tt.expected, result)
				}
			}
		})
	}
}

// Test helper functions for ECR client testing

func TestNewClient_ValidationOnly(t *testing.T) {
	tests := []struct {
		name        string
		region      string
		expectError bool
		errorType   string
	}{
		{
			name:        "empty region",
			region:      "",
			expectError: true,
			errorType:   "INVALID_REGION",
		},
		{
			name:        "whitespace region",
			region:      "   ",
			expectError: true,
			errorType:   "INVALID_REGION",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			client, err := NewClient(ctx, tt.region)

			if tt.expectError {
				if err == nil {
					t.Error("expected error but got none")
					return
				}
				if scannerErr, ok := err.(*appErrors.ScannerError); ok {
					if scannerErr.Code != tt.errorType {
						t.Errorf("expected error code %s, got %s", tt.errorType, scannerErr.Code)
					}
				} else {
					t.Errorf("expected ScannerError, got %T", err)
				}
			} else {
				if err != nil {
					t.Errorf("unexpected error: %v", err)
					return
				}
				if client == nil {
					t.Error("expected client but got nil")
					return
				}
			}
		})
	}
}

// Additional ECR client tests focusing on utility functions and error handling

// Additional ECR client tests can be added here for specific edge cases
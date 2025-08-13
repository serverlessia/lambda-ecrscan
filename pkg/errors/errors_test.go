package errors

import (
	"fmt"
	"testing"
	"time"
)

func TestScannerError_Error(t *testing.T) {
	tests := []struct {
		name     string
		err      *ScannerError
		expected string
	}{
		{
			name: "error without cause",
			err: &ScannerError{
				Type:    ErrorTypeAuth,
				Code:    "AUTH_FAILED",
				Message: "Authentication failed",
			},
			expected: "AUTH_ERROR [AUTH_FAILED]: Authentication failed",
		},
		{
			name: "error with cause",
			err: &ScannerError{
				Type:    ErrorTypeNetwork,
				Code:    "CONNECTION_FAILED",
				Message: "Network connection failed",
				Cause:   fmt.Errorf("connection refused"),
			},
			expected: "NETWORK_ERROR [CONNECTION_FAILED]: Network connection failed (caused by: connection refused)",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.err.Error(); got != tt.expected {
				t.Errorf("ScannerError.Error() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestScannerError_IsRetryable(t *testing.T) {
	tests := []struct {
		name      string
		retryable bool
		expected  bool
	}{
		{
			name:      "retryable error",
			retryable: true,
			expected:  true,
		},
		{
			name:      "non-retryable error",
			retryable: false,
			expected:  false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := &ScannerError{Retryable: tt.retryable}
			if got := err.IsRetryable(); got != tt.expected {
				t.Errorf("ScannerError.IsRetryable() = %v, want %v", got, tt.expected)
			}
		})
	}
}

func TestScannerError_WithDetail(t *testing.T) {
	err := NewScannerError(ErrorTypeAuth, "TEST_CODE", "Test message", false)
	result := err.WithDetail("key1", "value1").WithDetail("key2", "value2")

	if result.Details["key1"] != "value1" {
		t.Errorf("Expected detail key1=value1, got %s", result.Details["key1"])
	}
	if result.Details["key2"] != "value2" {
		t.Errorf("Expected detail key2=value2, got %s", result.Details["key2"])
	}
}

func TestScannerError_WithComponent(t *testing.T) {
	err := NewScannerError(ErrorTypeAuth, "TEST_CODE", "Test message", false)
	result := err.WithComponent("test_component")

	if result.Component != "test_component" {
		t.Errorf("Expected component=test_component, got %s", result.Component)
	}
}

func TestScannerError_WithOperation(t *testing.T) {
	err := NewScannerError(ErrorTypeAuth, "TEST_CODE", "Test message", false)
	result := err.WithOperation("test_operation")

	if result.Operation != "test_operation" {
		t.Errorf("Expected operation=test_operation, got %s", result.Operation)
	}
}

func TestNewScannerError(t *testing.T) {
	err := NewScannerError(ErrorTypeValidation, "VALIDATION_FAILED", "Validation failed", false)

	if err.Type != ErrorTypeValidation {
		t.Errorf("Expected type=%s, got %s", ErrorTypeValidation, err.Type)
	}
	if err.Code != "VALIDATION_FAILED" {
		t.Errorf("Expected code=VALIDATION_FAILED, got %s", err.Code)
	}
	if err.Message != "Validation failed" {
		t.Errorf("Expected message=Validation failed, got %s", err.Message)
	}
	if err.Retryable != false {
		t.Errorf("Expected retryable=false, got %t", err.Retryable)
	}
	if err.Details == nil {
		t.Error("Expected Details to be initialized")
	}
	if err.Timestamp.IsZero() {
		t.Error("Expected Timestamp to be set")
	}
}

func TestWrapError(t *testing.T) {
	originalErr := fmt.Errorf("original error")
	wrappedErr := WrapError(originalErr, ErrorTypeNetwork, "WRAPPED_ERROR", "Wrapped error", true)

	if wrappedErr.Cause != originalErr {
		t.Errorf("Expected cause to be original error, got %v", wrappedErr.Cause)
	}
	if wrappedErr.Type != ErrorTypeNetwork {
		t.Errorf("Expected type=%s, got %s", ErrorTypeNetwork, wrappedErr.Type)
	}
	if wrappedErr.Retryable != true {
		t.Errorf("Expected retryable=true, got %t", wrappedErr.Retryable)
	}
}

func TestAuthErrors(t *testing.T) {
	t.Run("NewECRAuthError", func(t *testing.T) {
		originalErr := fmt.Errorf("auth failed")
		err := NewECRAuthError(originalErr)

		if err.Type != ErrorTypeAuth {
			t.Errorf("Expected type=%s, got %s", ErrorTypeAuth, err.Type)
		}
		if err.Code != "ECR_AUTH_FAILED" {
			t.Errorf("Expected code=ECR_AUTH_FAILED, got %s", err.Code)
		}
		if err.Retryable != false {
			t.Errorf("Expected retryable=false, got %t", err.Retryable)
		}
	})

	t.Run("NewTokenExpiredError", func(t *testing.T) {
		err := NewTokenExpiredError()

		if err.Type != ErrorTypeAuth {
			t.Errorf("Expected type=%s, got %s", ErrorTypeAuth, err.Type)
		}
		if err.Code != "TOKEN_EXPIRED" {
			t.Errorf("Expected code=TOKEN_EXPIRED, got %s", err.Code)
		}
		if err.Details["retry_action"] != "obtain_new_token" {
			t.Errorf("Expected retry_action=obtain_new_token, got %s", err.Details["retry_action"])
		}
	})
}

func TestNetworkErrors(t *testing.T) {
	t.Run("NewECRConnectionError", func(t *testing.T) {
		originalErr := fmt.Errorf("connection failed")
		err := NewECRConnectionError(originalErr)

		if err.Type != ErrorTypeNetwork {
			t.Errorf("Expected type=%s, got %s", ErrorTypeNetwork, err.Type)
		}
		if err.Code != "ECR_CONNECTION_FAILED" {
			t.Errorf("Expected code=ECR_CONNECTION_FAILED, got %s", err.Code)
		}
		if err.Retryable != true {
			t.Errorf("Expected retryable=true, got %t", err.Retryable)
		}
	})

	t.Run("NewLayerDownloadError", func(t *testing.T) {
		originalErr := fmt.Errorf("download failed")
		layerDigest := "sha256:abc123"
		err := NewLayerDownloadError(layerDigest, originalErr)

		if err.Type != ErrorTypeNetwork {
			t.Errorf("Expected type=%s, got %s", ErrorTypeNetwork, err.Type)
		}
		if err.Code != "LAYER_DOWNLOAD_FAILED" {
			t.Errorf("Expected code=LAYER_DOWNLOAD_FAILED, got %s", err.Code)
		}
		if err.Details["layer_digest"] != layerDigest {
			t.Errorf("Expected layer_digest=%s, got %s", layerDigest, err.Details["layer_digest"])
		}
	})

	t.Run("NewTimeoutError", func(t *testing.T) {
		operation := "test_operation"
		timeout := 30 * time.Second
		err := NewTimeoutError(operation, timeout)

		if err.Type != ErrorTypeNetwork {
			t.Errorf("Expected type=%s, got %s", ErrorTypeNetwork, err.Type)
		}
		if err.Code != "OPERATION_TIMEOUT" {
			t.Errorf("Expected code=OPERATION_TIMEOUT, got %s", err.Code)
		}
		if err.Details["operation"] != operation {
			t.Errorf("Expected operation=%s, got %s", operation, err.Details["operation"])
		}
	})
}

func TestImageErrors(t *testing.T) {
	t.Run("NewInvalidImageURLError", func(t *testing.T) {
		imageURL := "invalid-url"
		err := NewInvalidImageURLError(imageURL)

		if err.Type != ErrorTypeImage {
			t.Errorf("Expected type=%s, got %s", ErrorTypeImage, err.Type)
		}
		if err.Code != "INVALID_IMAGE_URL" {
			t.Errorf("Expected code=INVALID_IMAGE_URL, got %s", err.Code)
		}
		if err.Details["image_url"] != imageURL {
			t.Errorf("Expected image_url=%s, got %s", imageURL, err.Details["image_url"])
		}
	})

	t.Run("NewImageNotFoundError", func(t *testing.T) {
		repo := "test-repo"
		tag := "test-tag"
		err := NewImageNotFoundError(repo, tag)

		if err.Type != ErrorTypeImage {
			t.Errorf("Expected type=%s, got %s", ErrorTypeImage, err.Type)
		}
		if err.Code != "IMAGE_NOT_FOUND" {
			t.Errorf("Expected code=IMAGE_NOT_FOUND, got %s", err.Code)
		}
		if err.Details["repository"] != repo {
			t.Errorf("Expected repository=%s, got %s", repo, err.Details["repository"])
		}
		if err.Details["tag"] != tag {
			t.Errorf("Expected tag=%s, got %s", tag, err.Details["tag"])
		}
	})
}

func TestScanningErrors(t *testing.T) {
	t.Run("NewVulnDatabaseError", func(t *testing.T) {
		originalErr := fmt.Errorf("database error")
		err := NewVulnDatabaseError(originalErr)

		if err.Type != ErrorTypeScanning {
			t.Errorf("Expected type=%s, got %s", ErrorTypeScanning, err.Type)
		}
		if err.Code != "VULN_DB_ERROR" {
			t.Errorf("Expected code=VULN_DB_ERROR, got %s", err.Code)
		}
		if err.Retryable != true {
			t.Errorf("Expected retryable=true, got %t", err.Retryable)
		}
	})

	t.Run("NewPartialScanError", func(t *testing.T) {
		completedLayers := 3
		totalLayers := 5
		originalErr := fmt.Errorf("partial failure")
		err := NewPartialScanError(completedLayers, totalLayers, originalErr)

		if err.Type != ErrorTypeScanning {
			t.Errorf("Expected type=%s, got %s", ErrorTypeScanning, err.Type)
		}
		if err.Code != "PARTIAL_SCAN_COMPLETED" {
			t.Errorf("Expected code=PARTIAL_SCAN_COMPLETED, got %s", err.Code)
		}
		if err.Details["completed_layers"] != "3" {
			t.Errorf("Expected completed_layers=3, got %s", err.Details["completed_layers"])
		}
		if err.Details["total_layers"] != "5" {
			t.Errorf("Expected total_layers=5, got %s", err.Details["total_layers"])
		}
		if err.Details["completion_percentage"] != "60.0" {
			t.Errorf("Expected completion_percentage=60.0, got %s", err.Details["completion_percentage"])
		}
	})
}

func TestResourceErrors(t *testing.T) {
	t.Run("NewMemoryLimitError", func(t *testing.T) {
		currentUsage := int64(2 * 1024 * 1024 * 1024) // 2GB
		limit := int64(1 * 1024 * 1024 * 1024)        // 1GB
		err := NewMemoryLimitError(currentUsage, limit)

		if err.Type != ErrorTypeResource {
			t.Errorf("Expected type=%s, got %s", ErrorTypeResource, err.Type)
		}
		if err.Code != "MEMORY_LIMIT_EXCEEDED" {
			t.Errorf("Expected code=MEMORY_LIMIT_EXCEEDED, got %s", err.Code)
		}
		if err.Details["current_usage_mb"] != "2048" {
			t.Errorf("Expected current_usage_mb=2048, got %s", err.Details["current_usage_mb"])
		}
		if err.Details["limit_mb"] != "1024" {
			t.Errorf("Expected limit_mb=1024, got %s", err.Details["limit_mb"])
		}
	})

	t.Run("NewLambdaTimeoutError", func(t *testing.T) {
		remainingTime := 15 * time.Second
		err := NewLambdaTimeoutError(remainingTime)

		if err.Type != ErrorTypeResource {
			t.Errorf("Expected type=%s, got %s", ErrorTypeResource, err.Type)
		}
		if err.Code != "LAMBDA_TIMEOUT_APPROACHING" {
			t.Errorf("Expected code=LAMBDA_TIMEOUT_APPROACHING, got %s", err.Code)
		}
		if err.Details["remaining_seconds"] != "15" {
			t.Errorf("Expected remaining_seconds=15, got %s", err.Details["remaining_seconds"])
		}
	})
}

func TestValidationErrors(t *testing.T) {
	t.Run("NewRequiredFieldError", func(t *testing.T) {
		field := "imageUrl"
		err := NewRequiredFieldError(field)

		if err.Type != ErrorTypeValidation {
			t.Errorf("Expected type=%s, got %s", ErrorTypeValidation, err.Type)
		}
		if err.Code != "REQUIRED_FIELD_MISSING" {
			t.Errorf("Expected code=REQUIRED_FIELD_MISSING, got %s", err.Code)
		}
		if err.Details["field"] != field {
			t.Errorf("Expected field=%s, got %s", field, err.Details["field"])
		}
	})

	t.Run("NewInvalidFieldValueError", func(t *testing.T) {
		field := "scanMode"
		value := "invalid"
		expectedFormat := "basic or enhanced"
		err := NewInvalidFieldValueError(field, value, expectedFormat)

		if err.Type != ErrorTypeValidation {
			t.Errorf("Expected type=%s, got %s", ErrorTypeValidation, err.Type)
		}
		if err.Code != "INVALID_FIELD_VALUE" {
			t.Errorf("Expected code=INVALID_FIELD_VALUE, got %s", err.Code)
		}
		if err.Details["field"] != field {
			t.Errorf("Expected field=%s, got %s", field, err.Details["field"])
		}
		if err.Details["provided_value"] != value {
			t.Errorf("Expected provided_value=%s, got %s", value, err.Details["provided_value"])
		}
		if err.Details["expected_format"] != expectedFormat {
			t.Errorf("Expected expected_format=%s, got %s", expectedFormat, err.Details["expected_format"])
		}
	})
}

func TestErrorClassificationHelpers(t *testing.T) {
	t.Run("IsRetryableError", func(t *testing.T) {
		retryableErr := NewScannerError(ErrorTypeNetwork, "TEST", "Test", true)
		nonRetryableErr := NewScannerError(ErrorTypeAuth, "TEST", "Test", false)
		regularErr := fmt.Errorf("regular error")

		if !IsRetryableError(retryableErr) {
			t.Error("Expected retryable ScannerError to be retryable")
		}
		if IsRetryableError(nonRetryableErr) {
			t.Error("Expected non-retryable ScannerError to not be retryable")
		}
		if IsRetryableError(regularErr) {
			t.Error("Expected regular error to not be retryable")
		}
	})

	t.Run("GetErrorType", func(t *testing.T) {
		scannerErr := NewScannerError(ErrorTypeNetwork, "TEST", "Test", true)
		regularErr := fmt.Errorf("regular error")

		if GetErrorType(scannerErr) != ErrorTypeNetwork {
			t.Errorf("Expected ErrorTypeNetwork, got %s", GetErrorType(scannerErr))
		}
		if GetErrorType(regularErr) != ErrorTypeUnknown {
			t.Errorf("Expected ErrorTypeUnknown, got %s", GetErrorType(regularErr))
		}
	})

	t.Run("IsTemporaryError", func(t *testing.T) {
		networkErr := NewScannerError(ErrorTypeNetwork, "TEST", "Test", true)
		resourceErr := NewScannerError(ErrorTypeResource, "TEST", "Test", true)
		authErr := NewScannerError(ErrorTypeAuth, "TEST", "Test", false)
		dbInitErr := NewDatabaseInitError(fmt.Errorf("init failed"))
		dbCorruptedErr := NewDatabaseCorruptedError(fmt.Errorf("corrupted"))

		if !IsTemporaryError(networkErr) {
			t.Error("Expected network error to be temporary")
		}
		if !IsTemporaryError(resourceErr) {
			t.Error("Expected resource error to be temporary")
		}
		if IsTemporaryError(authErr) {
			t.Error("Expected auth error to not be temporary")
		}
		if !IsTemporaryError(dbInitErr) {
			t.Error("Expected database init error to be temporary")
		}
		if IsTemporaryError(dbCorruptedErr) {
			t.Error("Expected database corrupted error to not be temporary")
		}
	})

	t.Run("IsPermanentError", func(t *testing.T) {
		authErr := NewScannerError(ErrorTypeAuth, "TEST", "Test", false)
		imageErr := NewScannerError(ErrorTypeImage, "TEST", "Test", false)
		validationErr := NewScannerError(ErrorTypeValidation, "TEST", "Test", false)
		networkErr := NewScannerError(ErrorTypeNetwork, "TEST", "Test", true)
		dbCorruptedErr := NewDatabaseCorruptedError(fmt.Errorf("corrupted"))
		dbInitErr := NewDatabaseInitError(fmt.Errorf("init failed"))

		if !IsPermanentError(authErr) {
			t.Error("Expected auth error to be permanent")
		}
		if !IsPermanentError(imageErr) {
			t.Error("Expected image error to be permanent")
		}
		if !IsPermanentError(validationErr) {
			t.Error("Expected validation error to be permanent")
		}
		if IsPermanentError(networkErr) {
			t.Error("Expected network error to not be permanent")
		}
		if !IsPermanentError(dbCorruptedErr) {
			t.Error("Expected database corrupted error to be permanent")
		}
		if IsPermanentError(dbInitErr) {
			t.Error("Expected database init error to not be permanent")
		}
	})
}
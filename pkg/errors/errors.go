package errors

import (
	"fmt"
	"time"
)

// ErrorType represents different categories of errors
type ErrorType string

const (
	// Authentication and authorization errors
	ErrorTypeAuth ErrorType = "AUTH_ERROR"
	
	// Network connectivity and communication errors
	ErrorTypeNetwork ErrorType = "NETWORK_ERROR"
	
	// Image-related errors (invalid URLs, missing tags, corrupted layers)
	ErrorTypeImage ErrorType = "IMAGE_ERROR"
	
	// Vulnerability scanning and analysis errors
	ErrorTypeScanning ErrorType = "SCANNING_ERROR"
	
	// Resource-related errors (timeouts, memory limits)
	ErrorTypeResource ErrorType = "RESOURCE_ERROR"
	
	// Configuration and validation errors
	ErrorTypeValidation ErrorType = "VALIDATION_ERROR"
	
	// Database-related errors
	ErrorTypeDatabase ErrorType = "DATABASE_ERROR"
	
	// Unknown or unexpected errors
	ErrorTypeUnknown ErrorType = "UNKNOWN_ERROR"
)

// ScannerError represents a structured error with context
type ScannerError struct {
	Type        ErrorType         `json:"type"`
	Code        string            `json:"code"`
	Message     string            `json:"message"`
	Details     map[string]string `json:"details,omitempty"`
	Retryable   bool              `json:"retryable"`
	Cause       error             `json:"-"` // Original error, not serialized
	Timestamp   time.Time         `json:"timestamp"`
	Component   string            `json:"component,omitempty"`
	Operation   string            `json:"operation,omitempty"`
}

// Error implements the error interface
func (e *ScannerError) Error() string {
	if e.Cause != nil {
		return fmt.Sprintf("%s [%s]: %s (caused by: %v)", e.Type, e.Code, e.Message, e.Cause)
	}
	return fmt.Sprintf("%s [%s]: %s", e.Type, e.Code, e.Message)
}

// Unwrap returns the underlying error for error unwrapping
func (e *ScannerError) Unwrap() error {
	return e.Cause
}

// IsRetryable returns whether the error is retryable
func (e *ScannerError) IsRetryable() bool {
	return e.Retryable
}

// WithDetail adds a detail to the error
func (e *ScannerError) WithDetail(key, value string) *ScannerError {
	if e.Details == nil {
		e.Details = make(map[string]string)
	}
	e.Details[key] = value
	return e
}

// WithComponent sets the component that generated the error
func (e *ScannerError) WithComponent(component string) *ScannerError {
	e.Component = component
	return e
}

// WithOperation sets the operation that was being performed
func (e *ScannerError) WithOperation(operation string) *ScannerError {
	e.Operation = operation
	return e
}

// NewScannerError creates a new ScannerError
func NewScannerError(errorType ErrorType, code, message string, retryable bool) *ScannerError {
	return &ScannerError{
		Type:      errorType,
		Code:      code,
		Message:   message,
		Retryable: retryable,
		Timestamp: time.Now(),
		Details:   make(map[string]string),
	}
}

// WrapError wraps an existing error with scanner error context
func WrapError(err error, errorType ErrorType, code, message string, retryable bool) *ScannerError {
	return &ScannerError{
		Type:      errorType,
		Code:      code,
		Message:   message,
		Retryable: retryable,
		Cause:     err,
		Timestamp: time.Now(),
		Details:   make(map[string]string),
	}
}

// Authentication Errors
func NewAuthError(code, message string, cause error) *ScannerError {
	return WrapError(cause, ErrorTypeAuth, code, message, false)
}

func NewECRAuthError(cause error) *ScannerError {
	return NewAuthError("ECR_AUTH_FAILED", "Failed to authenticate with ECR", cause)
}

func NewTokenExpiredError() *ScannerError {
	return NewAuthError("TOKEN_EXPIRED", "ECR authorization token has expired", nil).
		WithDetail("retry_action", "obtain_new_token")
}

// Network Errors
func NewNetworkError(code, message string, cause error, retryable bool) *ScannerError {
	return WrapError(cause, ErrorTypeNetwork, code, message, retryable)
}

func NewECRConnectionError(cause error) *ScannerError {
	return NewNetworkError("ECR_CONNECTION_FAILED", "Failed to connect to ECR", cause, true).
		WithDetail("retry_delay", "exponential_backoff")
}

func NewLayerDownloadError(layerDigest string, cause error) *ScannerError {
	return NewNetworkError("LAYER_DOWNLOAD_FAILED", "Failed to download image layer", cause, true).
		WithDetail("layer_digest", layerDigest).
		WithDetail("retry_action", "retry_download")
}

func NewTimeoutError(operation string, timeout time.Duration) *ScannerError {
	return NewNetworkError("OPERATION_TIMEOUT", fmt.Sprintf("Operation timed out after %v", timeout), nil, true).
		WithDetail("operation", operation).
		WithDetail("timeout_seconds", fmt.Sprintf("%.0f", timeout.Seconds()))
}

// Image Errors
func NewImageError(code, message string, cause error) *ScannerError {
	return WrapError(cause, ErrorTypeImage, code, message, false)
}

func NewInvalidImageURLError(imageURL string) *ScannerError {
	return NewImageError("INVALID_IMAGE_URL", "Invalid ECR image URL format", nil).
		WithDetail("image_url", imageURL).
		WithDetail("expected_format", "<account-id>.dkr.ecr.<region>.amazonaws.com/<repository>")
}

func NewImageNotFoundError(repository, tag string) *ScannerError {
	return NewImageError("IMAGE_NOT_FOUND", "Image not found in ECR repository", nil).
		WithDetail("repository", repository).
		WithDetail("tag", tag)
}

func NewManifestParseError(cause error) *ScannerError {
	return NewImageError("MANIFEST_PARSE_FAILED", "Failed to parse image manifest", cause).
		WithDetail("format", "docker_v2_or_oci_v1")
}

func NewCorruptedLayerError(layerDigest string, cause error) *ScannerError {
	return NewImageError("CORRUPTED_LAYER", "Image layer is corrupted or unreadable", cause).
		WithDetail("layer_digest", layerDigest)
}

func NewUnsupportedImageFormatError(mediaType string) *ScannerError {
	return NewImageError("UNSUPPORTED_FORMAT", "Unsupported image format", nil).
		WithDetail("media_type", mediaType).
		WithDetail("supported_formats", "docker_v2,oci_v1")
}

// Scanning Errors
func NewScanningError(code, message string, cause error, retryable bool) *ScannerError {
	return WrapError(cause, ErrorTypeScanning, code, message, retryable)
}

func NewVulnDatabaseError(cause error) *ScannerError {
	return NewScanningError("VULN_DB_ERROR", "Vulnerability database error", cause, true).
		WithDetail("retry_action", "reinitialize_database")
}

func NewPackageAnalysisError(layerDigest string, cause error) *ScannerError {
	return NewScanningError("PACKAGE_ANALYSIS_FAILED", "Failed to analyze packages in layer", cause, false).
		WithDetail("layer_digest", layerDigest)
}

func NewScanModeError(mode string) *ScannerError {
	return NewScanningError("INVALID_SCAN_MODE", "Invalid or unsupported scan mode", nil, false).
		WithDetail("provided_mode", mode).
		WithDetail("supported_modes", "basic,enhanced")
}

func NewPartialScanError(completedLayers, totalLayers int, cause error) *ScannerError {
	return NewScanningError("PARTIAL_SCAN_COMPLETED", "Scan completed with partial results", cause, false).
		WithDetail("completed_layers", fmt.Sprintf("%d", completedLayers)).
		WithDetail("total_layers", fmt.Sprintf("%d", totalLayers)).
		WithDetail("completion_percentage", fmt.Sprintf("%.1f", float64(completedLayers)/float64(totalLayers)*100))
}

// Resource Errors
func NewResourceError(code, message string, cause error) *ScannerError {
	return WrapError(cause, ErrorTypeResource, code, message, false)
}

func NewMemoryLimitError(currentUsage, limit int64) *ScannerError {
	return NewResourceError("MEMORY_LIMIT_EXCEEDED", "Memory usage exceeded configured limit", nil).
		WithDetail("current_usage_mb", fmt.Sprintf("%d", currentUsage/1024/1024)).
		WithDetail("limit_mb", fmt.Sprintf("%d", limit/1024/1024))
}

func NewLambdaTimeoutError(remainingTime time.Duration) *ScannerError {
	return NewResourceError("LAMBDA_TIMEOUT_APPROACHING", "Lambda function timeout approaching", nil).
		WithDetail("remaining_seconds", fmt.Sprintf("%.0f", remainingTime.Seconds()))
}

func NewLayerSizeLimitError(layerSize, maxSize int64) *ScannerError {
	return NewResourceError("LAYER_SIZE_EXCEEDED", "Layer size exceeds maximum allowed size", nil).
		WithDetail("layer_size_mb", fmt.Sprintf("%d", layerSize/1024/1024)).
		WithDetail("max_size_mb", fmt.Sprintf("%d", maxSize/1024/1024))
}

// Validation Errors
func NewValidationError(code, message string, field string) *ScannerError {
	err := NewScannerError(ErrorTypeValidation, code, message, false)
	if field != "" {
		err.WithDetail("field", field)
	}
	return err
}

func NewRequiredFieldError(field string) *ScannerError {
	return NewValidationError("REQUIRED_FIELD_MISSING", fmt.Sprintf("Required field '%s' is missing", field), field)
}

func NewInvalidFieldValueError(field, value, expectedFormat string) *ScannerError {
	return NewValidationError("INVALID_FIELD_VALUE", fmt.Sprintf("Invalid value for field '%s'", field), field).
		WithDetail("provided_value", value).
		WithDetail("expected_format", expectedFormat)
}

// Database Errors
func NewDatabaseError(code, message string, cause error, retryable bool) *ScannerError {
	return WrapError(cause, ErrorTypeDatabase, code, message, retryable)
}

func NewDatabaseInitError(cause error) *ScannerError {
	return NewDatabaseError("DB_INIT_FAILED", "Failed to initialize vulnerability database", cause, true)
}

func NewDatabaseCorruptedError(cause error) *ScannerError {
	return NewDatabaseError("DB_CORRUPTED", "Vulnerability database is corrupted", cause, false)
}

// Unknown Errors
func NewUnknownError(cause error) *ScannerError {
	return WrapError(cause, ErrorTypeUnknown, "UNKNOWN_ERROR", "An unexpected error occurred", false)
}

// Error Classification Helpers

// IsRetryableError checks if an error is retryable
func IsRetryableError(err error) bool {
	if scannerErr, ok := err.(*ScannerError); ok {
		return scannerErr.IsRetryable()
	}
	return false
}

// GetErrorType extracts the error type from an error
func GetErrorType(err error) ErrorType {
	if scannerErr, ok := err.(*ScannerError); ok {
		return scannerErr.Type
	}
	return ErrorTypeUnknown
}

// IsTemporaryError checks if an error is likely temporary
func IsTemporaryError(err error) bool {
	if scannerErr, ok := err.(*ScannerError); ok {
		switch scannerErr.Type {
		case ErrorTypeNetwork, ErrorTypeResource:
			return true
		case ErrorTypeDatabase:
			return scannerErr.Code == "DB_INIT_FAILED"
		default:
			return false
		}
	}
	return false
}

// IsPermanentError checks if an error is permanent and should not be retried
func IsPermanentError(err error) bool {
	if scannerErr, ok := err.(*ScannerError); ok {
		switch scannerErr.Type {
		case ErrorTypeAuth, ErrorTypeImage, ErrorTypeValidation:
			return true
		case ErrorTypeDatabase:
			return scannerErr.Code == "DB_CORRUPTED"
		default:
			return false
		}
	}
	return false
}
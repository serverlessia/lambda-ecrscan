package handler

import (
	"context"
	"fmt"
	"log"
	"os"
	"strconv"
	"strings"
	"time"

	"ecr-image-scanner/pkg/types"
	"ecr-image-scanner/pkg/errors"
)

// Config holds the configuration for the handler
type Config struct {
	AWSRegion      string
	VulnDBSource   string
	LogLevel       string
	MaxLayerSize   int64
	CacheEnabled   bool
	DefaultTimeout int
}

// Handler manages the Lambda function execution
type Handler struct {
	config *Config
	// Will be populated with dependencies in future tasks
}

// New creates a new handler instance with configuration loaded from environment
func New() *Handler {
	config := loadConfigFromEnvironment()
	return &Handler{
		config: config,
	}
}

// NewWithConfig creates a new handler instance with provided configuration
func NewWithConfig(config *Config) *Handler {
	return &Handler{
		config: config,
	}
}

// Handle processes the Lambda event and returns a response
func (h *Handler) Handle(ctx context.Context, event types.LambdaEvent) (types.LambdaResponse, error) {
	// Generate scan ID
	scanID := generateScanID()
	scanStartTime := time.Now()

	// Add scan context for logging
	h.logInfoWithContext(scanID, "Handler started", map[string]string{
		"image_url": event.ImageURL,
		"tag":       event.Tag,
		"scan_mode": event.ScanMode,
	})

	// Validate input event
	if err := event.Validate(); err != nil {
		validationErr := errors.WrapError(err, errors.ErrorTypeValidation, "INPUT_VALIDATION_FAILED", 
			"Input validation failed", false).
			WithComponent("handler").
			WithOperation("validate_input").
			WithDetail("scan_id", scanID)
		
		h.logErrorWithContext(scanID, "Input validation failed", validationErr)
		return h.createErrorResponseFromScannerError(scanID, event, scanStartTime, validationErr), nil
	}

	// Apply configuration defaults to event
	h.applyConfigDefaults(&event)

	// Log scan start with enhanced context
	h.logInfoWithContext(scanID, "Starting vulnerability scan", map[string]string{
		"image_url":        event.ImageURL,
		"tag":              event.Tag,
		"scan_mode":        string(event.GetScanMode()),
		"region":           event.Region,
		"severity_filter":  event.SeverityFilter,
		"max_findings":     fmt.Sprintf("%d", event.MaxFindings),
		"timeout_seconds":  fmt.Sprintf("%d", event.TimeoutSeconds),
		"output_format":    event.OutputFormat,
	})

	// Create scan metadata
	metadata := types.ScanMetadata{
		ScanID:        scanID,
		ImageURL:      event.ImageURL,
		Tag:           event.Tag,
		ScanMode:      event.GetScanMode(),
		ScanStartTime: scanStartTime,
		DatabaseInfo: types.DatabaseInfo{
			LastUpdated: time.Now(), // Placeholder - will be updated when database is implemented
			Version:     "1.0.0",    // Placeholder
			Sources:     []string{"CVE"}, // Placeholder
		},
	}

	// Check for context timeout
	if deadline, ok := ctx.Deadline(); ok {
		timeRemaining := time.Until(deadline)
		if timeRemaining < 30*time.Second {
			timeoutErr := errors.NewLambdaTimeoutError(timeRemaining).
				WithComponent("handler").
				WithOperation("handle").
				WithDetail("scan_id", scanID)
			
			h.logErrorWithContext(scanID, "Insufficient time remaining for scan", timeoutErr)
			return h.createErrorResponseFromScannerError(scanID, event, scanStartTime, timeoutErr), nil
		}
		
		h.logDebugWithContext(scanID, "Context deadline check passed", map[string]string{
			"time_remaining_seconds": fmt.Sprintf("%.0f", timeRemaining.Seconds()),
		})
	}

	// Placeholder implementation - will be completed in future tasks
	// For now, return a basic response structure with proper error handling
	scanResults := types.ScanResults{
		TotalVulnerabilities: 0,
		SeverityCounts:      h.initializeSeverityCounts(),
		Findings:            []types.VulnerabilityFinding{},
	}

	// Complete scan metadata
	metadata.ScanEndTime = time.Now()
	scanDuration := metadata.ScanEndTime.Sub(metadata.ScanStartTime)

	h.logInfoWithContext(scanID, "Scan completed successfully", map[string]string{
		"duration_ms":           fmt.Sprintf("%.0f", scanDuration.Seconds()*1000),
		"total_vulnerabilities": fmt.Sprintf("%d", scanResults.TotalVulnerabilities),
		"critical_count":        fmt.Sprintf("%d", scanResults.SeverityCounts["CRITICAL"]),
		"high_count":           fmt.Sprintf("%d", scanResults.SeverityCounts["HIGH"]),
		"medium_count":         fmt.Sprintf("%d", scanResults.SeverityCounts["MEDIUM"]),
		"low_count":            fmt.Sprintf("%d", scanResults.SeverityCounts["LOW"]),
	})

	return types.LambdaResponse{
		ScanResults: scanResults,
		Metadata:    metadata,
	}, nil
}

// loadConfigFromEnvironment loads configuration from environment variables
func loadConfigFromEnvironment() *Config {
	config := &Config{
		AWSRegion:      getEnvWithDefault("AWS_REGION", "us-east-1"),
		VulnDBSource:   getEnvWithDefault("VULN_DB_SOURCE", ""),
		LogLevel:       getEnvWithDefault("LOG_LEVEL", "INFO"),
		MaxLayerSize:   getEnvInt64WithDefault("MAX_LAYER_SIZE", 1024*1024*1024), // 1GB default
		CacheEnabled:   getEnvBoolWithDefault("CACHE_ENABLED", true),
		DefaultTimeout: getEnvIntWithDefault("DEFAULT_TIMEOUT_SECONDS", 300), // 5 minutes
	}

	return config
}

// applyConfigDefaults applies configuration defaults to the event
func (h *Handler) applyConfigDefaults(event *types.LambdaEvent) {
	// Set default region if not provided
	if event.Region == "" {
		event.Region = h.config.AWSRegion
	}

	// Set default scan mode if not provided
	if event.ScanMode == "" {
		event.ScanMode = string(types.ScanModeBasic)
	}

	// Set default timeout if not provided
	if event.TimeoutSeconds == 0 {
		event.TimeoutSeconds = h.config.DefaultTimeout
	}

	// Set default max findings if not provided
	if event.MaxFindings == 0 {
		event.MaxFindings = 1000
	}

	// Set default output format if not provided
	if event.OutputFormat == "" {
		event.OutputFormat = "detailed"
	}

	// Initialize config map if nil
	if event.Config == nil {
		event.Config = make(map[string]string)
	}

	// Add handler config to event config
	event.Config["maxLayerSize"] = strconv.FormatInt(h.config.MaxLayerSize, 10)
	event.Config["cacheEnabled"] = strconv.FormatBool(h.config.CacheEnabled)
	event.Config["vulnDBSource"] = h.config.VulnDBSource
}

// createErrorResponse creates a standardized error response
func (h *Handler) createErrorResponse(scanID string, event types.LambdaEvent, startTime time.Time, 
	errorCode, errorMsg string, retryable bool) types.LambdaResponse {
	
	h.logError(fmt.Sprintf("Scan %s failed: %s - %s", scanID, errorCode, errorMsg))

	return types.LambdaResponse{
		ScanResults: types.ScanResults{
			TotalVulnerabilities: 0,
			SeverityCounts:      make(map[string]int),
			Findings:            []types.VulnerabilityFinding{},
		},
		Metadata: types.ScanMetadata{
			ScanID:        scanID,
			ImageURL:      event.ImageURL,
			Tag:           event.Tag,
			ScanMode:      event.GetScanMode(),
			ScanStartTime: startTime,
			ScanEndTime:   time.Now(),
			DatabaseInfo: types.DatabaseInfo{
				LastUpdated: time.Now(),
				Version:     "1.0.0",
				Sources:     []string{"CVE"},
			},
		},
		Error: fmt.Sprintf("%s: %s (retryable: %t)", errorCode, errorMsg, retryable),
	}
}

// generateScanID generates a unique scan ID
func generateScanID() string {
	return fmt.Sprintf("scan-%d", time.Now().UnixNano())
}

// Logging helper functions
func (h *Handler) logInfo(msg string) {
	if h.shouldLog("INFO") {
		log.Printf("[INFO] %s", msg)
	}
}

func (h *Handler) logError(msg string) {
	if h.shouldLog("ERROR") {
		log.Printf("[ERROR] %s", msg)
	}
}

func (h *Handler) logDebug(msg string) {
	if h.shouldLog("DEBUG") {
		log.Printf("[DEBUG] %s", msg)
	}
}

// Enhanced logging functions with context
func (h *Handler) logInfoWithContext(scanID, msg string, context map[string]string) {
	if h.shouldLog("INFO") {
		contextStr := h.formatLogContext(context)
		log.Printf("[INFO] [%s] %s %s", scanID, msg, contextStr)
	}
}

func (h *Handler) logErrorWithContext(scanID, msg string, err error) {
	if h.shouldLog("ERROR") {
		var contextStr string
		if scannerErr, ok := err.(*errors.ScannerError); ok {
			contextStr = h.formatScannerErrorContext(scannerErr)
		} else {
			contextStr = fmt.Sprintf("error=%v", err)
		}
		log.Printf("[ERROR] [%s] %s %s", scanID, msg, contextStr)
	}
}

func (h *Handler) logDebugWithContext(scanID, msg string, context map[string]string) {
	if h.shouldLog("DEBUG") {
		contextStr := h.formatLogContext(context)
		log.Printf("[DEBUG] [%s] %s %s", scanID, msg, contextStr)
	}
}

func (h *Handler) logWarnWithContext(scanID, msg string, context map[string]string) {
	if h.shouldLog("WARN") {
		contextStr := h.formatLogContext(context)
		log.Printf("[WARN] [%s] %s %s", scanID, msg, contextStr)
	}
}

// formatLogContext formats a context map for logging
func (h *Handler) formatLogContext(context map[string]string) string {
	if len(context) == 0 {
		return ""
	}
	
	var parts []string
	for key, value := range context {
		parts = append(parts, fmt.Sprintf("%s=%s", key, value))
	}
	return fmt.Sprintf("[%s]", strings.Join(parts, " "))
}

// formatScannerErrorContext formats a ScannerError for logging
func (h *Handler) formatScannerErrorContext(err *errors.ScannerError) string {
	var parts []string
	
	parts = append(parts, fmt.Sprintf("type=%s", err.Type))
	parts = append(parts, fmt.Sprintf("code=%s", err.Code))
	parts = append(parts, fmt.Sprintf("retryable=%t", err.Retryable))
	
	if err.Component != "" {
		parts = append(parts, fmt.Sprintf("component=%s", err.Component))
	}
	
	if err.Operation != "" {
		parts = append(parts, fmt.Sprintf("operation=%s", err.Operation))
	}
	
	for key, value := range err.Details {
		parts = append(parts, fmt.Sprintf("%s=%s", key, value))
	}
	
	return fmt.Sprintf("[%s]", strings.Join(parts, " "))
}

func (h *Handler) shouldLog(level string) bool {
	levels := map[string]int{
		"DEBUG": 0,
		"INFO":  1,
		"WARN":  2,
		"ERROR": 3,
	}

	configLevel := levels[strings.ToUpper(h.config.LogLevel)]
	messageLevel := levels[level]

	return messageLevel >= configLevel
}

// Environment variable helper functions
func getEnvWithDefault(key, defaultValue string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return defaultValue
}

func getEnvIntWithDefault(key string, defaultValue int) int {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.Atoi(value); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvInt64WithDefault(key string, defaultValue int64) int64 {
	if value := os.Getenv(key); value != "" {
		if intValue, err := strconv.ParseInt(value, 10, 64); err == nil {
			return intValue
		}
	}
	return defaultValue
}

func getEnvBoolWithDefault(key string, defaultValue bool) bool {
	if value := os.Getenv(key); value != "" {
		if boolValue, err := strconv.ParseBool(value); err == nil {
			return boolValue
		}
	}
	return defaultValue
}

// initializeSeverityCounts initializes severity counts map
func (h *Handler) initializeSeverityCounts() map[string]int {
	return map[string]int{
		"CRITICAL":      0,
		"HIGH":          0,
		"MEDIUM":        0,
		"LOW":           0,
		"INFORMATIONAL": 0,
	}
}

// createErrorResponseFromScannerError creates an error response from a ScannerError
func (h *Handler) createErrorResponseFromScannerError(scanID string, event types.LambdaEvent, startTime time.Time, scannerErr *errors.ScannerError) types.LambdaResponse {
	h.logErrorWithContext(scanID, "Scan failed", scannerErr)

	// Create error message with structured information
	errorMsg := scannerErr.Error()
	if scannerErr.Details != nil && len(scannerErr.Details) > 0 {
		var details []string
		for key, value := range scannerErr.Details {
			details = append(details, fmt.Sprintf("%s=%s", key, value))
		}
		errorMsg = fmt.Sprintf("%s [%s]", errorMsg, strings.Join(details, " "))
	}

	return types.LambdaResponse{
		ScanResults: types.ScanResults{
			TotalVulnerabilities: 0,
			SeverityCounts:      h.initializeSeverityCounts(),
			Findings:            []types.VulnerabilityFinding{},
		},
		Metadata: types.ScanMetadata{
			ScanID:        scanID,
			ImageURL:      event.ImageURL,
			Tag:           event.Tag,
			ScanMode:      event.GetScanMode(),
			ScanStartTime: startTime,
			ScanEndTime:   time.Now(),
			DatabaseInfo: types.DatabaseInfo{
				LastUpdated: time.Now(),
				Version:     "1.0.0",
				Sources:     []string{"CVE"},
			},
		},
		Error: errorMsg,
	}
}
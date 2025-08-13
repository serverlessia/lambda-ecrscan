package types

import (
	"fmt"
	"strings"
	"time"
)

// ScanMode represents the scanning mode
type ScanMode string

const (
	ScanModeBasic    ScanMode = "basic"
	ScanModeEnhanced ScanMode = "enhanced"
)

// LambdaEvent represents the input event for the Lambda function
type LambdaEvent struct {
	ImageURL        string            `json:"imageUrl"`
	Tag             string            `json:"tag"`
	ScanMode        string            `json:"scanMode,omitempty"`        // "basic" or "enhanced"
	Region          string            `json:"region,omitempty"`          // AWS region for ECR
	SeverityFilter  string            `json:"severityFilter,omitempty"`  // "CRITICAL", "HIGH", "MEDIUM", "LOW"
	MaxFindings     int               `json:"maxFindings,omitempty"`     // limit number of findings returned
	TimeoutSeconds  int               `json:"timeoutSeconds,omitempty"`  // scan timeout
	OutputFormat    string            `json:"outputFormat,omitempty"`    // "detailed", "summary"
	Config          map[string]string `json:"config,omitempty"`          // additional configuration options
}

// LambdaResponse represents the response from the Lambda function
type LambdaResponse struct {
	ScanResults ScanResults  `json:"scanResults"`
	Metadata    ScanMetadata `json:"metadata"`
	Error       string       `json:"error,omitempty"`
}

// ScanResults contains the vulnerability scan results
type ScanResults struct {
	TotalVulnerabilities int                    `json:"totalVulnerabilities"`
	SeverityCounts      map[string]int         `json:"severityCounts"`
	Findings            []VulnerabilityFinding `json:"findings"`
}

// VulnerabilityFinding represents a single vulnerability finding
type VulnerabilityFinding struct {
	CVE         string `json:"cve"`
	Package     string `json:"package"`
	Version     string `json:"version"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	FixedIn     string `json:"fixedIn,omitempty"`
}

// ScanMetadata contains metadata about the scan
type ScanMetadata struct {
	ScanID        string       `json:"scanId"`
	ImageURL      string       `json:"imageUrl"`
	Tag           string       `json:"tag"`
	ScanMode      ScanMode     `json:"scanMode"`
	ScanStartTime time.Time    `json:"scanStartTime"`
	ScanEndTime   time.Time    `json:"scanEndTime"`
	DatabaseInfo  DatabaseInfo `json:"databaseInfo"`
}

// DatabaseInfo contains information about the vulnerability database
type DatabaseInfo struct {
	LastUpdated time.Time `json:"lastUpdated"`
	Version     string    `json:"version"`
	Sources     []string  `json:"sources"`
}

// ImageManifest represents a container image manifest
type ImageManifest struct {
	MediaType string        `json:"mediaType"`
	Digest    string        `json:"digest"`
	Layers    []LayerDigest `json:"layers"`
	Config    ConfigDigest  `json:"config"`
}

// LayerDigest represents a layer digest
type LayerDigest struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
}

// ConfigDigest represents a config digest
type ConfigDigest struct {
	Digest    string `json:"digest"`
	MediaType string `json:"mediaType"`
	Size      int64  `json:"size"`
}

// ImageLayer represents a container image layer
type ImageLayer struct {
	Digest  string `json:"digest"`
	Content []byte `json:"content"`
	Size    int64  `json:"size"`
}

// AuthToken represents an ECR authorization token
type AuthToken struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expiresAt"`
	Endpoint  string    `json:"endpoint"`
}

// PackageInventory represents the package inventory of an image
type PackageInventory struct {
	Packages  []Package `json:"packages"`
	OS        string    `json:"os"`
	OSVersion string    `json:"osVersion"`
}

// Package represents a software package
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Type    string `json:"type"` // "deb", "rpm", "apk", etc.
}

// ErrorResponse represents an error response
type ErrorResponse struct {
	Error     string            `json:"error"`
	ErrorCode string            `json:"errorCode"`
	Details   map[string]string `json:"details,omitempty"`
	Retryable bool              `json:"retryable"`
}

// Validate validates the LambdaEvent fields
func (e *LambdaEvent) Validate() error {
	if strings.TrimSpace(e.ImageURL) == "" {
		return fmt.Errorf("imageUrl is required")
	}

	if strings.TrimSpace(e.Tag) == "" {
		return fmt.Errorf("tag is required")
	}

	// Validate scan mode
	if e.ScanMode != "" {
		scanMode := ScanMode(e.ScanMode)
		if scanMode != ScanModeBasic && scanMode != ScanModeEnhanced {
			return fmt.Errorf("invalid scanMode: must be 'basic' or 'enhanced'")
		}
	}

	// Validate severity filter
	if e.SeverityFilter != "" {
		validSeverities := map[string]bool{
			"CRITICAL":      true,
			"HIGH":          true,
			"MEDIUM":        true,
			"LOW":           true,
			"INFORMATIONAL": true,
		}
		if !validSeverities[strings.ToUpper(e.SeverityFilter)] {
			return fmt.Errorf("invalid severityFilter: must be one of CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL")
		}
	}

	// Validate max findings
	if e.MaxFindings < 0 {
		return fmt.Errorf("maxFindings cannot be negative")
	}

	// Validate timeout
	if e.TimeoutSeconds < 0 {
		return fmt.Errorf("timeoutSeconds cannot be negative")
	}
	if e.TimeoutSeconds > 900 { // Lambda max timeout is 15 minutes
		return fmt.Errorf("timeoutSeconds cannot exceed 900 seconds (15 minutes)")
	}

	// Validate output format
	if e.OutputFormat != "" {
		validFormats := map[string]bool{
			"detailed": true,
			"summary":  true,
		}
		if !validFormats[strings.ToLower(e.OutputFormat)] {
			return fmt.Errorf("invalid outputFormat: must be 'detailed' or 'summary'")
		}
	}

	// Validate AWS region format (basic validation)
	if e.Region != "" {
		if len(e.Region) < 3 || !strings.Contains(e.Region, "-") {
			return fmt.Errorf("invalid region format")
		}
	}

	return nil
}

// GetScanMode returns the scan mode as a ScanMode type
func (e *LambdaEvent) GetScanMode() ScanMode {
	if e.ScanMode == "" {
		return ScanModeBasic
	}
	return ScanMode(e.ScanMode)
}

// IsValid checks if the scan mode is valid
func (s ScanMode) IsValid() bool {
	return s == ScanModeBasic || s == ScanModeEnhanced
}

// String returns the string representation of ScanMode
func (s ScanMode) String() string {
	return string(s)
}

// Validate validates the Package fields
func (p *Package) Validate() error {
	if strings.TrimSpace(p.Name) == "" {
		return fmt.Errorf("package name is required")
	}

	if strings.TrimSpace(p.Version) == "" {
		return fmt.Errorf("package version is required")
	}

	if strings.TrimSpace(p.Type) == "" {
		return fmt.Errorf("package type is required")
	}

	// Validate package type
	validTypes := map[string]bool{
		"deb": true,
		"rpm": true,
		"apk": true,
		"jar": true,
		"npm": true,
		"pip": true,
		"gem": true,
		"go":  true,
	}

	if !validTypes[strings.ToLower(p.Type)] {
		return fmt.Errorf("invalid package type: %s", p.Type)
	}

	return nil
}

// Validate validates the VulnerabilityFinding fields
func (v *VulnerabilityFinding) Validate() error {
	if strings.TrimSpace(v.CVE) == "" {
		return fmt.Errorf("CVE is required")
	}

	if strings.TrimSpace(v.Package) == "" {
		return fmt.Errorf("package is required")
	}

	if strings.TrimSpace(v.Version) == "" {
		return fmt.Errorf("version is required")
	}

	if strings.TrimSpace(v.Severity) == "" {
		return fmt.Errorf("severity is required")
	}

	// Validate severity
	validSeverities := map[string]bool{
		"CRITICAL":      true,
		"HIGH":          true,
		"MEDIUM":        true,
		"LOW":           true,
		"INFORMATIONAL": true,
	}

	if !validSeverities[strings.ToUpper(v.Severity)] {
		return fmt.Errorf("invalid severity: %s", v.Severity)
	}

	return nil
}

// Validate validates the ScanResults fields
func (s *ScanResults) Validate() error {
	if s.TotalVulnerabilities < 0 {
		return fmt.Errorf("totalVulnerabilities cannot be negative")
	}

	if s.SeverityCounts == nil {
		return fmt.Errorf("severityCounts cannot be nil")
	}

	if s.Findings == nil {
		return fmt.Errorf("findings cannot be nil")
	}

	// Validate each finding
	for i, finding := range s.Findings {
		if err := finding.Validate(); err != nil {
			return fmt.Errorf("finding %d is invalid: %w", i, err)
		}
	}

	// Validate that total vulnerabilities matches findings count
	if s.TotalVulnerabilities != len(s.Findings) {
		return fmt.Errorf("totalVulnerabilities (%d) does not match findings count (%d)", 
			s.TotalVulnerabilities, len(s.Findings))
	}

	return nil
}
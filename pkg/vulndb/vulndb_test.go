package vulndb

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"ecr-image-scanner/pkg/types"
)

func TestNewVulnDB(t *testing.T) {
	db := NewVulnDB()
	if db == nil {
		t.Fatal("NewVulnDB() returned nil")
	}

	vulnDB, ok := db.(*VulnDB)
	if !ok {
		t.Fatal("NewVulnDB() did not return *VulnDB")
	}

	if vulnDB.initialized {
		t.Error("New VulnDB should not be initialized")
	}

	if vulnDB.vulnerabilities == nil {
		t.Error("vulnerabilities map should be initialized")
	}

	if vulnDB.osVulns == nil {
		t.Error("osVulns map should be initialized")
	}
}

func TestVulnDB_Initialize(t *testing.T) {
	db := NewVulnDB().(*VulnDB)
	ctx := context.Background()

	// Test first initialization
	err := db.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	if !db.initialized {
		t.Error("Database should be initialized after Initialize()")
	}

	if db.dbInfo.LastUpdated.IsZero() {
		t.Error("LastUpdated should be set after initialization")
	}

	// Test double initialization (should not error)
	err = db.Initialize(ctx)
	if err != nil {
		t.Fatalf("Second Initialize() failed: %v", err)
	}
}

func TestVulnDB_FindVulnerabilities(t *testing.T) {
	db := NewVulnDB().(*VulnDB)
	ctx := context.Background()

	// Initialize the database
	err := db.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	tests := []struct {
		name           string
		pkg            types.Package
		os             string
		expectFindings bool
		expectedCVE    string
	}{
		{
			name: "Find Log4j vulnerability",
			pkg: types.Package{
				Name:    "log4j-core",
				Version: "2.14.0",
				Type:    "jar",
			},
			os:             "ubuntu",
			expectFindings: true,
			expectedCVE:    "CVE-2021-44228",
		},
		{
			name: "Find OpenSSL vulnerability",
			pkg: types.Package{
				Name:    "openssl",
				Version: "1.1.1k",
				Type:    "deb",
			},
			os:             "ubuntu",
			expectFindings: true,
			expectedCVE:    "CVE-2022-0778",
		},
		{
			name: "No vulnerability for safe package",
			pkg: types.Package{
				Name:    "safe-package",
				Version: "1.0.0",
				Type:    "deb",
			},
			os:             "ubuntu",
			expectFindings: false,
		},
		{
			name: "No vulnerability for fixed version",
			pkg: types.Package{
				Name:    "log4j-core",
				Version: "2.18.0", // Use a version that's definitely fixed for all CVEs
				Type:    "jar",
			},
			os:             "ubuntu",
			expectFindings: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			findings, err := db.FindVulnerabilities(ctx, tt.pkg, tt.os)
			if err != nil {
				t.Fatalf("FindVulnerabilities() failed: %v", err)
			}

			if tt.expectFindings {
				if len(findings) == 0 {
					t.Error("Expected to find vulnerabilities but got none")
					return
				}

				if tt.expectedCVE != "" {
					found := false
					for _, finding := range findings {
						if finding.CVE == tt.expectedCVE {
							found = true
							break
						}
					}
					if !found {
						t.Errorf("Expected to find CVE %s but didn't", tt.expectedCVE)
					}
				}

				// Validate finding structure
				for _, finding := range findings {
					if finding.CVE == "" {
						t.Error("Finding CVE should not be empty")
					}
					if finding.Package != tt.pkg.Name {
						t.Errorf("Finding package mismatch: got %s, want %s", finding.Package, tt.pkg.Name)
					}
					if finding.Version != tt.pkg.Version {
						t.Errorf("Finding version mismatch: got %s, want %s", finding.Version, tt.pkg.Version)
					}
					if finding.Severity == "" {
						t.Error("Finding severity should not be empty")
					}
				}
			} else {
				if len(findings) > 0 {
					t.Errorf("Expected no vulnerabilities but got %d", len(findings))
				}
			}
		})
	}
}

func TestVulnDB_FindVulnerabilities_NotInitialized(t *testing.T) {
	db := NewVulnDB().(*VulnDB)
	ctx := context.Background()

	pkg := types.Package{
		Name:    "test-package",
		Version: "1.0.0",
		Type:    "deb",
	}

	_, err := db.FindVulnerabilities(ctx, pkg, "ubuntu")
	if err == nil {
		t.Error("Expected error when database not initialized")
	}

	if !strings.Contains(err.Error(), "not initialized") {
		t.Errorf("Expected 'not initialized' error, got: %v", err)
	}
}

func TestVulnDB_GetDatabaseInfo(t *testing.T) {
	db := NewVulnDB().(*VulnDB)
	ctx := context.Background()

	// Test before initialization
	info := db.GetDatabaseInfo()
	if info.Version == "" {
		t.Error("Version should be set even before initialization")
	}
	if len(info.Sources) == 0 {
		t.Error("Sources should be set even before initialization")
	}

	// Test after initialization
	err := db.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	info = db.GetDatabaseInfo()
	if info.LastUpdated.IsZero() {
		t.Error("LastUpdated should be set after initialization")
	}
}

func TestVulnDB_LoadFromJSON(t *testing.T) {
	db := NewVulnDB().(*VulnDB)

	testData := []CVERecord{
		{
			CVE:         "CVE-2023-TEST",
			Description: "Test vulnerability",
			Severity:    "HIGH",
			Score:       7.5,
			Published:   "2023-01-01",
			AffectedPackages: []AffectedPackage{
				{
					Name:     "test-package",
					Type:     "deb",
					OS:       []string{"ubuntu"},
					Versions: []string{"1.0.0-1.0.5"},
					FixedIn:  "1.0.6",
				},
			},
		},
	}

	jsonData, err := json.Marshal(testData)
	if err != nil {
		t.Fatalf("Failed to marshal test data: %v", err)
	}

	err = db.LoadFromJSON(jsonData)
	if err != nil {
		t.Fatalf("LoadFromJSON() failed: %v", err)
	}

	if !db.initialized {
		t.Error("Database should be initialized after LoadFromJSON")
	}

	// Test that data was loaded correctly
	ctx := context.Background()
	pkg := types.Package{
		Name:    "test-package",
		Version: "1.0.3",
		Type:    "deb",
	}

	findings, err := db.FindVulnerabilities(ctx, pkg, "ubuntu")
	if err != nil {
		t.Fatalf("FindVulnerabilities() failed: %v", err)
	}

	if len(findings) < 1 {
		t.Fatalf("Expected at least 1 finding, got %d", len(findings))
	}

	// Check that our test CVE is present
	found := false
	for _, finding := range findings {
		if finding.CVE == "CVE-2023-TEST" {
			found = true
			break
		}
	}
	if !found {
		t.Error("Expected to find CVE-2023-TEST in findings")
	}

	if findings[0].CVE != "CVE-2023-TEST" {
		t.Errorf("Expected CVE-2023-TEST, got %s", findings[0].CVE)
	}
}

func TestVulnDB_LoadFromJSON_InvalidData(t *testing.T) {
	db := NewVulnDB().(*VulnDB)

	invalidJSON := []byte(`{"invalid": "json"}`)
	err := db.LoadFromJSON(invalidJSON)
	if err == nil {
		t.Error("Expected error for invalid JSON")
	}
}

func TestVulnDB_GetStats(t *testing.T) {
	db := NewVulnDB().(*VulnDB)
	ctx := context.Background()

	// Test before initialization
	stats := db.GetStats()
	if stats["initialized"].(bool) {
		t.Error("Database should not be initialized initially")
	}

	// Test after initialization
	err := db.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}

	stats = db.GetStats()
	if !stats["initialized"].(bool) {
		t.Error("Database should be initialized after Initialize()")
	}

	totalVulns, ok := stats["total_vulnerabilities"].(int)
	if !ok || totalVulns <= 0 {
		t.Error("Expected positive number of total vulnerabilities")
	}

	totalPackages, ok := stats["total_packages"].(int)
	if !ok || totalPackages <= 0 {
		t.Error("Expected positive number of total packages")
	}

	supportedOS, ok := stats["supported_os"].(int)
	if !ok || supportedOS <= 0 {
		t.Error("Expected positive number of supported OS")
	}

	severityCounts, ok := stats["severity_counts"].(map[string]int)
	if !ok {
		t.Error("Expected severity_counts to be map[string]int")
	}

	// Check that we have different severity levels
	if len(severityCounts) == 0 {
		t.Error("Expected some severity counts")
	}
}

func TestIsVersionAffected(t *testing.T) {
	db := &VulnDB{}

	tests := []struct {
		name        string
		version     string
		affectedPkg AffectedPackage
		expected    bool
	}{
		{
			name:    "No versions specified - all affected",
			version: "1.0.0",
			affectedPkg: AffectedPackage{
				Versions: []string{},
			},
			expected: true,
		},
		{
			name:    "Exact version match",
			version: "1.0.0",
			affectedPkg: AffectedPackage{
				Versions: []string{"1.0.0", "2.0.0"},
			},
			expected: true,
		},
		{
			name:    "No version match",
			version: "1.5.0",
			affectedPkg: AffectedPackage{
				Versions: []string{"1.0.0", "2.0.0"},
			},
			expected: false,
		},
		{
			name:    "Wildcard match",
			version: "1.2.3",
			affectedPkg: AffectedPackage{
				Versions: []string{"1.2.*"},
			},
			expected: true,
		},
		{
			name:    "Range match",
			version: "1.5.0",
			affectedPkg: AffectedPackage{
				Versions: []string{"1.0.0-2.0.0"},
			},
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := db.isVersionAffected(tt.version, tt.affectedPkg)
			if result != tt.expected {
				t.Errorf("isVersionAffected() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestVersionMatches(t *testing.T) {
	db := &VulnDB{}

	tests := []struct {
		name     string
		version  string
		pattern  string
		expected bool
	}{
		{
			name:     "Wildcard pattern",
			version:  "1.0.0",
			pattern:  "*",
			expected: true,
		},
		{
			name:     "Exact match",
			version:  "1.0.0",
			pattern:  "1.0.0",
			expected: true,
		},
		{
			name:     "No match",
			version:  "1.0.0",
			pattern:  "2.0.0",
			expected: false,
		},
		{
			name:     "Prefix wildcard match",
			version:  "1.2.3",
			pattern:  "1.2.*",
			expected: true,
		},
		{
			name:     "Prefix wildcard no match",
			version:  "1.3.0",
			pattern:  "1.2.*",
			expected: false,
		},
		{
			name:     "Range match",
			version:  "1.5.0",
			pattern:  "1.0.0-2.0.0",
			expected: true,
		},
		{
			name:     "Range no match - below",
			version:  "0.9.0",
			pattern:  "1.0.0-2.0.0",
			expected: false,
		},
		{
			name:     "Range no match - above",
			version:  "2.1.0",
			pattern:  "1.0.0-2.0.0",
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := db.versionMatches(tt.version, tt.pattern)
			if result != tt.expected {
				t.Errorf("versionMatches(%s, %s) = %v, want %v", tt.version, tt.pattern, result, tt.expected)
			}
		})
	}
}

func TestIsPackageAffected(t *testing.T) {
	db := &VulnDB{}

	vuln := CVERecord{
		CVE: "CVE-2023-TEST",
		AffectedPackages: []AffectedPackage{
			{
				Name:     "test-package",
				Type:     "deb",
				OS:       []string{"ubuntu", "debian"},
				Versions: []string{"1.0.0-2.0.0"},
			},
			{
				Name:     "another-package",
				Type:     "rpm",
				OS:       []string{"centos"},
				Versions: []string{"*"},
			},
		},
	}

	tests := []struct {
		name     string
		pkg      types.Package
		os       string
		expected bool
	}{
		{
			name: "Matching package, type, OS, and version",
			pkg: types.Package{
				Name:    "test-package",
				Version: "1.5.0",
				Type:    "deb",
			},
			os:       "ubuntu",
			expected: true,
		},
		{
			name: "Matching package but wrong type",
			pkg: types.Package{
				Name:    "test-package",
				Version: "1.5.0",
				Type:    "rpm",
			},
			os:       "ubuntu",
			expected: false,
		},
		{
			name: "Matching package but wrong OS",
			pkg: types.Package{
				Name:    "test-package",
				Version: "1.5.0",
				Type:    "deb",
			},
			os:       "centos",
			expected: false,
		},
		{
			name: "Matching package but version out of range",
			pkg: types.Package{
				Name:    "test-package",
				Version: "3.0.0",
				Type:    "deb",
			},
			os:       "ubuntu",
			expected: false,
		},
		{
			name: "Different package name",
			pkg: types.Package{
				Name:    "different-package",
				Version: "1.5.0",
				Type:    "deb",
			},
			os:       "ubuntu",
			expected: false,
		},
		{
			name: "Wildcard version match",
			pkg: types.Package{
				Name:    "another-package",
				Version: "5.0.0",
				Type:    "rpm",
			},
			os:       "centos",
			expected: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := db.isPackageAffected(tt.pkg, vuln, tt.os)
			if result != tt.expected {
				t.Errorf("isPackageAffected() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestCreateFinding(t *testing.T) {
	db := &VulnDB{}

	pkg := types.Package{
		Name:    "test-package",
		Version: "1.0.0",
		Type:    "deb",
	}

	vuln := CVERecord{
		CVE:         "CVE-2023-TEST",
		Description: "Test vulnerability description",
		Severity:    "HIGH",
		AffectedPackages: []AffectedPackage{
			{
				Name:    "test-package",
				FixedIn: "1.0.1",
			},
		},
	}

	finding := db.createFinding(pkg, vuln)

	if finding.CVE != vuln.CVE {
		t.Errorf("CVE mismatch: got %s, want %s", finding.CVE, vuln.CVE)
	}

	if finding.Package != pkg.Name {
		t.Errorf("Package mismatch: got %s, want %s", finding.Package, pkg.Name)
	}

	if finding.Version != pkg.Version {
		t.Errorf("Version mismatch: got %s, want %s", finding.Version, pkg.Version)
	}

	if finding.Severity != vuln.Severity {
		t.Errorf("Severity mismatch: got %s, want %s", finding.Severity, vuln.Severity)
	}

	if finding.Description != vuln.Description {
		t.Errorf("Description mismatch: got %s, want %s", finding.Description, vuln.Description)
	}

	if finding.FixedIn != "1.0.1" {
		t.Errorf("FixedIn mismatch: got %s, want %s", finding.FixedIn, "1.0.1")
	}
}

// Benchmark tests
func BenchmarkVulnDB_FindVulnerabilities(b *testing.B) {
	db := NewVulnDB().(*VulnDB)
	ctx := context.Background()

	err := db.Initialize(ctx)
	if err != nil {
		b.Fatalf("Initialize() failed: %v", err)
	}

	pkg := types.Package{
		Name:    "openssl",
		Version: "1.1.1k",
		Type:    "deb",
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := db.FindVulnerabilities(ctx, pkg, "ubuntu")
		if err != nil {
			b.Fatalf("FindVulnerabilities() failed: %v", err)
		}
	}
}

func BenchmarkVulnDB_Initialize(b *testing.B) {
	ctx := context.Background()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		db := NewVulnDB().(*VulnDB)
		err := db.Initialize(ctx)
		if err != nil {
			b.Fatalf("Initialize() failed: %v", err)
		}
	}
}
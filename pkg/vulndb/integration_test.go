package vulndb

import (
	"context"
	"testing"

	"ecr-image-scanner/pkg/interfaces"
	"ecr-image-scanner/pkg/types"
)

// TestVulnDBIntegration tests the vulnerability database integration with interfaces
func TestVulnDBIntegration(t *testing.T) {
	// Test that VulnDB implements the VulnDatabase interface
	var db interfaces.VulnDatabase = NewVulnDB()
	
	ctx := context.Background()
	
	// Test initialization
	err := db.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}
	
	// Test database info
	info := db.GetDatabaseInfo()
	if info.Version == "" {
		t.Error("Database version should not be empty")
	}
	if len(info.Sources) == 0 {
		t.Error("Database sources should not be empty")
	}
	if info.LastUpdated.IsZero() {
		t.Error("LastUpdated should be set after initialization")
	}
	
	// Test vulnerability finding
	testPackages := []types.Package{
		{Name: "log4j-core", Version: "2.14.0", Type: "jar"},
		{Name: "openssl", Version: "1.1.1k", Type: "deb"},
		{Name: "sudo", Version: "1.8.31", Type: "deb"},
		{Name: "nginx", Version: "1.18.0", Type: "deb"},
		{Name: "curl", Version: "7.70.0", Type: "deb"},
	}
	
	for _, pkg := range testPackages {
		findings, err := db.FindVulnerabilities(ctx, pkg, "ubuntu")
		if err != nil {
			t.Errorf("FindVulnerabilities() failed for %s: %v", pkg.Name, err)
			continue
		}
		
		// Validate findings structure
		for _, finding := range findings {
			if finding.CVE == "" {
				t.Errorf("CVE should not be empty for package %s", pkg.Name)
			}
			if finding.Package != pkg.Name {
				t.Errorf("Package name mismatch: got %s, want %s", finding.Package, pkg.Name)
			}
			if finding.Version != pkg.Version {
				t.Errorf("Package version mismatch: got %s, want %s", finding.Version, pkg.Version)
			}
			if finding.Severity == "" {
				t.Errorf("Severity should not be empty for CVE %s", finding.CVE)
			}
			
			// Validate severity values
			validSeverities := map[string]bool{
				"CRITICAL": true, "HIGH": true, "MEDIUM": true, "LOW": true, "INFORMATIONAL": true,
			}
			if !validSeverities[finding.Severity] {
				t.Errorf("Invalid severity %s for CVE %s", finding.Severity, finding.CVE)
			}
		}
	}
}

// TestVulnDBWithDifferentOS tests vulnerability database with different operating systems
func TestVulnDBWithDifferentOS(t *testing.T) {
	db := NewVulnDB()
	ctx := context.Background()
	
	err := db.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}
	
	pkg := types.Package{
		Name:    "openssl",
		Version: "1.1.1k",
		Type:    "deb",
	}
	
	operatingSystems := []string{"ubuntu", "debian", "alpine", "centos", "rhel"}
	
	for _, os := range operatingSystems {
		findings, err := db.FindVulnerabilities(ctx, pkg, os)
		if err != nil {
			t.Errorf("FindVulnerabilities() failed for OS %s: %v", os, err)
			continue
		}
		
		// Some OS should have findings for openssl 1.1.1k
		t.Logf("OS %s: found %d vulnerabilities for %s %s", os, len(findings), pkg.Name, pkg.Version)
	}
}

// TestVulnDBWithDifferentPackageTypes tests vulnerability database with different package types
func TestVulnDBWithDifferentPackageTypes(t *testing.T) {
	db := NewVulnDB()
	ctx := context.Background()
	
	err := db.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}
	
	testCases := []struct {
		name    string
		pkg     types.Package
		os      string
		expectFindings bool
	}{
		{
			name: "Java JAR package",
			pkg: types.Package{
				Name:    "log4j-core",
				Version: "2.14.0",
				Type:    "jar",
			},
			os: "ubuntu",
			expectFindings: true,
		},
		{
			name: "Debian package",
			pkg: types.Package{
				Name:    "openssl",
				Version: "1.1.1k",
				Type:    "deb",
			},
			os: "ubuntu",
			expectFindings: true,
		},
		{
			name: "RPM package",
			pkg: types.Package{
				Name:    "sudo",
				Version: "1.8.31",
				Type:    "rpm",
			},
			os: "centos",
			expectFindings: true,
		},
		{
			name: "Alpine package",
			pkg: types.Package{
				Name:    "openssl",
				Version: "1.1.1k",
				Type:    "apk",
			},
			os: "alpine",
			expectFindings: true,
		},
	}
	
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			findings, err := db.FindVulnerabilities(ctx, tc.pkg, tc.os)
			if err != nil {
				t.Fatalf("FindVulnerabilities() failed: %v", err)
			}
			
			if tc.expectFindings && len(findings) == 0 {
				t.Errorf("Expected to find vulnerabilities for %s %s (%s) on %s", 
					tc.pkg.Name, tc.pkg.Version, tc.pkg.Type, tc.os)
			}
			
			t.Logf("Package %s %s (%s) on %s: found %d vulnerabilities", 
				tc.pkg.Name, tc.pkg.Version, tc.pkg.Type, tc.os, len(findings))
		})
	}
}

// TestVulnDBSeverityFiltering tests that different severity levels are properly handled
func TestVulnDBSeverityFiltering(t *testing.T) {
	db := NewVulnDB()
	ctx := context.Background()
	
	err := db.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}
	
	// Find a package that has vulnerabilities with different severities
	pkg := types.Package{
		Name:    "openssl",
		Version: "1.1.1k",
		Type:    "deb",
	}
	
	findings, err := db.FindVulnerabilities(ctx, pkg, "ubuntu")
	if err != nil {
		t.Fatalf("FindVulnerabilities() failed: %v", err)
	}
	
	if len(findings) == 0 {
		t.Skip("No vulnerabilities found for test package")
	}
	
	// Count findings by severity
	severityCount := make(map[string]int)
	for _, finding := range findings {
		severityCount[finding.Severity]++
	}
	
	t.Logf("Severity distribution for %s %s:", pkg.Name, pkg.Version)
	for severity, count := range severityCount {
		t.Logf("  %s: %d", severity, count)
	}
	
	// Verify we have at least one severity level
	if len(severityCount) == 0 {
		t.Error("Expected at least one severity level")
	}
}

// TestVulnDBConcurrency tests that the vulnerability database is safe for concurrent use
func TestVulnDBConcurrency(t *testing.T) {
	db := NewVulnDB()
	ctx := context.Background()
	
	err := db.Initialize(ctx)
	if err != nil {
		t.Fatalf("Initialize() failed: %v", err)
	}
	
	pkg := types.Package{
		Name:    "openssl",
		Version: "1.1.1k",
		Type:    "deb",
	}
	
	// Run multiple goroutines concurrently
	const numGoroutines = 10
	const numIterations = 100
	
	errChan := make(chan error, numGoroutines)
	
	for i := 0; i < numGoroutines; i++ {
		go func() {
			for j := 0; j < numIterations; j++ {
				_, err := db.FindVulnerabilities(ctx, pkg, "ubuntu")
				if err != nil {
					errChan <- err
					return
				}
				
				// Also test GetDatabaseInfo concurrently
				_ = db.GetDatabaseInfo()
			}
			errChan <- nil
		}()
	}
	
	// Wait for all goroutines to complete
	for i := 0; i < numGoroutines; i++ {
		if err := <-errChan; err != nil {
			t.Errorf("Concurrent access failed: %v", err)
		}
	}
}
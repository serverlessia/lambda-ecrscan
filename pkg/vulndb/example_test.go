package vulndb_test

import (
	"context"
	"fmt"
	"log"

	"ecr-image-scanner/pkg/types"
	"ecr-image-scanner/pkg/vulndb"
)

// ExampleVulnDB_FindVulnerabilities demonstrates how to use the vulnerability database
func ExampleVulnDB_FindVulnerabilities() {
	// Create a new vulnerability database
	db := vulndb.NewVulnDB()

	// Initialize the database with embedded data
	ctx := context.Background()
	err := db.Initialize(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize vulnerability database: %v", err)
	}

	// Create a package to scan
	pkg := types.Package{
		Name:    "openssl",
		Version: "1.1.1k",
		Type:    "deb",
	}

	// Find vulnerabilities for the package
	findings, err := db.FindVulnerabilities(ctx, pkg, "ubuntu")
	if err != nil {
		log.Fatalf("Failed to find vulnerabilities: %v", err)
	}

	// Display results
	fmt.Printf("Found %d vulnerabilities for %s %s:\n", len(findings), pkg.Name, pkg.Version)
	for _, finding := range findings {
		fmt.Printf("- %s: %s (Severity: %s)\n", finding.CVE, finding.Description, finding.Severity)
		if finding.FixedIn != "" {
			fmt.Printf("  Fixed in: %s\n", finding.FixedIn)
		}
	}

	// Get database statistics
	stats := db.(*vulndb.VulnDB).GetStats()
	fmt.Printf("\nDatabase stats: %d total vulnerabilities across %d packages\n", 
		stats["total_vulnerabilities"], stats["total_packages"])
}

// ExampleVulnDB_LoadFromJSON demonstrates loading custom vulnerability data
func ExampleVulnDB_LoadFromJSON() {
	// Create a new vulnerability database
	db := vulndb.NewVulnDB().(*vulndb.VulnDB)

	// Custom vulnerability data in JSON format
	customData := `[
		{
			"cve": "CVE-2023-CUSTOM",
			"description": "Custom vulnerability for demonstration",
			"severity": "HIGH",
			"score": 8.5,
			"published": "2023-01-01",
			"affected_packages": [
				{
					"name": "my-custom-package",
					"type": "deb",
					"os": ["ubuntu", "debian"],
					"versions": ["1.0.0-1.5.0"],
					"fixed_in": "1.5.1"
				}
			]
		}
	]`

	// Load the custom data
	err := db.LoadFromJSON([]byte(customData))
	if err != nil {
		log.Fatalf("Failed to load custom vulnerability data: %v", err)
	}

	// Test with the custom package
	ctx := context.Background()
	pkg := types.Package{
		Name:    "my-custom-package",
		Version: "1.2.0",
		Type:    "deb",
	}

	findings, err := db.FindVulnerabilities(ctx, pkg, "ubuntu")
	if err != nil {
		log.Fatalf("Failed to find vulnerabilities: %v", err)
	}

	fmt.Printf("Found %d vulnerabilities for custom package:\n", len(findings))
	for _, finding := range findings {
		fmt.Printf("- %s: %s\n", finding.CVE, finding.Description)
	}
}

// ExampleVulnDB_ScanModeComparison demonstrates different scanning approaches
func ExampleVulnDB_ScanModeComparison() {
	db := vulndb.NewVulnDB()
	ctx := context.Background()

	err := db.Initialize(ctx)
	if err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	// Test packages with different risk levels
	packages := []types.Package{
		{Name: "log4j-core", Version: "2.14.0", Type: "jar"},
		{Name: "openssl", Version: "1.1.1k", Type: "deb"},
		{Name: "curl", Version: "7.70.0", Type: "deb"},
		{Name: "nginx", Version: "1.18.0", Type: "deb"},
	}

	fmt.Println("Vulnerability Scan Results:")
	fmt.Println("===========================")

	for _, pkg := range packages {
		findings, err := db.FindVulnerabilities(ctx, pkg, "ubuntu")
		if err != nil {
			log.Printf("Error scanning %s: %v", pkg.Name, err)
			continue
		}

		fmt.Printf("\n%s %s (%s):\n", pkg.Name, pkg.Version, pkg.Type)
		if len(findings) == 0 {
			fmt.Println("  No vulnerabilities found")
			continue
		}

		// Group by severity
		severityCount := make(map[string]int)
		for _, finding := range findings {
			severityCount[finding.Severity]++
		}

		fmt.Printf("  Total vulnerabilities: %d\n", len(findings))
		for severity, count := range severityCount {
			fmt.Printf("  %s: %d\n", severity, count)
		}

		// Show first few findings
		maxShow := 3
		if len(findings) < maxShow {
			maxShow = len(findings)
		}
		
		fmt.Println("  Sample findings:")
		for i := 0; i < maxShow; i++ {
			finding := findings[i]
			fmt.Printf("    - %s (%s)\n", finding.CVE, finding.Severity)
		}
		
		if len(findings) > maxShow {
			fmt.Printf("    ... and %d more\n", len(findings)-maxShow)
		}
	}
}
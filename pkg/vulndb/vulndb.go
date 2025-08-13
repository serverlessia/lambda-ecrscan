package vulndb

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"time"

	"ecr-image-scanner/pkg/interfaces"
	"ecr-image-scanner/pkg/types"
)

// VulnDB implements the VulnDatabase interface
type VulnDB struct {
	mu           sync.RWMutex
	vulnerabilities map[string][]CVERecord // key: package name
	osVulns      map[string]map[string][]CVERecord // key: os, package name
	initialized  bool
	dbInfo       types.DatabaseInfo
}

// CVERecord represents a CVE vulnerability record
type CVERecord struct {
	CVE         string   `json:"cve"`
	Description string   `json:"description"`
	Severity    string   `json:"severity"`
	Score       float64  `json:"score"`
	Vector      string   `json:"vector"`
	Published   string   `json:"published"`
	Modified    string   `json:"modified"`
	References  []string `json:"references"`
	
	// Package-specific information
	AffectedPackages []AffectedPackage `json:"affected_packages"`
}

// AffectedPackage represents a package affected by a vulnerability
type AffectedPackage struct {
	Name         string   `json:"name"`
	Type         string   `json:"type"` // deb, rpm, apk, etc.
	OS           []string `json:"os"`   // ubuntu, debian, alpine, etc.
	Versions     []string `json:"versions"`
	FixedIn      string   `json:"fixed_in,omitempty"`
	NotFixedIn   []string `json:"not_fixed_in,omitempty"`
}

// NewVulnDB creates a new vulnerability database instance
func NewVulnDB() interfaces.VulnDatabase {
	return &VulnDB{
		vulnerabilities: make(map[string][]CVERecord),
		osVulns:        make(map[string]map[string][]CVERecord),
		initialized:    false,
		dbInfo: types.DatabaseInfo{
			Version: "1.0.0",
			Sources: []string{"embedded-cve-feed"},
		},
	}
}

// Initialize initializes the vulnerability database
func (v *VulnDB) Initialize(ctx context.Context) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	if v.initialized {
		return nil
	}

	// Load embedded vulnerability data
	if err := v.loadEmbeddedData(ctx); err != nil {
		return fmt.Errorf("failed to load embedded vulnerability data: %w", err)
	}

	v.dbInfo.LastUpdated = time.Now()
	v.initialized = true

	return nil
}

// FindVulnerabilities finds vulnerabilities for a given package
func (v *VulnDB) FindVulnerabilities(ctx context.Context, pkg types.Package, os string) ([]types.VulnerabilityFinding, error) {
	v.mu.RLock()
	defer v.mu.RUnlock()

	if !v.initialized {
		return nil, fmt.Errorf("vulnerability database not initialized")
	}

	var findings []types.VulnerabilityFinding

	// Normalize package name for lookup
	normalizedName := strings.ToLower(pkg.Name)
	normalizedOS := strings.ToLower(os)

	// First, check OS-specific vulnerabilities
	if osVulns, exists := v.osVulns[normalizedOS]; exists {
		if vulns, exists := osVulns[normalizedName]; exists {
			for _, vuln := range vulns {
				if v.isPackageAffected(pkg, vuln, normalizedOS) {
					finding := v.createFinding(pkg, vuln)
					findings = append(findings, finding)
				}
			}
		}
	}

	// Then check general package vulnerabilities
	if vulns, exists := v.vulnerabilities[normalizedName]; exists {
		for _, vuln := range vulns {
			if v.isPackageAffected(pkg, vuln, normalizedOS) {
				finding := v.createFinding(pkg, vuln)
				findings = append(findings, finding)
			}
		}
	}

	return findings, nil
}

// GetDatabaseInfo returns information about the vulnerability database
func (v *VulnDB) GetDatabaseInfo() types.DatabaseInfo {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return v.dbInfo
}

// loadEmbeddedData loads the embedded vulnerability data
func (v *VulnDB) loadEmbeddedData(ctx context.Context) error {
	// Load sample vulnerability data for common packages
	sampleVulns := v.getSampleVulnerabilities()
	
	for _, vuln := range sampleVulns {
		for _, affectedPkg := range vuln.AffectedPackages {
			normalizedName := strings.ToLower(affectedPkg.Name)
			
			// Add to general vulnerabilities
			v.vulnerabilities[normalizedName] = append(v.vulnerabilities[normalizedName], vuln)
			
			// Add to OS-specific vulnerabilities
			for _, osName := range affectedPkg.OS {
				normalizedOS := strings.ToLower(osName)
				if v.osVulns[normalizedOS] == nil {
					v.osVulns[normalizedOS] = make(map[string][]CVERecord)
				}
				v.osVulns[normalizedOS][normalizedName] = append(v.osVulns[normalizedOS][normalizedName], vuln)
			}
		}
	}

	return nil
}

// isPackageAffected checks if a package is affected by a vulnerability
func (v *VulnDB) isPackageAffected(pkg types.Package, vuln CVERecord, os string) bool {
	for _, affectedPkg := range vuln.AffectedPackages {
		// Check package name match
		if strings.ToLower(affectedPkg.Name) != strings.ToLower(pkg.Name) {
			continue
		}

		// Check package type match
		if affectedPkg.Type != "" && strings.ToLower(affectedPkg.Type) != strings.ToLower(pkg.Type) {
			continue
		}

		// Check OS match if specified
		if len(affectedPkg.OS) > 0 {
			osMatch := false
			for _, affectedOS := range affectedPkg.OS {
				if strings.ToLower(affectedOS) == strings.ToLower(os) {
					osMatch = true
					break
				}
			}
			if !osMatch {
				continue
			}
		}

		// Check if version is affected
		if v.isVersionAffected(pkg.Version, affectedPkg) {
			return true
		}
	}

	return false
}

// isVersionAffected checks if a specific version is affected by a vulnerability
func (v *VulnDB) isVersionAffected(version string, affectedPkg AffectedPackage) bool {
	// If no specific versions are listed, assume all versions are affected
	if len(affectedPkg.Versions) == 0 {
		return true
	}

	// Check if version is in the affected versions list
	for _, affectedVersion := range affectedPkg.Versions {
		if v.versionMatches(version, affectedVersion) {
			return true
		}
	}

	return false
}

// versionMatches checks if a version matches a pattern
func (v *VulnDB) versionMatches(version, pattern string) bool {
	// Simple version matching - can be enhanced with proper semver logic
	if pattern == "*" {
		return true
	}

	// Exact match
	if version == pattern {
		return true
	}

	// Range matching (simplified)
	if strings.Contains(pattern, "-") {
		parts := strings.Split(pattern, "-")
		if len(parts) == 2 {
			// Range format: "1.0.0-2.0.0"
			return v.versionInRange(version, parts[0], parts[1])
		}
	}

	// Prefix matching for versions like "1.2.*"
	if strings.HasSuffix(pattern, "*") {
		prefix := strings.TrimSuffix(pattern, "*")
		return strings.HasPrefix(version, prefix)
	}

	return false
}

// versionInRange checks if a version is within a range (simplified)
func (v *VulnDB) versionInRange(version, minVersion, maxVersion string) bool {
	// Simplified version comparison - in production, use proper semver library
	// For now, use basic string comparison which works for simple cases
	return v.compareVersions(version, minVersion) >= 0 && v.compareVersions(version, maxVersion) <= 0
}

// compareVersions compares two version strings (simplified implementation)
func (v *VulnDB) compareVersions(v1, v2 string) int {
	// Split versions into parts
	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")
	
	// Pad shorter version with zeros
	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}
	
	for len(parts1) < maxLen {
		parts1 = append(parts1, "0")
	}
	for len(parts2) < maxLen {
		parts2 = append(parts2, "0")
	}
	
	// Compare each part
	for i := 0; i < maxLen; i++ {
		// Extract numeric part (ignore non-numeric suffixes for now)
		num1 := v.extractNumericPart(parts1[i])
		num2 := v.extractNumericPart(parts2[i])
		
		if num1 < num2 {
			return -1
		} else if num1 > num2 {
			return 1
		}
	}
	
	return 0
}

// extractNumericPart extracts the numeric part from a version component
func (v *VulnDB) extractNumericPart(part string) int {
	// Find the first non-digit character
	i := 0
	for i < len(part) && part[i] >= '0' && part[i] <= '9' {
		i++
	}
	
	if i == 0 {
		return 0
	}
	
	// Convert to integer
	num := 0
	for j := 0; j < i; j++ {
		num = num*10 + int(part[j]-'0')
	}
	
	return num
}

// createFinding creates a VulnerabilityFinding from a CVE record
func (v *VulnDB) createFinding(pkg types.Package, vuln CVERecord) types.VulnerabilityFinding {
	var fixedIn string
	
	// Find the fixed version for this package
	for _, affectedPkg := range vuln.AffectedPackages {
		if strings.ToLower(affectedPkg.Name) == strings.ToLower(pkg.Name) {
			fixedIn = affectedPkg.FixedIn
			break
		}
	}

	return types.VulnerabilityFinding{
		CVE:         vuln.CVE,
		Package:     pkg.Name,
		Version:     pkg.Version,
		Severity:    vuln.Severity,
		Description: vuln.Description,
		FixedIn:     fixedIn,
	}
}

// getSampleVulnerabilities returns sample vulnerability data for testing and basic functionality
func (v *VulnDB) getSampleVulnerabilities() []CVERecord {
	return []CVERecord{
		{
			CVE:         "CVE-2021-44228",
			Description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP and other JNDI related endpoints",
			Severity:    "CRITICAL",
			Score:       10.0,
			Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H",
			Published:   "2021-12-10",
			Modified:    "2021-12-14",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44228"},
			AffectedPackages: []AffectedPackage{
				{
					Name:     "log4j-core",
					Type:     "jar",
					OS:       []string{"ubuntu", "debian", "alpine", "centos", "rhel"},
					Versions: []string{"2.0-2.14.1"},
					FixedIn:  "2.15.0",
				},
			},
		},
		{
			CVE:         "CVE-2022-22965",
			Description: "Spring Framework RCE via Data Binding on JDK 9+",
			Severity:    "CRITICAL",
			Score:       9.8,
			Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Published:   "2022-04-01",
			Modified:    "2022-04-05",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-22965"},
			AffectedPackages: []AffectedPackage{
				{
					Name:     "spring-core",
					Type:     "jar",
					OS:       []string{"ubuntu", "debian", "alpine", "centos", "rhel"},
					Versions: []string{"5.3.0-5.3.17", "5.2.0-5.2.19"},
					FixedIn:  "5.3.18",
				},
			},
		},
		{
			CVE:         "CVE-2021-3156",
			Description: "Heap-based buffer overflow in Sudo (Baron Samedit)",
			Severity:    "HIGH",
			Score:       7.8,
			Vector:      "CVSS:3.1/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Published:   "2021-01-26",
			Modified:    "2021-02-01",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-3156"},
			AffectedPackages: []AffectedPackage{
				{
					Name:     "sudo",
					Type:     "deb",
					OS:       []string{"ubuntu", "debian"},
					Versions: []string{"1.8.2-1.9.5p1"},
					FixedIn:  "1.9.5p2",
				},
				{
					Name:     "sudo",
					Type:     "rpm",
					OS:       []string{"centos", "rhel", "fedora"},
					Versions: []string{"1.8.2-1.9.5p1"},
					FixedIn:  "1.9.5p2",
				},
			},
		},
		{
			CVE:         "CVE-2021-44832",
			Description: "Apache Log4j2 RCE via JDBC Appender",
			Severity:    "MEDIUM",
			Score:       6.6,
			Vector:      "CVSS:3.1/AV:N/AC:H/PR:H/UI:N/S:U/C:H/I:H/A:H",
			Published:   "2021-12-28",
			Modified:    "2021-12-30",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-44832"},
			AffectedPackages: []AffectedPackage{
				{
					Name:     "log4j-core",
					Type:     "jar",
					OS:       []string{"ubuntu", "debian", "alpine", "centos", "rhel"},
					Versions: []string{"2.0-2.17.0"},
					FixedIn:  "2.17.1",
				},
			},
		},
		{
			CVE:         "CVE-2022-0778",
			Description: "Infinite loop in BN_mod_sqrt() reachable when parsing certificates",
			Severity:    "HIGH",
			Score:       7.5,
			Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H",
			Published:   "2022-03-15",
			Modified:    "2022-03-16",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-0778"},
			AffectedPackages: []AffectedPackage{
				{
					Name:     "openssl",
					Type:     "deb",
					OS:       []string{"ubuntu", "debian"},
					Versions: []string{"1.0.2-1.1.1m"},
					FixedIn:  "1.1.1n",
				},
				{
					Name:     "openssl",
					Type:     "rpm",
					OS:       []string{"centos", "rhel", "fedora"},
					Versions: []string{"1.0.2-1.1.1m"},
					FixedIn:  "1.1.1n",
				},
				{
					Name:     "openssl",
					Type:     "apk",
					OS:       []string{"alpine"},
					Versions: []string{"1.0.2-1.1.1m"},
					FixedIn:  "1.1.1n",
				},
			},
		},
		{
			CVE:         "CVE-2021-33560",
			Description: "Libgcrypt ECDSA signature verification vulnerability",
			Severity:    "HIGH",
			Score:       7.0,
			Vector:      "CVSS:3.1/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H",
			Published:   "2021-06-08",
			Modified:    "2021-06-10",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-33560"},
			AffectedPackages: []AffectedPackage{
				{
					Name:     "libgcrypt20",
					Type:     "deb",
					OS:       []string{"ubuntu", "debian"},
					Versions: []string{"1.8.0-1.8.7"},
					FixedIn:  "1.8.8",
				},
				{
					Name:     "libgcrypt",
					Type:     "rpm",
					OS:       []string{"centos", "rhel", "fedora"},
					Versions: []string{"1.8.0-1.8.7"},
					FixedIn:  "1.8.8",
				},
			},
		},
		{
			CVE:         "CVE-2021-3711",
			Description: "Buffer overrun in SM2 decryption in OpenSSL",
			Severity:    "HIGH",
			Score:       9.8,
			Vector:      "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
			Published:   "2021-08-24",
			Modified:    "2021-08-26",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-3711"},
			AffectedPackages: []AffectedPackage{
				{
					Name:     "openssl",
					Type:     "deb",
					OS:       []string{"ubuntu", "debian"},
					Versions: []string{"1.1.1-1.1.1k"},
					FixedIn:  "1.1.1l",
				},
				{
					Name:     "openssl",
					Type:     "apk",
					OS:       []string{"alpine"},
					Versions: []string{"1.1.1-1.1.1k"},
					FixedIn:  "1.1.1l",
				},
			},
		},
		{
			CVE:         "CVE-2022-1292",
			Description: "OpenSSL c_rehash script allows command injection",
			Severity:    "MEDIUM",
			Score:       5.3,
			Vector:      "CVSS:3.1/AV:L/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L",
			Published:   "2022-05-03",
			Modified:    "2022-05-05",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2022-1292"},
			AffectedPackages: []AffectedPackage{
				{
					Name:     "openssl",
					Type:     "deb",
					OS:       []string{"ubuntu", "debian"},
					Versions: []string{"1.0.2-3.0.2"},
					FixedIn:  "3.0.3",
				},
				{
					Name:     "openssl",
					Type:     "rpm",
					OS:       []string{"centos", "rhel", "fedora"},
					Versions: []string{"1.0.2-3.0.2"},
					FixedIn:  "3.0.3",
				},
			},
		},
		{
			CVE:         "CVE-2021-23017",
			Description: "nginx off-by-one in resolver",
			Severity:    "HIGH",
			Score:       7.7,
			Vector:      "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:C/C:N/I:N/A:H",
			Published:   "2021-05-25",
			Modified:    "2021-05-27",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-23017"},
			AffectedPackages: []AffectedPackage{
				{
					Name:     "nginx",
					Type:     "deb",
					OS:       []string{"ubuntu", "debian"},
					Versions: []string{"0.6.18-1.20.0"},
					FixedIn:  "1.20.1",
				},
				{
					Name:     "nginx",
					Type:     "rpm",
					OS:       []string{"centos", "rhel", "fedora"},
					Versions: []string{"0.6.18-1.20.0"},
					FixedIn:  "1.20.1",
				},
				{
					Name:     "nginx",
					Type:     "apk",
					OS:       []string{"alpine"},
					Versions: []string{"0.6.18-1.20.0"},
					FixedIn:  "1.20.1",
				},
			},
		},
		{
			CVE:         "CVE-2021-22876",
			Description: "curl automatic referer leaks credentials",
			Severity:    "LOW",
			Score:       3.7,
			Vector:      "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:L/I:N/A:N",
			Published:   "2021-03-31",
			Modified:    "2021-04-02",
			References:  []string{"https://nvd.nist.gov/vuln/detail/CVE-2021-22876"},
			AffectedPackages: []AffectedPackage{
				{
					Name:     "curl",
					Type:     "deb",
					OS:       []string{"ubuntu", "debian"},
					Versions: []string{"7.1.1-7.75.0"},
					FixedIn:  "7.76.0",
				},
				{
					Name:     "libcurl4",
					Type:     "deb",
					OS:       []string{"ubuntu", "debian"},
					Versions: []string{"7.1.1-7.75.0"},
					FixedIn:  "7.76.0",
				},
				{
					Name:     "curl",
					Type:     "apk",
					OS:       []string{"alpine"},
					Versions: []string{"7.1.1-7.75.0"},
					FixedIn:  "7.76.0",
				},
			},
		},
	}
}

// LoadFromJSON loads vulnerability data from JSON format
func (v *VulnDB) LoadFromJSON(data []byte) error {
	v.mu.Lock()
	defer v.mu.Unlock()

	var vulns []CVERecord
	if err := json.Unmarshal(data, &vulns); err != nil {
		return fmt.Errorf("failed to unmarshal vulnerability data: %w", err)
	}

	// Clear existing data
	v.vulnerabilities = make(map[string][]CVERecord)
	v.osVulns = make(map[string]map[string][]CVERecord)

	// Load new data
	for _, vuln := range vulns {
		for _, affectedPkg := range vuln.AffectedPackages {
			normalizedName := strings.ToLower(affectedPkg.Name)
			
			// Add to general vulnerabilities
			v.vulnerabilities[normalizedName] = append(v.vulnerabilities[normalizedName], vuln)
			
			// Add to OS-specific vulnerabilities
			for _, osName := range affectedPkg.OS {
				normalizedOS := strings.ToLower(osName)
				if v.osVulns[normalizedOS] == nil {
					v.osVulns[normalizedOS] = make(map[string][]CVERecord)
				}
				v.osVulns[normalizedOS][normalizedName] = append(v.osVulns[normalizedOS][normalizedName], vuln)
			}
		}
	}

	v.dbInfo.LastUpdated = time.Now()
	v.initialized = true

	return nil
}

// GetStats returns statistics about the vulnerability database
func (v *VulnDB) GetStats() map[string]interface{} {
	v.mu.RLock()
	defer v.mu.RUnlock()

	totalVulns := 0
	for _, vulns := range v.vulnerabilities {
		totalVulns += len(vulns)
	}

	severityCounts := make(map[string]int)
	for _, vulns := range v.vulnerabilities {
		for _, vuln := range vulns {
			severityCounts[vuln.Severity]++
		}
	}

	return map[string]interface{}{
		"total_vulnerabilities": totalVulns,
		"total_packages":        len(v.vulnerabilities),
		"supported_os":          len(v.osVulns),
		"severity_counts":       severityCounts,
		"initialized":           v.initialized,
		"last_updated":          v.dbInfo.LastUpdated,
	}
}
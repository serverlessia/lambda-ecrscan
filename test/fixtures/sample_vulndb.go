package fixtures

import (
	"context"
	"fmt"
	"time"

	"ecr-image-scanner/pkg/interfaces"
	"ecr-image-scanner/pkg/types"
)

// SampleVulnDB provides a sample vulnerability database for testing
type SampleVulnDB struct {
	initialized bool
	vulns       map[string]map[string][]types.VulnerabilityFinding // [package][os][]findings
}

// NewSampleVulnDB creates a new sample vulnerability database
func NewSampleVulnDB() interfaces.VulnDatabase {
	return &SampleVulnDB{
		vulns: createSampleVulnerabilities(),
	}
}

// Initialize initializes the sample vulnerability database
func (s *SampleVulnDB) Initialize(ctx context.Context) error {
	s.initialized = true
	return nil
}

// FindVulnerabilities finds vulnerabilities for a given package
func (s *SampleVulnDB) FindVulnerabilities(ctx context.Context, pkg types.Package, os string) ([]types.VulnerabilityFinding, error) {
	if !s.initialized {
		return nil, fmt.Errorf("vulnerability database not initialized")
	}

	packageVulns, exists := s.vulns[pkg.Name]
	if !exists {
		return []types.VulnerabilityFinding{}, nil
	}

	// Try OS-specific vulnerabilities first
	if osVulns, exists := packageVulns[os]; exists {
		return filterByVersion(osVulns, pkg.Version), nil
	}

	// Fall back to generic vulnerabilities
	if genericVulns, exists := packageVulns["generic"]; exists {
		return filterByVersion(genericVulns, pkg.Version), nil
	}

	return []types.VulnerabilityFinding{}, nil
}

// GetDatabaseInfo returns information about the sample database
func (s *SampleVulnDB) GetDatabaseInfo() types.DatabaseInfo {
	return types.DatabaseInfo{
		LastUpdated: time.Now().Add(-24 * time.Hour),
		Version:     "sample-1.0.0",
		Sources:     []string{"Sample CVE Database", "Test Vulnerabilities"},
	}
}

// createSampleVulnerabilities creates a comprehensive set of sample vulnerabilities
func createSampleVulnerabilities() map[string]map[string][]types.VulnerabilityFinding {
	return map[string]map[string][]types.VulnerabilityFinding{
		"openssl": {
			"ubuntu": {
				{
					CVE:         "CVE-2022-0778",
					Package:     "openssl",
					Version:     "1.1.1k",
					Severity:    "HIGH",
					Description: "Infinite loop in BN_mod_sqrt() reachable when parsing certificates",
					FixedIn:     "1.1.1n",
				},
				{
					CVE:         "CVE-2021-3712",
					Package:     "openssl",
					Version:     "1.1.1k",
					Severity:    "HIGH",
					Description: "Read buffer overruns processing ASN.1 strings",
					FixedIn:     "1.1.1l",
				},
				{
					CVE:         "CVE-2021-3711",
					Package:     "openssl",
					Version:     "1.1.1k",
					Severity:    "CRITICAL",
					Description: "SM2 Decryption Buffer Overflow",
					FixedIn:     "1.1.1l",
				},
			},
			"debian": {
				{
					CVE:         "CVE-2022-0778",
					Package:     "openssl",
					Version:     "1.1.1k",
					Severity:    "HIGH",
					Description: "Infinite loop in BN_mod_sqrt() reachable when parsing certificates",
					FixedIn:     "1.1.1n",
				},
			},
			"alpine": {
				{
					CVE:         "CVE-2022-0778",
					Package:     "openssl",
					Version:     "1.1.1k",
					Severity:    "HIGH",
					Description: "Infinite loop in BN_mod_sqrt() reachable when parsing certificates",
					FixedIn:     "1.1.1n",
				},
			},
		},
		"log4j-core": {
			"generic": {
				{
					CVE:         "CVE-2021-44228",
					Package:     "log4j-core",
					Version:     "2.14.1",
					Severity:    "CRITICAL",
					Description: "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
					FixedIn:     "2.15.0",
				},
				{
					CVE:         "CVE-2021-45046",
					Package:     "log4j-core",
					Version:     "2.14.1",
					Severity:    "CRITICAL",
					Description: "Apache Log4j2 Thread Context Lookup Pattern vulnerable to remote code execution",
					FixedIn:     "2.16.0",
				},
				{
					CVE:         "CVE-2021-45105",
					Package:     "log4j-core",
					Version:     "2.14.1",
					Severity:    "HIGH",
					Description: "Apache Log4j2 does not always protect from infinite recursion in lookup evaluation",
					FixedIn:     "2.17.0",
				},
			},
		},
		"curl": {
			"ubuntu": {
				{
					CVE:         "CVE-2021-22876",
					Package:     "curl",
					Version:     "7.68.0",
					Severity:    "LOW",
					Description: "curl automatic referer leaks credentials",
					FixedIn:     "7.76.0",
				},
				{
					CVE:         "CVE-2021-22890",
					Package:     "curl",
					Version:     "7.68.0",
					Severity:    "MEDIUM",
					Description: "TLS 1.3 session ticket proxy host mixup",
					FixedIn:     "7.76.0",
				},
			},
			"centos": {
				{
					CVE:         "CVE-2021-22876",
					Package:     "curl",
					Version:     "7.61.1",
					Severity:    "LOW",
					Description: "curl automatic referer leaks credentials",
					FixedIn:     "7.76.0",
				},
			},
		},
		"nginx": {
			"ubuntu": {
				{
					CVE:         "CVE-2021-23017",
					Package:     "nginx",
					Version:     "1.18.0",
					Severity:    "HIGH",
					Description: "nginx off-by-one in resolver",
					FixedIn:     "1.20.1",
				},
			},
			"centos": {
				{
					CVE:         "CVE-2021-23017",
					Package:     "nginx",
					Version:     "1.18.0",
					Severity:    "HIGH",
					Description: "nginx off-by-one in resolver",
					FixedIn:     "1.20.1",
				},
			},
		},
		"sudo": {
			"ubuntu": {
				{
					CVE:         "CVE-2021-3156",
					Package:     "sudo",
					Version:     "1.8.31",
					Severity:    "HIGH",
					Description: "Heap-based buffer overflow in sudo",
					FixedIn:     "1.9.5p2",
				},
			},
			"debian": {
				{
					CVE:         "CVE-2021-3156",
					Package:     "sudo",
					Version:     "1.8.31",
					Severity:    "HIGH",
					Description: "Heap-based buffer overflow in sudo",
					FixedIn:     "1.9.5p2",
				},
			},
		},
		"bash": {
			"ubuntu": {
				{
					CVE:         "CVE-2019-18276",
					Package:     "bash",
					Version:     "5.0-6ubuntu1.2",
					Severity:    "LOW",
					Description: "An issue was discovered in disable_priv_mode in shell.c in GNU Bash",
					FixedIn:     "5.0-6ubuntu1.3",
				},
			},
		},
		"glibc": {
			"ubuntu": {
				{
					CVE:         "CVE-2021-35942",
					Package:     "glibc",
					Version:     "2.31-0ubuntu9.2",
					Severity:    "MEDIUM",
					Description: "The wordexp function in the GNU C Library has a use-after-free bug",
					FixedIn:     "2.31-0ubuntu9.9",
				},
			},
		},
		"python3": {
			"ubuntu": {
				{
					CVE:         "CVE-2021-3737",
					Package:     "python3",
					Version:     "3.8.10",
					Severity:    "MEDIUM",
					Description: "A flaw was found in python. An improperly handled HTTP response",
					FixedIn:     "3.8.12",
				},
			},
		},
		"git": {
			"ubuntu": {
				{
					CVE:         "CVE-2021-40330",
					Package:     "git",
					Version:     "2.25.1",
					Severity:    "HIGH",
					Description: "git_connect_git in connect.c in Git before 2.30.1 allows a repository path to contain a newline character",
					FixedIn:     "2.30.1",
				},
			},
		},
		"apache2": {
			"ubuntu": {
				{
					CVE:         "CVE-2021-44790",
					Package:     "apache2",
					Version:     "2.4.41",
					Severity:    "CRITICAL",
					Description: "A carefully crafted request body can cause a buffer overflow in the mod_lua multipart parser",
					FixedIn:     "2.4.52",
				},
				{
					CVE:         "CVE-2021-44224",
					Package:     "apache2",
					Version:     "2.4.41",
					Severity:    "HIGH",
					Description: "A crafted URI sent to httpd configured as a forward proxy can cause a crash",
					FixedIn:     "2.4.52",
				},
			},
		},
		"mysql-server": {
			"ubuntu": {
				{
					CVE:         "CVE-2021-35604",
					Package:     "mysql-server",
					Version:     "8.0.25",
					Severity:    "HIGH",
					Description: "Vulnerability in the MySQL Server product of Oracle MySQL",
					FixedIn:     "8.0.27",
				},
			},
		},
		"postgresql": {
			"ubuntu": {
				{
					CVE:         "CVE-2021-32027",
					Package:     "postgresql",
					Version:     "12.7",
					Severity:    "HIGH",
					Description: "A flaw was found in postgresql in versions before 13.3",
					FixedIn:     "13.3",
				},
			},
		},
		"redis": {
			"ubuntu": {
				{
					CVE:         "CVE-2021-32625",
					Package:     "redis",
					Version:     "6.0.6",
					Severity:    "HIGH",
					Description: "Redis is an open source, in-memory database that persists on disk",
					FixedIn:     "6.2.4",
				},
			},
		},
		"node": {
			"generic": {
				{
					CVE:         "CVE-2021-44531",
					Package:     "node",
					Version:     "14.17.0",
					Severity:    "HIGH",
					Description: "Accepting arbitrary Subject Alternative Name (SAN) types",
					FixedIn:     "14.18.2",
				},
			},
		},
		"golang": {
			"generic": {
				{
					CVE:         "CVE-2021-44716",
					Package:     "golang",
					Version:     "1.16.5",
					Severity:    "HIGH",
					Description: "net/http: limit growth of header canonicalization cache",
					FixedIn:     "1.16.12",
				},
			},
		},
	}
}

// filterByVersion filters vulnerabilities based on package version
// This is a simplified version comparison - in a real implementation,
// you would use proper semantic version comparison
func filterByVersion(vulns []types.VulnerabilityFinding, version string) []types.VulnerabilityFinding {
	var filtered []types.VulnerabilityFinding
	
	for _, vuln := range vulns {
		// Simple version matching - in reality, you'd need proper version comparison
		if vuln.Version == version || vuln.Version == "" {
			filtered = append(filtered, vuln)
		}
	}
	
	return filtered
}

// GetSampleVulnerabilityDatabase returns a pre-configured sample vulnerability database
func GetSampleVulnerabilityDatabase() interfaces.VulnDatabase {
	return NewSampleVulnDB()
}

// GetVulnerabilityCountByPackage returns the number of vulnerabilities for a given package
func GetVulnerabilityCountByPackage(packageName, os string) int {
	vulns := createSampleVulnerabilities()
	
	if packageVulns, exists := vulns[packageName]; exists {
		if osVulns, exists := packageVulns[os]; exists {
			return len(osVulns)
		}
		if genericVulns, exists := packageVulns["generic"]; exists {
			return len(genericVulns)
		}
	}
	
	return 0
}

// GetAllSamplePackages returns all packages that have vulnerabilities in the sample database
func GetAllSamplePackages() []string {
	vulns := createSampleVulnerabilities()
	packages := make([]string, 0, len(vulns))
	
	for pkg := range vulns {
		packages = append(packages, pkg)
	}
	
	return packages
}

// GetSamplePackagesByOS returns packages that have vulnerabilities for a specific OS
func GetSamplePackagesByOS(os string) []string {
	vulns := createSampleVulnerabilities()
	var packages []string
	
	for pkg, osVulns := range vulns {
		if _, exists := osVulns[os]; exists {
			packages = append(packages, pkg)
		} else if _, exists := osVulns["generic"]; exists {
			packages = append(packages, pkg)
		}
	}
	
	return packages
}

// GetExpectedVulnerabilityCount returns expected vulnerability counts for test scenarios
func GetExpectedVulnerabilityCount(packages []types.Package, os string, scanMode types.ScanMode) map[string]int {
	counts := map[string]int{
		"CRITICAL":      0,
		"HIGH":          0,
		"MEDIUM":        0,
		"LOW":           0,
		"INFORMATIONAL": 0,
	}
	
	vulns := createSampleVulnerabilities()
	
	for _, pkg := range packages {
		if packageVulns, exists := vulns[pkg.Name]; exists {
			var findings []types.VulnerabilityFinding
			
			if osVulns, exists := packageVulns[os]; exists {
				findings = filterByVersion(osVulns, pkg.Version)
			} else if genericVulns, exists := packageVulns["generic"]; exists {
				findings = filterByVersion(genericVulns, pkg.Version)
			}
			
			for _, finding := range findings {
				// In basic mode, only include CRITICAL and HIGH
				if scanMode == types.ScanModeBasic {
					if finding.Severity == "CRITICAL" || finding.Severity == "HIGH" {
						counts[finding.Severity]++
					}
				} else {
					// Enhanced mode includes all severities
					counts[finding.Severity]++
				}
			}
		}
	}
	
	return counts
}
package fixtures

import (
	"time"

	"ecr-image-scanner/pkg/types"
)

// TestImageManifests provides sample image manifests for testing
var TestImageManifests = map[string]*types.ImageManifest{
	"small": {
		MediaType: "application/vnd.docker.distribution.manifest.v2+json",
		Digest:    "sha256:small-test-image",
		Layers: []types.LayerDigest{
			{
				Digest:    "sha256:layer1-small",
				MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				Size:      1024,
			},
		},
		Config: types.ConfigDigest{
			Digest:    "sha256:config-small",
			MediaType: "application/vnd.docker.container.image.v1+json",
			Size:      512,
		},
	},
	"medium": {
		MediaType: "application/vnd.docker.distribution.manifest.v2+json",
		Digest:    "sha256:medium-test-image",
		Layers: []types.LayerDigest{
			{
				Digest:    "sha256:layer1-medium",
				MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				Size:      10240,
			},
			{
				Digest:    "sha256:layer2-medium",
				MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				Size:      8192,
			},
		},
		Config: types.ConfigDigest{
			Digest:    "sha256:config-medium",
			MediaType: "application/vnd.docker.container.image.v1+json",
			Size:      1024,
		},
	},
	"large": {
		MediaType: "application/vnd.docker.distribution.manifest.v2+json",
		Digest:    "sha256:large-test-image",
		Layers: []types.LayerDigest{
			{
				Digest:    "sha256:layer1-large",
				MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				Size:      102400,
			},
			{
				Digest:    "sha256:layer2-large",
				MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				Size:      81920,
			},
			{
				Digest:    "sha256:layer3-large",
				MediaType: "application/vnd.docker.image.rootfs.diff.tar.gzip",
				Size:      65536,
			},
		},
		Config: types.ConfigDigest{
			Digest:    "sha256:config-large",
			MediaType: "application/vnd.docker.container.image.v1+json",
			Size:      2048,
		},
	},
}

// TestImageLayers provides sample image layers for testing
var TestImageLayers = map[string][]types.ImageLayer{
	"small": {
		{
			Digest:  "sha256:layer1-small",
			Content: []byte("test layer content for small image"),
			Size:    1024,
		},
	},
	"medium": {
		{
			Digest:  "sha256:layer1-medium",
			Content: generateTestContent(10240),
			Size:    10240,
		},
		{
			Digest:  "sha256:layer2-medium",
			Content: generateTestContent(8192),
			Size:    8192,
		},
	},
	"large": {
		{
			Digest:  "sha256:layer1-large",
			Content: generateTestContent(102400),
			Size:    102400,
		},
		{
			Digest:  "sha256:layer2-large",
			Content: generateTestContent(81920),
			Size:    81920,
		},
		{
			Digest:  "sha256:layer3-large",
			Content: generateTestContent(65536),
			Size:    65536,
		},
	},
}

// TestPackageInventories provides sample package inventories for different image types
var TestPackageInventories = map[string]*types.PackageInventory{
	"ubuntu-basic": {
		Packages: []types.Package{
			{Name: "base-files", Version: "11.1ubuntu2.2", Type: "deb"},
			{Name: "bash", Version: "5.0-6ubuntu1.2", Type: "deb"},
			{Name: "coreutils", Version: "8.30-3ubuntu2", Type: "deb"},
		},
		OS:        "ubuntu",
		OSVersion: "20.04",
	},
	"ubuntu-vulnerable": {
		Packages: []types.Package{
			{Name: "openssl", Version: "1.1.1k", Type: "deb"},
			{Name: "curl", Version: "7.68.0", Type: "deb"},
			{Name: "nginx", Version: "1.18.0", Type: "deb"},
			{Name: "log4j-core", Version: "2.14.1", Type: "jar"},
			{Name: "sudo", Version: "1.8.31", Type: "deb"},
		},
		OS:        "ubuntu",
		OSVersion: "20.04",
	},
	"alpine-basic": {
		Packages: []types.Package{
			{Name: "alpine-baselayout", Version: "3.2.0-r16", Type: "apk"},
			{Name: "busybox", Version: "1.33.1-r3", Type: "apk"},
			{Name: "musl", Version: "1.2.2-r3", Type: "apk"},
		},
		OS:        "alpine",
		OSVersion: "3.14",
	},
	"centos-vulnerable": {
		Packages: []types.Package{
			{Name: "openssl", Version: "1.1.1k", Type: "rpm"},
			{Name: "curl", Version: "7.61.1", Type: "rpm"},
			{Name: "httpd", Version: "2.4.37", Type: "rpm"},
		},
		OS:        "centos",
		OSVersion: "8",
	},
}

// TestVulnerabilityFindings provides sample vulnerability findings
var TestVulnerabilityFindings = map[string][]types.VulnerabilityFinding{
	"openssl": {
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
	},
	"log4j-core": {
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
	},
	"curl": {
		{
			CVE:         "CVE-2021-22876",
			Package:     "curl",
			Version:     "7.68.0",
			Severity:    "LOW",
			Description: "curl automatic referer leaks credentials",
			FixedIn:     "7.76.0",
		},
	},
	"nginx": {
		{
			CVE:         "CVE-2021-23017",
			Package:     "nginx",
			Version:     "1.18.0",
			Severity:    "HIGH",
			Description: "nginx off-by-one in resolver",
			FixedIn:     "1.20.1",
		},
	},
	"sudo": {
		{
			CVE:         "CVE-2021-3156",
			Package:     "sudo",
			Version:     "1.8.31",
			Severity:    "HIGH",
			Description: "Heap-based buffer overflow in sudo",
			FixedIn:     "1.9.5p2",
		},
	},
}

// TestLambdaEvents provides sample Lambda events for testing
var TestLambdaEvents = map[string]types.LambdaEvent{
	"basic": {
		ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
		Tag:      "latest",
		ScanMode: "basic",
	},
	"enhanced": {
		ImageURL: "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
		Tag:      "v1.0.0",
		ScanMode: "enhanced",
	},
	"with-filters": {
		ImageURL:       "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
		Tag:            "latest",
		ScanMode:       "enhanced",
		SeverityFilter: "HIGH",
		MaxFindings:    50,
		OutputFormat:   "summary",
	},
	"custom-config": {
		ImageURL:       "123456789012.dkr.ecr.us-west-2.amazonaws.com/test-repo",
		Tag:            "latest",
		Region:         "us-west-2",
		TimeoutSeconds: 600,
		Config: map[string]string{
			"debug": "true",
		},
	},
}

// TestDatabaseInfo provides sample database information
var TestDatabaseInfo = types.DatabaseInfo{
	LastUpdated: time.Now().Add(-24 * time.Hour),
	Version:     "test-1.0.0",
	Sources:     []string{"NVD", "GitHub Security Advisories", "Test Database"},
}

// generateTestContent creates test content of specified size
func generateTestContent(size int64) []byte {
	content := make([]byte, size)
	pattern := []byte("test content pattern ")
	patternLen := int64(len(pattern))
	
	for i := int64(0); i < size; i++ {
		content[i] = pattern[i%patternLen]
	}
	
	return content
}

// GetTestScanResults returns sample scan results for testing
func GetTestScanResults(imageType string) *types.ScanResults {
	switch imageType {
	case "clean":
		return &types.ScanResults{
			TotalVulnerabilities: 0,
			SeverityCounts:       map[string]int{},
			Findings:             []types.VulnerabilityFinding{},
		}
	case "low-risk":
		return &types.ScanResults{
			TotalVulnerabilities: 1,
			SeverityCounts: map[string]int{
				"LOW": 1,
			},
			Findings: []types.VulnerabilityFinding{
				TestVulnerabilityFindings["curl"][0],
			},
		}
	case "high-risk":
		findings := []types.VulnerabilityFinding{}
		findings = append(findings, TestVulnerabilityFindings["openssl"]...)
		findings = append(findings, TestVulnerabilityFindings["log4j-core"]...)
		findings = append(findings, TestVulnerabilityFindings["nginx"]...)
		findings = append(findings, TestVulnerabilityFindings["sudo"]...)
		
		return &types.ScanResults{
			TotalVulnerabilities: len(findings),
			SeverityCounts: map[string]int{
				"CRITICAL": 2,
				"HIGH":     4,
			},
			Findings: findings,
		}
	default:
		return GetTestScanResults("clean")
	}
}

// GetExpectedResults returns expected results for different test scenarios
func GetExpectedResults() map[string]*types.ScanResults {
	return map[string]*types.ScanResults{
		"ubuntu-basic-basic":      GetTestScanResults("clean"),
		"ubuntu-basic-enhanced":   GetTestScanResults("clean"),
		"ubuntu-vulnerable-basic": GetTestScanResults("high-risk"),
		"ubuntu-vulnerable-enhanced": GetTestScanResults("high-risk"),
		"alpine-basic-basic":      GetTestScanResults("clean"),
		"alpine-basic-enhanced":   GetTestScanResults("clean"),
		"centos-vulnerable-basic": GetTestScanResults("high-risk"),
		"centos-vulnerable-enhanced": GetTestScanResults("high-risk"),
	}
}
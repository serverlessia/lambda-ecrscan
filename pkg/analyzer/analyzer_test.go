package analyzer

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"io"
	"strings"
	"testing"
	"time"

	"ecr-image-scanner/pkg/types"
)

func TestNewLayerAnalyzer(t *testing.T) {
	tests := []struct {
		name         string
		maxLayerSize int64
		expected     int64
	}{
		{
			name:         "positive max layer size",
			maxLayerSize: 100 * 1024 * 1024,
			expected:     100 * 1024 * 1024,
		},
		{
			name:         "zero max layer size uses default",
			maxLayerSize: 0,
			expected:     500 * 1024 * 1024,
		},
		{
			name:         "negative max layer size uses default",
			maxLayerSize: -1,
			expected:     500 * 1024 * 1024,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			analyzer := NewLayerAnalyzer(tt.maxLayerSize)
			impl := analyzer.(*LayerAnalyzerImpl)
			if impl.maxLayerSize != tt.expected {
				t.Errorf("expected maxLayerSize %d, got %d", tt.expected, impl.maxLayerSize)
			}
		})
	}
}

func TestAnalyzeLayers(t *testing.T) {
	analyzer := NewLayerAnalyzer(500 * 1024 * 1024)

	tests := []struct {
		name           string
		layers         []types.ImageLayer
		expectedOS     string
		expectedOSVer  string
		expectedPkgLen int
		expectError    bool
	}{
		{
			name:           "empty layers",
			layers:         []types.ImageLayer{},
			expectedOS:     "unknown",
			expectedOSVer:  "unknown",
			expectedPkgLen: 0,
			expectError:    false,
		},
		{
			name: "layer with debian packages",
			layers: []types.ImageLayer{
				createTestLayerWithDebianStatus(),
			},
			expectedOS:     "debian",
			expectedOSVer:  "11",
			expectedPkgLen: 2,
			expectError:    false,
		},
		{
			name: "layer with alpine packages",
			layers: []types.ImageLayer{
				createTestLayerWithAlpinePackages(),
			},
			expectedOS:     "alpine",
			expectedOSVer:  "3.15.0",
			expectedPkgLen: 2,
			expectError:    false,
		},
		{
			name: "multiple layers with deduplication",
			layers: []types.ImageLayer{
				createTestLayerWithDebianStatus(),
				createTestLayerWithMoreDebianPackages(),
			},
			expectedOS:     "debian",
			expectedOSVer:  "11",
			expectedPkgLen: 3, // Should deduplicate overlapping packages
			expectError:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			inventory, err := analyzer.AnalyzeLayers(ctx, tt.layers)

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
				return
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if inventory == nil {
				t.Error("expected inventory but got nil")
				return
			}

			if inventory.OS != tt.expectedOS {
				t.Errorf("expected OS %s, got %s", tt.expectedOS, inventory.OS)
			}

			if inventory.OSVersion != tt.expectedOSVer {
				t.Errorf("expected OS version %s, got %s", tt.expectedOSVer, inventory.OSVersion)
			}

			if len(inventory.Packages) != tt.expectedPkgLen {
				t.Errorf("expected %d packages, got %d", tt.expectedPkgLen, len(inventory.Packages))
			}
		})
	}
}

func TestAnalyzeLayersWithContext(t *testing.T) {
	analyzer := NewLayerAnalyzer(500 * 1024 * 1024)

	t.Run("context cancellation", func(t *testing.T) {
		ctx, cancel := context.WithCancel(context.Background())
		cancel() // Cancel immediately

		layers := []types.ImageLayer{
			createTestLayerWithDebianStatus(),
		}

		_, err := analyzer.AnalyzeLayers(ctx, layers)
		if err != context.Canceled {
			t.Errorf("expected context.Canceled error, got %v", err)
		}
	})

	t.Run("context timeout", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 1*time.Nanosecond)
		defer cancel()

		// Give context time to timeout
		time.Sleep(1 * time.Millisecond)

		layers := []types.ImageLayer{
			createTestLayerWithDebianStatus(),
		}

		_, err := analyzer.AnalyzeLayers(ctx, layers)
		if err != context.DeadlineExceeded {
			t.Errorf("expected context.DeadlineExceeded error, got %v", err)
		}
	})
}

func TestExtractPackages(t *testing.T) {
	analyzer := NewLayerAnalyzer(500 * 1024 * 1024)

	tests := []struct {
		name        string
		layer       types.ImageLayer
		expectedLen int
		expectError bool
	}{
		{
			name: "empty layer",
			layer: types.ImageLayer{
				Digest:  "sha256:empty",
				Content: []byte{},
				Size:    0,
			},
			expectedLen: 0,
			expectError: false,
		},
		{
			name:        "debian status layer",
			layer:       createTestLayerWithDebianStatus(),
			expectedLen: 2,
			expectError: false,
		},
		{
			name:        "alpine packages layer",
			layer:       createTestLayerWithAlpinePackages(),
			expectedLen: 2,
			expectError: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			packages, err := analyzer.ExtractPackages(ctx, tt.layer)

			if tt.expectError && err == nil {
				t.Error("expected error but got none")
				return
			}
			if !tt.expectError && err != nil {
				t.Errorf("unexpected error: %v", err)
				return
			}

			if len(packages) != tt.expectedLen {
				t.Errorf("expected %d packages, got %d", tt.expectedLen, len(packages))
			}
		})
	}
}

func TestParseDebianStatus(t *testing.T) {
	analyzer := &LayerAnalyzerImpl{}

	debianStatus := `Package: base-files
Status: install ok installed
Priority: required
Section: admin
Installed-Size: 348
Maintainer: Santiago Vila <sanvila@debian.org>
Architecture: amd64
Multi-Arch: foreign
Version: 11.1+deb11u7
Description: Debian base system miscellaneous files

Package: bash
Status: install ok installed
Priority: required
Section: shells
Installed-Size: 6470
Maintainer: Matthias Klose <doko@debian.org>
Architecture: amd64
Multi-Arch: foreign
Version: 5.1-2+deb11u1
Description: GNU Bourne Again SHell

Package: removed-package
Status: deinstall ok config-files
Priority: optional
Section: misc
Version: 1.0.0
Description: This package was removed
`

	reader := strings.NewReader(debianStatus)
	packages := analyzer.parseDebianStatus(reader)

	if len(packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(packages))
	}

	expectedPackages := map[string]string{
		"base-files": "11.1+deb11u7",
		"bash":       "5.1-2+deb11u1",
	}

	for _, pkg := range packages {
		if pkg.Type != "deb" {
			t.Errorf("expected package type 'deb', got '%s'", pkg.Type)
		}

		expectedVersion, exists := expectedPackages[pkg.Name]
		if !exists {
			t.Errorf("unexpected package: %s", pkg.Name)
			continue
		}

		if pkg.Version != expectedVersion {
			t.Errorf("expected version %s for package %s, got %s", expectedVersion, pkg.Name, pkg.Version)
		}
	}
}

func TestParseAlpineInstalled(t *testing.T) {
	analyzer := &LayerAnalyzerImpl{}

	alpineInstalled := `C:Q1p6+TFwS8JjOv5vGMb1JbqvAuEA4=
P:musl
V:1.2.2-r7
A:x86_64
S:387072
I:632832
T:the musl c library (libc) implementation
U:https://musl.libc.org/
L:MIT

C:Q1BD6GBbLEs+Jx+JSBkn+BtWJPMA4=
P:busybox
V:1.34.1-r3
A:x86_64
S:962560
I:1949696
T:Size optimized toolbox of many common UNIX utilities
U:https://busybox.net/
L:GPL-2.0-only
`

	reader := strings.NewReader(alpineInstalled)
	packages := analyzer.parseAlpineInstalled(reader)

	if len(packages) != 2 {
		t.Errorf("expected 2 packages, got %d", len(packages))
	}

	expectedPackages := map[string]string{
		"musl":    "1.2.2-r7",
		"busybox": "1.34.1-r3",
	}

	for _, pkg := range packages {
		if pkg.Type != "apk" {
			t.Errorf("expected package type 'apk', got '%s'", pkg.Type)
		}

		expectedVersion, exists := expectedPackages[pkg.Name]
		if !exists {
			t.Errorf("unexpected package: %s", pkg.Name)
			continue
		}

		if pkg.Version != expectedVersion {
			t.Errorf("expected version %s for package %s, got %s", expectedVersion, pkg.Name, pkg.Version)
		}
	}
}

func TestParseOSRelease(t *testing.T) {
	analyzer := &LayerAnalyzerImpl{}

	osRelease := `PRETTY_NAME="Debian GNU/Linux 11 (bullseye)"
NAME="Debian GNU/Linux"
VERSION_ID="11"
VERSION="11 (bullseye)"
VERSION_CODENAME=bullseye
ID=debian
HOME_URL="https://www.debian.org/"
SUPPORT_URL="https://www.debian.org/support"
BUG_REPORT_URL="https://bugs.debian.org/"
`

	reader := strings.NewReader(osRelease)
	os, version := analyzer.parseOSRelease(reader)

	if os != "debian" {
		t.Errorf("expected OS 'debian', got '%s'", os)
	}

	if version != "11" {
		t.Errorf("expected version '11', got '%s'", version)
	}
}

func TestParseRedHatRelease(t *testing.T) {
	analyzer := &LayerAnalyzerImpl{}

	tests := []struct {
		name            string
		content         string
		expectedOS      string
		expectedVersion string
	}{
		{
			name:            "Red Hat Enterprise Linux",
			content:         "Red Hat Enterprise Linux Server release 8.5 (Ootpa)",
			expectedOS:      "rhel",
			expectedVersion: "8.5",
		},
		{
			name:            "CentOS",
			content:         "CentOS Linux release 7.9.2009 (Core)",
			expectedOS:      "centos",
			expectedVersion: "7.9",
		},
		{
			name:            "Fedora",
			content:         "Fedora release 35 (Thirty Five)",
			expectedOS:      "fedora",
			expectedVersion: "35",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			reader := strings.NewReader(tt.content)
			os, version := analyzer.parseRedHatRelease(reader)

			if os != tt.expectedOS {
				t.Errorf("expected OS '%s', got '%s'", tt.expectedOS, os)
			}

			if version != tt.expectedVersion {
				t.Errorf("expected version '%s', got '%s'", tt.expectedVersion, version)
			}
		})
	}
}

func TestDecompressLayer(t *testing.T) {
	analyzer := &LayerAnalyzerImpl{}

	t.Run("gzip compressed content", func(t *testing.T) {
		// Create gzip compressed content
		var buf bytes.Buffer
		gzWriter := gzip.NewWriter(&buf)
		testData := "test data"
		gzWriter.Write([]byte(testData))
		gzWriter.Close()

		reader, err := analyzer.decompressLayer(buf.Bytes())
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		defer reader.Close()

		// Read decompressed content
		content, err := io.ReadAll(reader)
		if err != nil {
			t.Errorf("failed to read decompressed content: %v", err)
			return
		}

		if string(content) != testData {
			t.Errorf("expected '%s', got '%s'", testData, string(content))
		}
	})

	t.Run("uncompressed content", func(t *testing.T) {
		testData := "uncompressed test data"
		reader, err := analyzer.decompressLayer([]byte(testData))
		if err != nil {
			t.Errorf("unexpected error: %v", err)
			return
		}
		defer reader.Close()

		content, err := io.ReadAll(reader)
		if err != nil {
			t.Errorf("failed to read content: %v", err)
			return
		}

		if string(content) != testData {
			t.Errorf("expected '%s', got '%s'", testData, string(content))
		}
	})
}

// Helper functions to create test layers

func createTestLayerWithDebianStatus() types.ImageLayer {
	debianStatus := `Package: base-files
Status: install ok installed
Version: 11.1+deb11u7

Package: bash
Status: install ok installed
Version: 5.1-2+deb11u1
`

	osRelease := `ID=debian
VERSION_ID="11"
`

	return createTestTarLayer(map[string]string{
		"var/lib/dpkg/status": debianStatus,
		"etc/os-release":      osRelease,
	})
}

func createTestLayerWithAlpinePackages() types.ImageLayer {
	alpineInstalled := `P:musl
V:1.2.2-r7

P:busybox
V:1.34.1-r3
`

	alpineRelease := "3.15.0"

	return createTestTarLayer(map[string]string{
		"lib/apk/db/installed": alpineInstalled,
		"etc/alpine-release":   alpineRelease,
	})
}

func createTestLayerWithMoreDebianPackages() types.ImageLayer {
	debianStatus := `Package: base-files
Status: install ok installed
Version: 11.1+deb11u8

Package: curl
Status: install ok installed
Version: 7.74.0-1.3+deb11u2
`

	return createTestTarLayer(map[string]string{
		"var/lib/dpkg/status": debianStatus,
	})
}

func createTestTarLayer(files map[string]string) types.ImageLayer {
	var buf bytes.Buffer
	tarWriter := tar.NewWriter(&buf)

	for filename, content := range files {
		header := &tar.Header{
			Name: filename,
			Mode: 0644,
			Size: int64(len(content)),
		}

		if err := tarWriter.WriteHeader(header); err != nil {
			panic(err)
		}

		if _, err := tarWriter.Write([]byte(content)); err != nil {
			panic(err)
		}
	}

	tarWriter.Close()

	// Compress with gzip
	var gzipBuf bytes.Buffer
	gzWriter := gzip.NewWriter(&gzipBuf)
	gzWriter.Write(buf.Bytes())
	gzWriter.Close()

	return types.ImageLayer{
		Digest:  "sha256:test",
		Content: gzipBuf.Bytes(),
		Size:    int64(gzipBuf.Len()),
	}
}
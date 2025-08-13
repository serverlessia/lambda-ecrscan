package analyzer

import (
	"archive/tar"
	"bufio"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"

	"ecr-image-scanner/pkg/interfaces"
	"ecr-image-scanner/pkg/types"
)

// LayerAnalyzerImpl implements the LayerAnalyzer interface
type LayerAnalyzerImpl struct {
	maxLayerSize int64
}

// NewLayerAnalyzer creates a new LayerAnalyzer instance
func NewLayerAnalyzer(maxLayerSize int64) interfaces.LayerAnalyzer {
	if maxLayerSize <= 0 {
		maxLayerSize = 500 * 1024 * 1024 // 500MB default
	}
	return &LayerAnalyzerImpl{
		maxLayerSize: maxLayerSize,
	}
}

// AnalyzeLayers analyzes multiple image layers to extract package inventory
func (la *LayerAnalyzerImpl) AnalyzeLayers(ctx context.Context, layers []types.ImageLayer) (*types.PackageInventory, error) {
	if len(layers) == 0 {
		return &types.PackageInventory{
			Packages:  []types.Package{},
			OS:        "unknown",
			OSVersion: "unknown",
		}, nil
	}

	var allPackages []types.Package
	var detectedOS string
	var detectedOSVersion string
	packageMap := make(map[string]types.Package) // Use map to deduplicate packages

	// Analyze each layer
	for i, layer := range layers {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		// Skip layers that are too large
		if layer.Size > la.maxLayerSize {
			continue
		}

		packages, err := la.ExtractPackages(ctx, layer)
		if err != nil {
			// Log error but continue with other layers
			continue
		}

		// Add packages to map (later packages override earlier ones)
		for _, pkg := range packages {
			key := fmt.Sprintf("%s:%s", pkg.Name, pkg.Type)
			packageMap[key] = pkg
		}

		// Try to detect OS from the first few layers
		if i < 3 && (detectedOS == "" || detectedOS == "unknown") {
			os, version := la.detectOSFromLayer(layer)
			if os != "unknown" {
				detectedOS = os
				detectedOSVersion = version
			}
		}
	}

	// Convert map back to slice
	for _, pkg := range packageMap {
		allPackages = append(allPackages, pkg)
	}

	if detectedOS == "" {
		detectedOS = "unknown"
	}
	if detectedOSVersion == "" {
		detectedOSVersion = "unknown"
	}

	return &types.PackageInventory{
		Packages:  allPackages,
		OS:        detectedOS,
		OSVersion: detectedOSVersion,
	}, nil
}

// ExtractPackages extracts packages from a single image layer
func (la *LayerAnalyzerImpl) ExtractPackages(ctx context.Context, layer types.ImageLayer) ([]types.Package, error) {
	if len(layer.Content) == 0 {
		return []types.Package{}, nil
	}

	// Decompress the layer content
	reader, err := la.decompressLayer(layer.Content)
	if err != nil {
		return nil, fmt.Errorf("failed to decompress layer %s: %w", layer.Digest, err)
	}
	defer reader.Close()

	// Extract packages from tar archive
	packages, err := la.extractPackagesFromTar(ctx, reader)
	if err != nil {
		return nil, fmt.Errorf("failed to extract packages from layer %s: %w", layer.Digest, err)
	}

	return packages, nil
}

// decompressLayer decompresses layer content based on detected format
func (la *LayerAnalyzerImpl) decompressLayer(content []byte) (io.ReadCloser, error) {
	reader := bytes.NewReader(content)

	// Check if content is gzip compressed
	if len(content) >= 2 && content[0] == 0x1f && content[1] == 0x8b {
		gzReader, err := gzip.NewReader(reader)
		if err != nil {
			return nil, fmt.Errorf("failed to create gzip reader: %w", err)
		}
		return gzReader, nil
	}

	// Return uncompressed content
	return io.NopCloser(reader), nil
}

// extractPackagesFromTar extracts packages from a tar archive
func (la *LayerAnalyzerImpl) extractPackagesFromTar(ctx context.Context, reader io.Reader) ([]types.Package, error) {
	var packages []types.Package
	tarReader := tar.NewReader(reader)

	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("failed to read tar header: %w", err)
		}

		// Skip directories and non-regular files
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Check for package database files
		pkgs := la.extractPackagesFromFile(header.Name, tarReader)
		packages = append(packages, pkgs...)
	}

	return packages, nil
}

// extractPackagesFromFile extracts packages from specific package database files
func (la *LayerAnalyzerImpl) extractPackagesFromFile(filename string, reader io.Reader) []types.Package {
	var packages []types.Package

	switch {
	// Debian/Ubuntu package databases
	case strings.HasSuffix(filename, "var/lib/dpkg/status") || strings.HasSuffix(filename, "/var/lib/dpkg/status"):
		packages = append(packages, la.parseDebianStatus(reader)...)
	case strings.Contains(filename, "/var/lib/apt/lists/") && strings.HasSuffix(filename, "_Packages"):
		packages = append(packages, la.parseDebianPackages(reader)...)

	// RPM package databases
	case strings.Contains(filename, "/var/lib/rpm/"):
		// RPM database files are binary, would need special handling
		// For now, skip these and rely on other methods

	// Alpine package database
	case strings.HasSuffix(filename, "lib/apk/db/installed") || strings.HasSuffix(filename, "/lib/apk/db/installed"):
		packages = append(packages, la.parseAlpineInstalled(reader)...)

	// Package manager cache files
	case strings.Contains(filename, "/var/cache/apt/"):
		// Skip cache files for now
	case strings.Contains(filename, "/var/cache/yum/"):
		// Skip cache files for now
	}

	return packages
}

// parseDebianStatus parses Debian/Ubuntu dpkg status file
func (la *LayerAnalyzerImpl) parseDebianStatus(reader io.Reader) []types.Package {
	var packages []types.Package
	scanner := bufio.NewScanner(reader)

	var currentPackage types.Package
	var inPackage bool

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			// End of package entry
			if inPackage && currentPackage.Name != "" && currentPackage.Version != "" {
				currentPackage.Type = "deb"
				packages = append(packages, currentPackage)
			}
			currentPackage = types.Package{}
			inPackage = false
			continue
		}

		if strings.HasPrefix(line, "Package: ") {
			currentPackage.Name = strings.TrimPrefix(line, "Package: ")
			inPackage = true
		} else if strings.HasPrefix(line, "Version: ") {
			currentPackage.Version = strings.TrimPrefix(line, "Version: ")
		} else if strings.HasPrefix(line, "Status: ") {
			status := strings.TrimPrefix(line, "Status: ")
			// Only include installed packages
			if !strings.Contains(status, "installed") {
				inPackage = false
			}
		}
	}

	// Handle last package if file doesn't end with empty line
	if inPackage && currentPackage.Name != "" && currentPackage.Version != "" {
		currentPackage.Type = "deb"
		packages = append(packages, currentPackage)
	}

	return packages
}

// parseDebianPackages parses Debian/Ubuntu package list files
func (la *LayerAnalyzerImpl) parseDebianPackages(reader io.Reader) []types.Package {
	var packages []types.Package
	scanner := bufio.NewScanner(reader)

	var currentPackage types.Package
	var inPackage bool

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			// End of package entry
			if inPackage && currentPackage.Name != "" && currentPackage.Version != "" {
				currentPackage.Type = "deb"
				packages = append(packages, currentPackage)
			}
			currentPackage = types.Package{}
			inPackage = false
			continue
		}

		if strings.HasPrefix(line, "Package: ") {
			currentPackage.Name = strings.TrimPrefix(line, "Package: ")
			inPackage = true
		} else if strings.HasPrefix(line, "Version: ") {
			currentPackage.Version = strings.TrimPrefix(line, "Version: ")
		}
	}

	// Handle last package
	if inPackage && currentPackage.Name != "" && currentPackage.Version != "" {
		currentPackage.Type = "deb"
		packages = append(packages, currentPackage)
	}

	return packages
}

// parseAlpineInstalled parses Alpine Linux apk installed packages database
func (la *LayerAnalyzerImpl) parseAlpineInstalled(reader io.Reader) []types.Package {
	var packages []types.Package
	scanner := bufio.NewScanner(reader)

	var currentPackage types.Package
	var inPackage bool

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" {
			// End of package entry
			if inPackage && currentPackage.Name != "" && currentPackage.Version != "" {
				currentPackage.Type = "apk"
				packages = append(packages, currentPackage)
			}
			currentPackage = types.Package{}
			inPackage = false
			continue
		}

		if strings.HasPrefix(line, "P:") {
			// Package name
			currentPackage.Name = strings.TrimPrefix(line, "P:")
			inPackage = true
		} else if strings.HasPrefix(line, "V:") {
			// Version
			currentPackage.Version = strings.TrimPrefix(line, "V:")
		}
	}

	// Handle last package
	if inPackage && currentPackage.Name != "" && currentPackage.Version != "" {
		currentPackage.Type = "apk"
		packages = append(packages, currentPackage)
	}

	return packages
}

// detectOSFromLayer attempts to detect the OS and version from layer contents
func (la *LayerAnalyzerImpl) detectOSFromLayer(layer types.ImageLayer) (string, string) {
	if len(layer.Content) == 0 {
		return "unknown", "unknown"
	}

	// Decompress the layer content
	reader, err := la.decompressLayer(layer.Content)
	if err != nil {
		return "unknown", "unknown"
	}
	defer reader.Close()

	// Look for OS identification files in tar archive
	tarReader := tar.NewReader(reader)

	for {
		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			break
		}

		// Skip directories and non-regular files
		if header.Typeflag != tar.TypeReg {
			continue
		}

		os, version := la.detectOSFromFile(header.Name, tarReader)
		if os != "unknown" {
			return os, version
		}
	}

	return "unknown", "unknown"
}

// detectOSFromFile detects OS from specific system files
func (la *LayerAnalyzerImpl) detectOSFromFile(filename string, reader io.Reader) (string, string) {
	switch filename {
	case "etc/os-release", "/etc/os-release":
		return la.parseOSRelease(reader)
	case "etc/lsb-release", "/etc/lsb-release":
		return la.parseLSBRelease(reader)
	case "etc/debian_version", "/etc/debian_version":
		return la.parseDebianVersion(reader)
	case "etc/redhat-release", "/etc/redhat-release":
		return la.parseRedHatRelease(reader)
	case "etc/alpine-release", "/etc/alpine-release":
		return la.parseAlpineRelease(reader)
	}

	return "unknown", "unknown"
}

// parseOSRelease parses /etc/os-release file
func (la *LayerAnalyzerImpl) parseOSRelease(reader io.Reader) (string, string) {
	scanner := bufio.NewScanner(reader)
	var osName, osVersion string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "ID=") {
			osName = strings.Trim(strings.TrimPrefix(line, "ID="), `"`)
		} else if strings.HasPrefix(line, "VERSION_ID=") {
			osVersion = strings.Trim(strings.TrimPrefix(line, "VERSION_ID="), `"`)
		}
	}

	if osName == "" {
		osName = "unknown"
	}
	if osVersion == "" {
		osVersion = "unknown"
	}

	return osName, osVersion
}

// parseLSBRelease parses /etc/lsb-release file
func (la *LayerAnalyzerImpl) parseLSBRelease(reader io.Reader) (string, string) {
	scanner := bufio.NewScanner(reader)
	var osName, osVersion string

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "DISTRIB_ID=") {
			osName = strings.ToLower(strings.TrimPrefix(line, "DISTRIB_ID="))
		} else if strings.HasPrefix(line, "DISTRIB_RELEASE=") {
			osVersion = strings.TrimPrefix(line, "DISTRIB_RELEASE=")
		}
	}

	if osName == "" {
		osName = "unknown"
	}
	if osVersion == "" {
		osVersion = "unknown"
	}

	return osName, osVersion
}

// parseDebianVersion parses /etc/debian_version file
func (la *LayerAnalyzerImpl) parseDebianVersion(reader io.Reader) (string, string) {
	scanner := bufio.NewScanner(reader)
	if scanner.Scan() {
		version := strings.TrimSpace(scanner.Text())
		return "debian", version
	}
	return "debian", "unknown"
}

// parseRedHatRelease parses /etc/redhat-release file
func (la *LayerAnalyzerImpl) parseRedHatRelease(reader io.Reader) (string, string) {
	scanner := bufio.NewScanner(reader)
	if scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		
		// Extract OS name and version using regex
		re := regexp.MustCompile(`^([A-Za-z\s]+)\s+.*?(\d+(?:\.\d+)?)`)
		matches := re.FindStringSubmatch(line)
		
		if len(matches) >= 3 {
			osName := strings.ToLower(strings.TrimSpace(matches[1]))
			osVersion := matches[2]
			
			// Normalize common Red Hat variants
			if strings.Contains(osName, "red hat") {
				osName = "rhel"
			} else if strings.Contains(osName, "centos") {
				osName = "centos"
			} else if strings.Contains(osName, "fedora") {
				osName = "fedora"
			}
			
			return osName, osVersion
		}
	}
	return "rhel", "unknown"
}

// parseAlpineRelease parses /etc/alpine-release file
func (la *LayerAnalyzerImpl) parseAlpineRelease(reader io.Reader) (string, string) {
	scanner := bufio.NewScanner(reader)
	if scanner.Scan() {
		version := strings.TrimSpace(scanner.Text())
		return "alpine", version
	}
	return "alpine", "unknown"
}
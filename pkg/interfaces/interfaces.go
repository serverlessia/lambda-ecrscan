package interfaces

import (
	"context"
	"ecr-image-scanner/pkg/types"
)

// ECRClient interface for ECR operations
type ECRClient interface {
	// GetAuthorizationToken retrieves an authorization token for ECR
	GetAuthorizationToken(ctx context.Context) (*types.AuthToken, error)
	
	// GetImageManifest retrieves the manifest for a specific image
	GetImageManifest(ctx context.Context, repo, tag string) (*types.ImageManifest, error)
	
	// GetImageLayers downloads the specified image layers
	GetImageLayers(ctx context.Context, repo string, layers []types.LayerDigest) ([]types.ImageLayer, error)
}

// VulnerabilityScanner interface for vulnerability scanning operations
type VulnerabilityScanner interface {
	// ScanImage performs vulnerability scanning on an image
	ScanImage(ctx context.Context, manifest *types.ImageManifest, layers []types.ImageLayer, mode types.ScanMode) (*types.ScanResults, error)
	
	// LoadVulnerabilityDatabase loads the vulnerability database
	LoadVulnerabilityDatabase(ctx context.Context) error
}

// LayerAnalyzer interface for analyzing image layers
type LayerAnalyzer interface {
	// AnalyzeLayers analyzes multiple image layers to extract package inventory
	AnalyzeLayers(ctx context.Context, layers []types.ImageLayer) (*types.PackageInventory, error)
	
	// ExtractPackages extracts packages from a single image layer
	ExtractPackages(ctx context.Context, layer types.ImageLayer) ([]types.Package, error)
}

// VulnDatabase interface for vulnerability database operations
type VulnDatabase interface {
	// Initialize initializes the vulnerability database
	Initialize(ctx context.Context) error
	
	// FindVulnerabilities finds vulnerabilities for a given package
	FindVulnerabilities(ctx context.Context, pkg types.Package, os string) ([]types.VulnerabilityFinding, error)
	
	// GetDatabaseInfo returns information about the vulnerability database
	GetDatabaseInfo() types.DatabaseInfo
}
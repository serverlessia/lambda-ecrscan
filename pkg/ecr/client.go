package ecr

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ecr"
	"github.com/aws/aws-sdk-go-v2/service/ecr/types"

	appTypes "ecr-image-scanner/pkg/types"
	"ecr-image-scanner/pkg/errors"
	"ecr-image-scanner/pkg/retry"
)

// Client implements the ECRClient interface using AWS SDK v2
type Client struct {
	ecrClient *ecr.Client
	region    string
	httpClient *http.Client
}

// NewClient creates a new ECR client
func NewClient(ctx context.Context, region string) (*Client, error) {
	if strings.TrimSpace(region) == "" {
		return nil, errors.NewValidationError("INVALID_REGION", "AWS region is required", "region")
	}

	// Load AWS configuration with retry
	var cfg aws.Config
	err := retry.RetryECROperation(ctx, func(ctx context.Context) error {
		var err error
		cfg, err = config.LoadDefaultConfig(ctx, config.WithRegion(region))
		if err != nil {
			return errors.NewECRAuthError(err).WithComponent("ecr_client").WithOperation("load_config")
		}
		return nil
	})
	if err != nil {
		return nil, err
	}

	// Create ECR client
	ecrClient := ecr.NewFromConfig(cfg)

	// Create HTTP client with timeout
	httpClient := &http.Client{
		Timeout: 30 * time.Second,
	}

	return &Client{
		ecrClient:  ecrClient,
		region:     region,
		httpClient: httpClient,
	}, nil
}

// GetAuthorizationToken retrieves an authorization token for ECR
func (c *Client) GetAuthorizationToken(ctx context.Context) (*appTypes.AuthToken, error) {
	var authToken *appTypes.AuthToken
	
	err := retry.RetryECROperation(ctx, func(ctx context.Context) error {
		input := &ecr.GetAuthorizationTokenInput{}

		result, err := c.ecrClient.GetAuthorizationToken(ctx, input)
		if err != nil {
			return errors.NewECRAuthError(err).
				WithComponent("ecr_client").
				WithOperation("get_authorization_token")
		}

		if len(result.AuthorizationData) == 0 {
			return errors.NewECRAuthError(nil).
				WithComponent("ecr_client").
				WithOperation("get_authorization_token").
				WithDetail("issue", "no_authorization_data_returned")
		}

		authData := result.AuthorizationData[0]
		if authData.AuthorizationToken == nil {
			return errors.NewECRAuthError(nil).
				WithComponent("ecr_client").
				WithOperation("get_authorization_token").
				WithDetail("issue", "authorization_token_nil")
		}

		if authData.ProxyEndpoint == nil {
			return errors.NewECRAuthError(nil).
				WithComponent("ecr_client").
				WithOperation("get_authorization_token").
				WithDetail("issue", "proxy_endpoint_nil")
		}

		if authData.ExpiresAt == nil {
			return errors.NewECRAuthError(nil).
				WithComponent("ecr_client").
				WithOperation("get_authorization_token").
				WithDetail("issue", "expires_at_nil")
		}

		authToken = &appTypes.AuthToken{
			Token:     *authData.AuthorizationToken,
			ExpiresAt: *authData.ExpiresAt,
			Endpoint:  *authData.ProxyEndpoint,
		}
		
		return nil
	})

	if err != nil {
		return nil, err
	}
	
	return authToken, nil
}

// GetImageManifest retrieves the manifest for a specific image
func (c *Client) GetImageManifest(ctx context.Context, repo, tag string) (*appTypes.ImageManifest, error) {
	if strings.TrimSpace(repo) == "" {
		return nil, errors.NewValidationError("EMPTY_REPOSITORY", "Repository name is required", "repository")
	}
	if strings.TrimSpace(tag) == "" {
		return nil, errors.NewValidationError("EMPTY_TAG", "Image tag is required", "tag")
	}

	var manifest *appTypes.ImageManifest
	
	err := retry.RetryECROperation(ctx, func(ctx context.Context) error {
		// First, get the image details to retrieve the manifest
		input := &ecr.BatchGetImageInput{
			RepositoryName: aws.String(repo),
			ImageIds: []types.ImageIdentifier{
				{
					ImageTag: aws.String(tag),
				},
			},
			AcceptedMediaTypes: []string{
				"application/vnd.docker.distribution.manifest.v2+json",
				"application/vnd.oci.image.manifest.v1+json",
			},
		}

		result, err := c.ecrClient.BatchGetImage(ctx, input)
		if err != nil {
			return errors.NewECRConnectionError(err).
				WithComponent("ecr_client").
				WithOperation("batch_get_image").
				WithDetail("repository", repo).
				WithDetail("tag", tag)
		}

		if len(result.Images) == 0 {
			return errors.NewImageNotFoundError(repo, tag).
				WithComponent("ecr_client").
				WithOperation("batch_get_image")
		}

		image := result.Images[0]
		if image.ImageManifest == nil {
			return errors.NewImageError("MANIFEST_NIL", "Image manifest is nil", nil).
				WithComponent("ecr_client").
				WithOperation("batch_get_image").
				WithDetail("repository", repo).
				WithDetail("tag", tag)
		}

		// Parse the manifest JSON
		var manifestData struct {
			MediaType string `json:"mediaType"`
			Config    struct {
				Digest    string `json:"digest"`
				MediaType string `json:"mediaType"`
				Size      int64  `json:"size"`
			} `json:"config"`
			Layers []struct {
				Digest    string `json:"digest"`
				MediaType string `json:"mediaType"`
				Size      int64  `json:"size"`
			} `json:"layers"`
		}

		if err := json.Unmarshal([]byte(*image.ImageManifest), &manifestData); err != nil {
			return errors.NewManifestParseError(err).
				WithComponent("ecr_client").
				WithOperation("parse_manifest").
				WithDetail("repository", repo).
				WithDetail("tag", tag)
		}

		// Validate manifest data
		if manifestData.MediaType == "" {
			return errors.NewUnsupportedImageFormatError("unknown").
				WithComponent("ecr_client").
				WithOperation("validate_manifest")
		}

		// Convert to our types
		layers := make([]appTypes.LayerDigest, len(manifestData.Layers))
		for i, layer := range manifestData.Layers {
			if layer.Digest == "" {
				return errors.NewImageError("INVALID_LAYER_DIGEST", "Layer digest is empty", nil).
					WithComponent("ecr_client").
					WithOperation("parse_manifest").
					WithDetail("layer_index", fmt.Sprintf("%d", i))
			}
			
			layers[i] = appTypes.LayerDigest{
				Digest:    layer.Digest,
				MediaType: layer.MediaType,
				Size:      layer.Size,
			}
		}

		imageDigest := ""
		if image.ImageId.ImageDigest != nil {
			imageDigest = *image.ImageId.ImageDigest
		}

		manifest = &appTypes.ImageManifest{
			MediaType: manifestData.MediaType,
			Digest:    imageDigest,
			Layers:    layers,
			Config: appTypes.ConfigDigest{
				Digest:    manifestData.Config.Digest,
				MediaType: manifestData.Config.MediaType,
				Size:      manifestData.Config.Size,
			},
		}

		return nil
	})

	if err != nil {
		return nil, err
	}

	return manifest, nil
}

// GetImageLayers downloads the specified image layers
func (c *Client) GetImageLayers(ctx context.Context, repo string, layers []appTypes.LayerDigest) ([]appTypes.ImageLayer, error) {
	if strings.TrimSpace(repo) == "" {
		return nil, errors.NewValidationError("EMPTY_REPOSITORY", "Repository name is required", "repository")
	}
	
	if len(layers) == 0 {
		return []appTypes.ImageLayer{}, nil
	}

	// Get authorization token for Docker registry API calls
	authToken, err := c.GetAuthorizationToken(ctx)
	if err != nil {
		return nil, errors.WrapError(err, errors.ErrorTypeAuth, "AUTH_TOKEN_FAILED", 
			"Failed to get auth token for layer download", true).
			WithComponent("ecr_client").
			WithOperation("get_image_layers")
	}

	imageLayers := make([]appTypes.ImageLayer, len(layers))
	var partialResults []appTypes.ImageLayer
	var lastError error

	// Download layers with graceful degradation
	for i, layer := range layers {
		select {
		case <-ctx.Done():
			// Context cancelled, return partial results if any
			if len(partialResults) > 0 {
				return partialResults, errors.NewPartialScanError(len(partialResults), len(layers), ctx.Err()).
					WithComponent("ecr_client").
					WithOperation("get_image_layers")
			}
			return nil, ctx.Err()
		default:
		}

		layerContent, err := c.downloadLayer(ctx, authToken, repo, layer.Digest)
		if err != nil {
			lastError = err
			// For graceful degradation, continue with other layers
			continue
		}

		imageLayer := appTypes.ImageLayer{
			Digest:  layer.Digest,
			Content: layerContent,
			Size:    int64(len(layerContent)),
		}
		
		imageLayers[i] = imageLayer
		partialResults = append(partialResults, imageLayer)
	}

	// If we have some results but not all, return partial results with error
	if len(partialResults) > 0 && len(partialResults) < len(layers) {
		return partialResults, errors.NewPartialScanError(len(partialResults), len(layers), lastError).
			WithComponent("ecr_client").
			WithOperation("get_image_layers")
	}

	// If no results at all, return the last error
	if len(partialResults) == 0 {
		if lastError != nil {
			return nil, lastError
		}
		return nil, errors.NewImageError("NO_LAYERS_DOWNLOADED", "Failed to download any image layers", nil).
			WithComponent("ecr_client").
			WithOperation("get_image_layers")
	}

	return imageLayers, nil
}

// downloadLayer downloads a single layer using the Docker Registry API
func (c *Client) downloadLayer(ctx context.Context, authToken *appTypes.AuthToken, repo, digest string) ([]byte, error) {
	var content []byte
	
	err := retry.RetryLayerDownload(ctx, func(ctx context.Context) error {
		// Check if token is expired
		if time.Now().After(authToken.ExpiresAt) {
			return errors.NewTokenExpiredError().
				WithComponent("ecr_client").
				WithOperation("download_layer").
				WithDetail("layer_digest", digest)
		}

		// Parse the endpoint to get the registry URL
		endpoint := strings.TrimPrefix(authToken.Endpoint, "https://")
		
		// Construct the blob URL
		blobURL := fmt.Sprintf("https://%s/v2/%s/blobs/%s", endpoint, repo, digest)

		// Create HTTP request
		req, err := http.NewRequestWithContext(ctx, "GET", blobURL, nil)
		if err != nil {
			return errors.NewNetworkError("REQUEST_CREATION_FAILED", "Failed to create HTTP request", err, false).
				WithComponent("ecr_client").
				WithOperation("download_layer").
				WithDetail("layer_digest", digest).
				WithDetail("blob_url", blobURL)
		}

		// Set authorization header (token is already base64 encoded)
		req.Header.Set("Authorization", fmt.Sprintf("Basic %s", authToken.Token))
		req.Header.Set("Accept", "application/vnd.docker.image.rootfs.diff.tar.gzip")

		// Make the request
		resp, err := c.httpClient.Do(req)
		if err != nil {
			return errors.NewLayerDownloadError(digest, err).
				WithComponent("ecr_client").
				WithOperation("download_layer")
		}
		defer resp.Body.Close()

		// Handle different HTTP status codes
		switch resp.StatusCode {
		case http.StatusOK:
			// Success, continue to read content
		case http.StatusUnauthorized:
			return errors.NewTokenExpiredError().
				WithComponent("ecr_client").
				WithOperation("download_layer").
				WithDetail("layer_digest", digest).
				WithDetail("http_status", fmt.Sprintf("%d", resp.StatusCode))
		case http.StatusNotFound:
			return errors.NewImageError("LAYER_NOT_FOUND", "Layer not found in registry", nil).
				WithComponent("ecr_client").
				WithOperation("download_layer").
				WithDetail("layer_digest", digest).
				WithDetail("http_status", fmt.Sprintf("%d", resp.StatusCode))
		case http.StatusTooManyRequests, http.StatusServiceUnavailable, http.StatusBadGateway:
			return errors.NewNetworkError("REGISTRY_UNAVAILABLE", "Registry temporarily unavailable", nil, true).
				WithComponent("ecr_client").
				WithOperation("download_layer").
				WithDetail("layer_digest", digest).
				WithDetail("http_status", fmt.Sprintf("%d", resp.StatusCode))
		default:
			return errors.NewLayerDownloadError(digest, 
				fmt.Errorf("unexpected HTTP status: %d", resp.StatusCode)).
				WithComponent("ecr_client").
				WithOperation("download_layer")
		}

		// Check content length if available
		if resp.ContentLength > 0 {
			// Check if layer size exceeds reasonable limits (e.g., 2GB)
			maxLayerSize := int64(2 * 1024 * 1024 * 1024) // 2GB
			if resp.ContentLength > maxLayerSize {
				return errors.NewLayerSizeLimitError(resp.ContentLength, maxLayerSize).
					WithComponent("ecr_client").
					WithOperation("download_layer").
					WithDetail("layer_digest", digest)
			}
		}

		// Read the layer content
		layerContent, err := io.ReadAll(resp.Body)
		if err != nil {
			return errors.NewLayerDownloadError(digest, err).
				WithComponent("ecr_client").
				WithOperation("read_layer_content")
		}

		// Validate that we got some content
		if len(layerContent) == 0 {
			return errors.NewCorruptedLayerError(digest, 
				fmt.Errorf("layer content is empty")).
				WithComponent("ecr_client").
				WithOperation("download_layer")
		}

		content = layerContent
		return nil
	})

	if err != nil {
		return nil, err
	}

	return content, nil
}

// parseRepositoryFromImageURL extracts the repository name from an ECR image URL
func ParseRepositoryFromImageURL(imageURL string) (string, error) {
	// ECR image URL format: <account-id>.dkr.ecr.<region>.amazonaws.com/<repository-name>
	parts := strings.Split(imageURL, "/")
	if len(parts) < 2 {
		return "", fmt.Errorf("invalid ECR image URL format: %s", imageURL)
	}

	// The repository name is everything after the first slash
	repo := strings.Join(parts[1:], "/")
	if repo == "" {
		return "", fmt.Errorf("empty repository name in URL: %s", imageURL)
	}

	return repo, nil
}

// parseRegionFromImageURL extracts the AWS region from an ECR image URL
func ParseRegionFromImageURL(imageURL string) (string, error) {
	// ECR image URL format: <account-id>.dkr.ecr.<region>.amazonaws.com/<repository-name>
	if !strings.Contains(imageURL, ".dkr.ecr.") || !strings.Contains(imageURL, ".amazonaws.com") {
		return "", fmt.Errorf("invalid ECR image URL format: %s", imageURL)
	}

	parts := strings.Split(imageURL, ".")
	if len(parts) < 5 {
		return "", fmt.Errorf("invalid ECR image URL format: %s", imageURL)
	}

	// Find the region part (should be between "ecr" and "amazonaws")
	for i, part := range parts {
		if part == "ecr" && i+1 < len(parts) && i+2 < len(parts) && parts[i+2] == "amazonaws" {
			return parts[i+1], nil
		}
	}

	return "", fmt.Errorf("could not extract region from ECR image URL: %s", imageURL)
}
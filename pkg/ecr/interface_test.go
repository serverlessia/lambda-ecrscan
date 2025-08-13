package ecr

import (
	"ecr-image-scanner/pkg/interfaces"
)

// Compile-time check to ensure Client implements ECRClient interface
var _ interfaces.ECRClient = (*Client)(nil)
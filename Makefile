.PHONY: build clean deploy test

# Build the Go binary for Lambda (provided.al2 runtime)
build:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -ldflags="-s -w" -tags lambda.norpc -o bootstrap cmd/scanner/main.go

# Clean build artifacts
clean:
	rm -f bootstrap scanner

# Deploy using SAM (guided mode)
deploy: build
	./scripts/deploy.sh --guided

# Deploy to dev environment
deploy-dev: build
	./scripts/deploy.sh --environment dev

# Deploy to staging environment
deploy-staging: build
	./scripts/deploy.sh --environment staging

# Deploy to production environment
deploy-prod: build
	./scripts/deploy.sh --environment prod

# Deploy with existing configuration (fast)
deploy-fast: build
	./scripts/deploy.sh --yes

# Run tests
test:
	./scripts/test-local.sh --test-type all

# Run unit tests only
test-unit:
	./scripts/test-local.sh --test-type unit

# Run integration tests
test-integration:
	./scripts/test-local.sh --test-type integration

# Run performance tests
test-performance:
	go test -run Performance ./test/integration/...

# Run end-to-end tests
test-e2e:
	./scripts/test-local.sh --test-type e2e

# Run all integration and e2e tests
test-all-integration:
	go test ./test/integration/...

# Test local binary execution
test-binary:
	./scripts/test-local.sh --test-type binary

# Run tests with verbose output
test-verbose:
	./scripts/test-local.sh --test-type all --verbose

# Run locally for testing
run-local: build
	./bootstrap

# Install dependencies
deps:
	go mod tidy
	go mod download

# Format code
fmt:
	go fmt ./...

# Lint code
lint:
	golangci-lint run

# Build for local testing (native architecture)
build-local:
	CGO_ENABLED=0 go build -ldflags="-s -w" -o scanner cmd/scanner/main.go

# Build and test
all: deps fmt build test

# Validate SAM template (requires SAM CLI)
validate:
	sam validate

# Build and package for deployment
package: build
	sam build
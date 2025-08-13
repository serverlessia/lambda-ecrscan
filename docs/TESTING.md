# Testing Guide

This guide provides comprehensive information about testing the ECR Image Scanner locally and in AWS.

## Test Structure

The project includes multiple types of tests organized in a clear structure:

```
test/
├── fixtures/                    # Test data and sample inputs
│   ├── basic-scan-input.json   # Basic scan test input
│   ├── enhanced-scan-input.json # Enhanced scan test input
│   ├── sample-inputs.json      # Collection of test scenarios
│   ├── expected-outputs.json   # Expected results for validation
│   ├── sample_vulndb.go       # Sample vulnerability database
│   └── test_data.go           # Test data structures and helpers
└── integration/                # Integration and E2E tests
    ├── ecr_integration_test.go # ECR client integration tests
    ├── end_to_end_test.go     # Full end-to-end test scenarios
    ├── local_binary_test.go   # Local binary execution tests
    └── performance_test.go    # Performance and load tests
```

## Test Types

### 1. Unit Tests

Unit tests are located alongside the source code and test individual components in isolation.

```bash
# Run all unit tests
make test-unit

# Run unit tests with verbose output
go test -v -short ./...

# Run unit tests for specific package
go test -v ./pkg/scanner/

# Run unit tests with coverage
go test -cover ./...
```

**Coverage Areas:**
- ECR client functionality with mocked AWS SDK
- Vulnerability scanning logic with test data
- Image layer analysis with sample layers
- Error handling scenarios and edge cases
- Configuration parsing and validation

### 2. Integration Tests

Integration tests verify component interactions and external service integration.

```bash
# Run all integration tests
make test-integration

# Run specific integration test
go test -v -run Integration ./test/integration/

# Run ECR integration tests (requires AWS credentials)
go test -v -run ECRIntegration ./test/integration/
```

**Test Scenarios:**
- ECR authentication and authorization
- Image manifest retrieval from real ECR repositories
- Layer download and processing
- Vulnerability database integration
- Error handling with real AWS services

### 3. End-to-End Tests

End-to-end tests validate the complete scanning workflow from input to output.

```bash
# Run all E2E tests
make test-e2e

# Run specific E2E test scenarios
go test -v -run EndToEnd ./test/integration/

# Run E2E tests with custom timeout
go test -v -timeout 10m -run EndToEnd ./test/integration/
```

**Test Scenarios:**
- Complete scan workflow with real ECR images
- Different scan modes (basic vs enhanced)
- Various image types and sizes
- Error scenarios and recovery
- Output format validation

### 4. Performance Tests

Performance tests measure scanning performance and resource usage.

```bash
# Run performance tests
make test-performance

# Run performance tests with benchmarking
go test -v -bench=. -run Performance ./test/integration/

# Run performance tests with memory profiling
go test -v -memprofile=mem.prof -run Performance ./test/integration/
```

**Performance Metrics:**
- Scan duration for different image sizes
- Memory usage during layer processing
- Concurrent scan performance
- Database lookup performance
- Network I/O efficiency

### 5. Local Binary Tests

Tests for the compiled binary running outside of Lambda environment.

```bash
# Run local binary tests
make test-binary

# Test with specific input file
./scripts/test-local.sh --test-type binary --input test/fixtures/basic-scan-input.json

# Test with output file
./scripts/test-local.sh --test-type binary --output results.json
```

## Using the Test Script

The `scripts/test-local.sh` script provides a unified interface for running tests:

### Basic Usage

```bash
# Run all tests
./scripts/test-local.sh

# Run specific test type
./scripts/test-local.sh --test-type unit
./scripts/test-local.sh --test-type integration
./scripts/test-local.sh --test-type e2e
./scripts/test-local.sh --test-type binary

# Enable verbose output
./scripts/test-local.sh --verbose

# Skip building (use existing binaries)
./scripts/test-local.sh --no-build
```

### Advanced Usage

```bash
# Test local binary with custom input
./scripts/test-local.sh \
  --test-type binary \
  --input test/fixtures/enhanced-scan-input.json \
  --output test-results.json

# Run tests with coverage report
./scripts/test-local.sh --verbose --test-type all
```

## Test Data and Fixtures

### Sample Input Files

#### Basic Scan Input
```json
{
  "imageUrl": "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
  "tag": "latest",
  "scanMode": "basic"
}
```

#### Enhanced Scan Input
```json
{
  "imageUrl": "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
  "tag": "v1.0.0",
  "scanMode": "enhanced"
}
```

#### Advanced Configuration Input
```json
{
  "imageUrl": "123456789012.dkr.ecr.us-east-1.amazonaws.com/vulnerable-app",
  "tag": "latest",
  "scanMode": "enhanced",
  "severityFilter": "HIGH",
  "maxFindings": 50,
  "outputFormat": "summary",
  "timeoutSeconds": 600,
  "config": {
    "debug": "true"
  }
}
```

### Expected Outputs

The `test/fixtures/expected-outputs.json` file contains expected results for various test scenarios:

- Clean images with no vulnerabilities
- Images with known vulnerabilities
- Error scenarios (auth failures, timeouts, etc.)
- Different output formats (detailed vs summary)

### Test Data Helpers

The `test/fixtures/test_data.go` file provides:

- Sample image manifests and layers
- Package inventories for different OS types
- Vulnerability findings for testing
- Lambda event structures
- Helper functions for generating test content

## Testing Strategies

### 1. Mocking External Dependencies

#### ECR Client Mocking
```go
type MockECRClient struct {
    GetAuthTokenFunc    func(ctx context.Context) (*AuthToken, error)
    GetImageManifestFunc func(ctx context.Context, repo, tag string) (*ImageManifest, error)
    GetImageLayersFunc  func(ctx context.Context, repo string, layers []LayerDigest) ([]ImageLayer, error)
}
```

#### Vulnerability Database Mocking
```go
type MockVulnDatabase struct {
    FindVulnerabilitiesFunc func(ctx context.Context, pkg Package, os string) ([]VulnerabilityFinding, error)
    InitializeFunc         func(ctx context.Context) error
}
```

### 2. Test Environment Setup

#### Environment Variables for Testing
```bash
export AWS_REGION=us-east-1
export LOG_LEVEL=DEBUG
export VULN_DB_SOURCE=test://fixtures/sample_vulndb
export MAX_LAYER_SIZE=1073741824
export SCAN_TIMEOUT=300
```

#### Test AWS Credentials
```bash
# Use test credentials (for integration tests)
export AWS_ACCESS_KEY_ID=test-access-key
export AWS_SECRET_ACCESS_KEY=test-secret-key

# Or use AWS CLI profiles
export AWS_PROFILE=test-profile
```

### 3. Test Data Management

#### Creating Test Images
```bash
# Build test image with known vulnerabilities
docker build -t test-vulnerable-image -f test/Dockerfile.vulnerable .

# Push to test ECR repository
aws ecr get-login-password --region us-east-1 | docker login --username AWS --password-stdin 123456789012.dkr.ecr.us-east-1.amazonaws.com
docker tag test-vulnerable-image:latest 123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo:vulnerable
docker push 123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo:vulnerable
```

#### Generating Test Vulnerability Database
```go
// Generate test vulnerability data
func GenerateTestVulnDB() *VulnDatabase {
    return &VulnDatabase{
        Vulnerabilities: map[string][]Vulnerability{
            "openssl": {
                {CVE: "CVE-2022-0778", Severity: "HIGH", Description: "..."},
            },
            "log4j-core": {
                {CVE: "CVE-2021-44228", Severity: "CRITICAL", Description: "..."},
            },
        },
    }
}
```

## Continuous Integration Testing

### GitHub Actions Configuration

```yaml
name: Test ECR Image Scanner

on: [push, pull_request]

jobs:
  test:
    runs-on: ubuntu-latest
    
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v3
        with:
          go-version: '1.19'
      
      - name: Install dependencies
        run: make deps
      
      - name: Run unit tests
        run: make test-unit
      
      - name: Run integration tests
        env:
          AWS_ACCESS_KEY_ID: ${{ secrets.AWS_ACCESS_KEY_ID }}
          AWS_SECRET_ACCESS_KEY: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
        run: make test-integration
      
      - name: Generate coverage report
        run: |
          go test -coverprofile=coverage.out ./...
          go tool cover -html=coverage.out -o coverage.html
      
      - name: Upload coverage to Codecov
        uses: codecov/codecov-action@v3
        with:
          file: ./coverage.out
```

### AWS CodeBuild Configuration

```yaml
version: 0.2
phases:
  install:
    runtime-versions:
      golang: 1.19
  
  pre_build:
    commands:
      - make deps
  
  build:
    commands:
      - make test-unit
      - make test-integration
      - make build
  
  post_build:
    commands:
      - make test-binary
      - echo "All tests passed"

reports:
  test-reports:
    files:
      - 'test-results.xml'
    base-directory: '.'
    file-format: 'JUNITXML'

artifacts:
  files:
    - coverage.out
    - coverage.html
```

## Testing Best Practices

### 1. Test Organization

- **Separate unit and integration tests** using build tags or separate directories
- **Use table-driven tests** for testing multiple scenarios
- **Mock external dependencies** to ensure test reliability
- **Use test helpers** to reduce code duplication

### 2. Test Data Management

- **Use fixtures** for consistent test data
- **Generate test data** programmatically when possible
- **Version control test data** to ensure reproducibility
- **Clean up test resources** after test execution

### 3. Error Testing

- **Test error conditions** explicitly
- **Verify error messages** and error codes
- **Test timeout scenarios** and resource limits
- **Test recovery mechanisms** and retry logic

### 4. Performance Testing

- **Set performance benchmarks** for critical operations
- **Test with realistic data sizes** and scenarios
- **Monitor memory usage** and resource consumption
- **Test concurrent operations** and race conditions

### 5. Integration Testing

- **Use real AWS services** when possible for integration tests
- **Test with multiple AWS regions** and configurations
- **Verify IAM permissions** and security boundaries
- **Test deployment and rollback** procedures

## Troubleshooting Test Issues

### Common Test Failures

#### 1. AWS Credential Issues
```bash
# Check AWS credentials
aws sts get-caller-identity

# Set test credentials
export AWS_PROFILE=test-profile
```

#### 2. Network Connectivity Issues
```bash
# Test ECR connectivity
aws ecr describe-repositories --region us-east-1

# Check VPC/security group settings if using VPC
```

#### 3. Test Data Issues
```bash
# Regenerate test data
go run test/fixtures/generate_test_data.go

# Verify test image availability
aws ecr describe-images --repository-name test-repo --region us-east-1
```

#### 4. Timeout Issues
```bash
# Increase test timeout
go test -timeout 10m ./test/integration/

# Check system resources
top
df -h
```

### Debugging Test Failures

#### Enable Debug Logging
```bash
export LOG_LEVEL=DEBUG
go test -v ./...
```

#### Run Individual Tests
```bash
# Run specific test function
go test -v -run TestSpecificFunction ./pkg/scanner/

# Run with race detection
go test -race ./...
```

#### Profile Test Performance
```bash
# CPU profiling
go test -cpuprofile=cpu.prof -run TestPerformance ./test/integration/

# Memory profiling
go test -memprofile=mem.prof -run TestPerformance ./test/integration/

# Analyze profiles
go tool pprof cpu.prof
go tool pprof mem.prof
```

## Test Coverage

### Generating Coverage Reports

```bash
# Generate coverage for all packages
go test -coverprofile=coverage.out ./...

# Generate HTML coverage report
go tool cover -html=coverage.out -o coverage.html

# View coverage by function
go tool cover -func=coverage.out
```

### Coverage Targets

- **Unit Tests**: Aim for >90% coverage
- **Integration Tests**: Focus on critical paths
- **E2E Tests**: Cover main user scenarios
- **Error Handling**: Test all error conditions

### Excluding Files from Coverage

```bash
# Exclude generated files and test files
go test -coverprofile=coverage.out -coverpkg=./... ./... | grep -v "_test.go" | grep -v ".pb.go"
```

## Load Testing

### Concurrent Scan Testing

```go
func TestConcurrentScans(t *testing.T) {
    const numScans = 10
    var wg sync.WaitGroup
    
    for i := 0; i < numScans; i++ {
        wg.Add(1)
        go func() {
            defer wg.Done()
            // Perform scan
            result, err := scanner.ScanImage(ctx, manifest, layers, ScanModeBasic)
            assert.NoError(t, err)
            assert.NotNil(t, result)
        }()
    }
    
    wg.Wait()
}
```

### Memory Usage Testing

```go
func TestMemoryUsage(t *testing.T) {
    var m1, m2 runtime.MemStats
    
    runtime.GC()
    runtime.ReadMemStats(&m1)
    
    // Perform memory-intensive operation
    result, err := scanner.ScanLargeImage(ctx, largeManifest, largeLayers)
    
    runtime.GC()
    runtime.ReadMemStats(&m2)
    
    memUsed := m2.Alloc - m1.Alloc
    assert.Less(t, memUsed, uint64(100*1024*1024)) // Less than 100MB
}
```

This comprehensive testing guide ensures thorough validation of the ECR Image Scanner functionality across all deployment scenarios and use cases.
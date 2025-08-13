# ECR Image Scanner

A serverless AWS Lambda function that performs custom vulnerability scanning of container images stored in Amazon ECR (Elastic Container Registry). The scanner supports both basic and enhanced scanning modes and returns structured results with severity classifications.

## Features

- **Custom Vulnerability Scanning**: Performs its own vulnerability analysis similar to ECR's basic scan functionality
- **Dual Scan Modes**: Supports both basic and enhanced scanning for different levels of analysis
- **Severity Classification**: Categorizes findings by severity (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)
- **Flexible Input**: Accepts various configuration options including filters and timeouts
- **Local Testing**: Can be run locally for development and testing
- **AWS Integration**: Deployed as Lambda function with minimal IAM permissions
- **Monitoring**: Includes CloudWatch alarms and dead letter queue for error handling

## Architecture

The scanner is built with Go and deployed using AWS SAM (Serverless Application Model). It uses the `provided.al2` runtime for optimal performance and includes:

- **Lambda Function**: Main scanning logic with configurable timeout and memory
- **IAM Role**: Minimal permissions for ECR access and CloudWatch logging
- **Dead Letter Queue**: Handles failed scan requests
- **CloudWatch Alarms**: Monitors function errors and duration
- **API Gateway**: Optional REST API endpoint for HTTP access

## Prerequisites

- [Go](https://golang.org/doc/install) 1.19 or later
- [AWS CLI](https://aws.amazon.com/cli/) configured with appropriate credentials
- [SAM CLI](https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html) for deployment
- Docker (optional, for local SAM testing)

## Quick Start

### 1. Clone and Build

```bash
git clone <repository-url>
cd lambda-ecrscan
make build
```

### 2. Deploy to AWS

```bash
# Deploy to dev environment (guided setup)
make deploy

# Or deploy to specific environment
make deploy-dev
make deploy-staging
make deploy-prod
```

### 3. Test Locally

```bash
# Run all tests
make test

# Test local binary with sample input
make test-binary
```

## Usage

### Lambda Function Input

The Lambda function accepts JSON input with the following structure:

```json
{
  "imageUrl": "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
  "tag": "latest",
  "scanMode": "basic",
  "region": "us-east-1",
  "severityFilter": "HIGH",
  "maxFindings": 100,
  "timeoutSeconds": 300,
  "outputFormat": "detailed",
  "config": {
    "debug": "false"
  }
}
```

#### Input Parameters

| Parameter | Type | Required | Default | Description |
|-----------|------|----------|---------|-------------|
| `imageUrl` | string | Yes | - | ECR image URL to scan |
| `tag` | string | Yes | - | Image tag to scan |
| `scanMode` | string | No | "basic" | Scanning mode: "basic" or "enhanced" |
| `region` | string | No | AWS_REGION env | AWS region for ECR access |
| `severityFilter` | string | No | - | Minimum severity: "CRITICAL", "HIGH", "MEDIUM", "LOW" |
| `maxFindings` | int | No | 1000 | Maximum number of findings to return |
| `timeoutSeconds` | int | No | 300 | Scan timeout in seconds |
| `outputFormat` | string | No | "detailed" | Output format: "detailed" or "summary" |
| `config` | map | No | {} | Additional configuration options |

### Lambda Function Output

The function returns structured JSON with scan results:

```json
{
  "scanResults": {
    "totalVulnerabilities": 3,
    "severityCounts": {
      "CRITICAL": 1,
      "HIGH": 2
    },
    "findings": [
      {
        "cve": "CVE-2021-44228",
        "package": "log4j-core",
        "version": "2.14.1",
        "severity": "CRITICAL",
        "description": "Apache Log4j2 JNDI features do not protect against attacker controlled LDAP",
        "fixedIn": "2.15.0"
      }
    ]
  },
  "metadata": {
    "scanId": "scan-12345",
    "imageUrl": "123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo",
    "tag": "latest",
    "scanMode": "basic",
    "scanStartTime": "2024-01-01T00:00:00Z",
    "scanEndTime": "2024-01-01T00:02:30Z",
    "databaseInfo": {
      "lastUpdated": "2024-01-01T00:00:00Z",
      "version": "1.0.0",
      "sources": ["NVD", "GitHub Security Advisories"]
    }
  }
}
```

## Development

### Local Development Setup

1. **Install Dependencies**
   ```bash
   make deps
   ```

2. **Build Binaries**
   ```bash
   # Build Lambda binary
   make build
   
   # Build local binary for testing
   make build-local
   ```

3. **Run Tests**
   ```bash
   # Run all tests
   make test
   
   # Run specific test types
   make test-unit
   make test-integration
   make test-e2e
   ```

### Local Testing

#### Using the Test Script

The `scripts/test-local.sh` script provides comprehensive testing capabilities:

```bash
# Run all tests
./scripts/test-local.sh

# Run specific test types
./scripts/test-local.sh --test-type unit
./scripts/test-local.sh --test-type integration
./scripts/test-local.sh --test-type e2e

# Test local binary with sample input
./scripts/test-local.sh --test-type binary

# Test with custom input file
./scripts/test-local.sh --test-type binary --input test/fixtures/basic-scan-input.json

# Verbose output with coverage
./scripts/test-local.sh --verbose
```

#### Manual Binary Testing

You can also test the local binary directly:

```bash
# Build local binary
make build-local

# Test with sample input
./scanner < test/fixtures/basic-scan-input.json

# Test with enhanced scanning
./scanner < test/fixtures/enhanced-scan-input.json
```

#### Sample Test Inputs

The `test/fixtures/` directory contains various sample inputs:

- `basic-scan-input.json` - Basic scanning example
- `enhanced-scan-input.json` - Enhanced scanning example
- `sample-inputs.json` - Collection of test scenarios
- `expected-outputs.json` - Expected results for validation

### Code Quality

```bash
# Format code
make fmt

# Run linter (requires golangci-lint)
make lint

# Validate SAM template
make validate
```

## Deployment

### Using the Deployment Script

The `scripts/deploy.sh` script provides flexible deployment options:

```bash
# Guided deployment (first time)
./scripts/deploy.sh --guided

# Deploy to specific environment
./scripts/deploy.sh --environment dev
./scripts/deploy.sh --environment staging
./scripts/deploy.sh --environment prod

# Deploy to specific region
./scripts/deploy.sh --environment prod --region us-west-2

# Deploy without confirmation prompts
./scripts/deploy.sh --environment dev --yes

# Custom configuration
./scripts/deploy.sh \
  --environment prod \
  --log-level ERROR \
  --max-layer-size 2147483648 \
  --scan-timeout 600
```

#### Deployment Script Options

| Option | Description | Default |
|--------|-------------|---------|
| `--environment` | Environment (dev, staging, prod) | dev |
| `--region` | AWS region | Current AWS CLI region |
| `--stack-name` | CloudFormation stack name | ecr-image-scanner-{env} |
| `--guided` | Run SAM deploy in guided mode | false |
| `--yes` | Skip confirmation prompts | false |
| `--log-level` | Log level (DEBUG, INFO, WARN, ERROR) | INFO |
| `--max-layer-size` | Maximum layer size in bytes | 1073741824 |
| `--scan-timeout` | Scan timeout in seconds | 300 |

### Using Make Targets

```bash
# Deploy with guided setup
make deploy

# Deploy to specific environments
make deploy-dev
make deploy-staging
make deploy-prod

# Fast deployment (skip confirmations)
make deploy-fast
```

### Manual SAM Deployment

```bash
# Build and validate
make build
sam validate

# Deploy with parameters
sam deploy \
  --stack-name ecr-image-scanner-dev \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    Environment=dev \
    LogLevel=INFO \
    MaxLayerSize=1073741824 \
    ScanTimeout=300
```

## Configuration

### Environment Variables

The Lambda function supports the following environment variables:

| Variable | Description | Default |
|----------|-------------|---------|
| `AWS_REGION` | AWS region for ECR access | Function region |
| `VULN_DB_SOURCE` | Vulnerability database source URL | "" |
| `LOG_LEVEL` | Logging level | INFO |
| `MAX_LAYER_SIZE` | Maximum layer size in bytes | 1073741824 |
| `CACHE_ENABLED` | Enable layer caching | false |
| `SCAN_TIMEOUT` | Scan timeout in seconds | 300 |
| `MAX_FINDINGS` | Maximum findings to return | 1000 |
| `DEFAULT_SCAN_MODE` | Default scanning mode | basic |

### IAM Permissions

The Lambda function requires the following minimal IAM permissions:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "ecr:GetAuthorizationToken"
      ],
      "Resource": "*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "ecr:BatchCheckLayerAvailability",
        "ecr:GetDownloadUrlForLayer",
        "ecr:BatchGetImage",
        "ecr:DescribeRepositories",
        "ecr:DescribeImages"
      ],
      "Resource": "arn:aws:ecr:*:*:repository/*"
    },
    {
      "Effect": "Allow",
      "Action": [
        "logs:CreateLogGroup",
        "logs:CreateLogStream",
        "logs:PutLogEvents"
      ],
      "Resource": "arn:aws:logs:*:*:log-group:/aws/lambda/ecr-image-scanner-*:*"
    }
  ]
}
```

## Monitoring and Troubleshooting

### CloudWatch Metrics

The deployment includes CloudWatch alarms for:

- **Function Errors**: Triggers when error count exceeds threshold
- **Function Duration**: Triggers when execution time approaches timeout
- **Dead Letter Queue**: Monitors failed scan requests

### Logs

View function logs using AWS CLI:

```bash
# View recent logs
aws logs tail /aws/lambda/ecr-image-scanner-dev --follow

# View logs for specific time range
aws logs filter-log-events \
  --log-group-name /aws/lambda/ecr-image-scanner-dev \
  --start-time 1640995200000 \
  --end-time 1640998800000
```

### Common Issues

1. **Authentication Errors**
   - Verify AWS credentials and IAM permissions
   - Check ECR repository permissions
   - Ensure correct region configuration

2. **Timeout Errors**
   - Increase Lambda timeout in SAM template
   - Use basic scan mode for large images
   - Check network connectivity to ECR

3. **Memory Errors**
   - Increase Lambda memory allocation
   - Reduce max layer size configuration
   - Enable layer caching if available

## Testing

### Test Structure

```
test/
├── fixtures/           # Test data and sample inputs
│   ├── basic-scan-input.json
│   ├── enhanced-scan-input.json
│   ├── sample-inputs.json
│   ├── expected-outputs.json
│   ├── sample_vulndb.go
│   └── test_data.go
└── integration/        # Integration and E2E tests
    ├── ecr_integration_test.go
    ├── end_to_end_test.go
    ├── local_binary_test.go
    └── performance_test.go
```

### Running Tests

```bash
# All tests
make test

# Unit tests only
make test-unit

# Integration tests
make test-integration

# End-to-end tests
make test-e2e

# Performance tests
make test-performance

# Local binary tests
make test-binary

# Verbose output with coverage
make test-verbose
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Add tests for new functionality
5. Run the test suite
6. Submit a pull request

### Code Standards

- Follow Go best practices and conventions
- Add unit tests for new functions
- Update documentation for API changes
- Use meaningful commit messages
- Ensure all tests pass before submitting

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

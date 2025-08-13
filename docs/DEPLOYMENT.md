# Deployment Guide

This guide provides detailed instructions for deploying the ECR Image Scanner Lambda function to AWS.

## Prerequisites

Before deploying, ensure you have:

1. **AWS CLI** configured with appropriate credentials
2. **SAM CLI** installed and configured
3. **Go** 1.19 or later installed
4. **Make** utility available
5. **Appropriate IAM permissions** for deployment

### Required IAM Permissions for Deployment

Your AWS user/role needs the following permissions to deploy the stack:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "cloudformation:*",
        "lambda:*",
        "iam:CreateRole",
        "iam:DeleteRole",
        "iam:GetRole",
        "iam:PassRole",
        "iam:AttachRolePolicy",
        "iam:DetachRolePolicy",
        "iam:PutRolePolicy",
        "iam:DeleteRolePolicy",
        "logs:CreateLogGroup",
        "logs:DeleteLogGroup",
        "logs:DescribeLogGroups",
        "logs:PutRetentionPolicy",
        "sqs:CreateQueue",
        "sqs:DeleteQueue",
        "sqs:GetQueueAttributes",
        "sqs:SetQueueAttributes",
        "sqs:TagQueue",
        "cloudwatch:PutMetricAlarm",
        "cloudwatch:DeleteAlarms",
        "apigateway:*",
        "s3:CreateBucket",
        "s3:DeleteBucket",
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ],
      "Resource": "*"
    }
  ]
}
```

## Deployment Methods

### Method 1: Using Deployment Script (Recommended)

The deployment script provides the most flexible and user-friendly deployment experience.

#### First-Time Deployment (Guided)

```bash
# Run guided deployment to set up initial configuration
./scripts/deploy.sh --guided
```

This will:
1. Build the application
2. Validate the SAM template
3. Guide you through configuration options
4. Create a `samconfig.toml` file for future deployments
5. Deploy the stack

#### Environment-Specific Deployments

```bash
# Deploy to development environment
./scripts/deploy.sh --environment dev

# Deploy to staging environment
./scripts/deploy.sh --environment staging --region us-west-2

# Deploy to production environment
./scripts/deploy.sh --environment prod --region us-east-1 --log-level ERROR
```

#### Advanced Deployment Options

```bash
# Deploy with custom configuration
./scripts/deploy.sh \
  --environment prod \
  --region us-west-2 \
  --stack-name my-custom-scanner \
  --log-level ERROR \
  --max-layer-size 2147483648 \
  --scan-timeout 600 \
  --yes
```

### Method 2: Using Make Targets

```bash
# Guided deployment (first time)
make deploy

# Environment-specific deployments
make deploy-dev
make deploy-staging
make deploy-prod

# Fast deployment (skip confirmations)
make deploy-fast
```

### Method 3: Manual SAM Deployment

```bash
# Build the application
make build

# Validate the template
sam validate

# Deploy with custom parameters
sam deploy \
  --stack-name ecr-image-scanner-prod \
  --capabilities CAPABILITY_IAM \
  --parameter-overrides \
    Environment=prod \
    LogLevel=ERROR \
    MaxLayerSize=2147483648 \
    ScanTimeout=600 \
  --region us-east-1
```

## Configuration Parameters

### SAM Template Parameters

| Parameter | Description | Type | Default | Allowed Values |
|-----------|-------------|------|---------|----------------|
| `Environment` | Environment name | String | dev | dev, staging, prod |
| `LogLevel` | Lambda function log level | String | INFO | DEBUG, INFO, WARN, ERROR |
| `MaxLayerSize` | Maximum layer size in bytes | Number | 1073741824 | 1-10737418240 |
| `ScanTimeout` | Scan timeout in seconds | Number | 300 | 60-900 |

### Environment-Specific Configurations

#### Development Environment
```bash
./scripts/deploy.sh \
  --environment dev \
  --log-level DEBUG \
  --scan-timeout 300
```

#### Staging Environment
```bash
./scripts/deploy.sh \
  --environment staging \
  --log-level INFO \
  --scan-timeout 450
```

#### Production Environment
```bash
./scripts/deploy.sh \
  --environment prod \
  --log-level ERROR \
  --scan-timeout 600 \
  --max-layer-size 2147483648
```

## Post-Deployment Verification

### 1. Verify Stack Deployment

```bash
# Check stack status
aws cloudformation describe-stacks \
  --stack-name ecr-image-scanner-dev \
  --query 'Stacks[0].StackStatus'

# List stack outputs
aws cloudformation describe-stacks \
  --stack-name ecr-image-scanner-dev \
  --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
  --output table
```

### 2. Test Lambda Function

```bash
# Get function name from stack outputs
FUNCTION_NAME=$(aws cloudformation describe-stacks \
  --stack-name ecr-image-scanner-dev \
  --query 'Stacks[0].Outputs[?OutputKey==`ECRImageScannerFunctionName`].OutputValue' \
  --output text)

# Test with sample payload
aws lambda invoke \
  --function-name $FUNCTION_NAME \
  --payload file://test/fixtures/basic-scan-input.json \
  response.json

# Check response
cat response.json
```

### 3. Verify CloudWatch Resources

```bash
# Check log group
aws logs describe-log-groups \
  --log-group-name-prefix "/aws/lambda/ecr-image-scanner"

# Check CloudWatch alarms
aws cloudwatch describe-alarms \
  --alarm-name-prefix "ECRImageScanner"
```

### 4. Test API Gateway (if enabled)

```bash
# Get API endpoint from stack outputs
API_ENDPOINT=$(aws cloudformation describe-stacks \
  --stack-name ecr-image-scanner-dev \
  --query 'Stacks[0].Outputs[?OutputKey==`ECRImageScannerApi`].OutputValue' \
  --output text)

# Test API endpoint
curl -X POST $API_ENDPOINT \
  -H "Content-Type: application/json" \
  -d @test/fixtures/basic-scan-input.json
```

## Troubleshooting Deployment Issues

### Common Issues and Solutions

#### 1. SAM CLI Not Found
```bash
# Install SAM CLI
pip install aws-sam-cli

# Or using Homebrew (macOS)
brew install aws-sam-cli
```

#### 2. AWS Credentials Not Configured
```bash
# Configure AWS CLI
aws configure

# Or set environment variables
export AWS_ACCESS_KEY_ID=your-access-key
export AWS_SECRET_ACCESS_KEY=your-secret-key
export AWS_DEFAULT_REGION=us-east-1
```

#### 3. Insufficient IAM Permissions
- Ensure your AWS user/role has the required permissions listed above
- Check CloudTrail logs for specific permission denials

#### 4. Stack Already Exists Error
```bash
# Update existing stack
sam deploy --stack-name ecr-image-scanner-dev

# Or delete and recreate
aws cloudformation delete-stack --stack-name ecr-image-scanner-dev
aws cloudformation wait stack-delete-complete --stack-name ecr-image-scanner-dev
```

#### 5. Build Failures
```bash
# Clean and rebuild
make clean
make build

# Check Go version
go version

# Verify dependencies
make deps
```

#### 6. Template Validation Errors
```bash
# Validate template
sam validate --template template.yaml

# Check for syntax errors
yamllint template.yaml
```

### Debugging Deployment

#### Enable Verbose Output
```bash
# SAM CLI debug mode
sam deploy --debug

# Deployment script verbose mode
./scripts/deploy.sh --environment dev --verbose
```

#### Check CloudFormation Events
```bash
# Monitor stack events during deployment
aws cloudformation describe-stack-events \
  --stack-name ecr-image-scanner-dev \
  --query 'StackEvents[*].[Timestamp,ResourceStatus,ResourceType,LogicalResourceId,ResourceStatusReason]' \
  --output table
```

## Multi-Region Deployment

### Deploy to Multiple Regions

```bash
# Deploy to us-east-1
./scripts/deploy.sh --environment prod --region us-east-1

# Deploy to us-west-2
./scripts/deploy.sh --environment prod --region us-west-2

# Deploy to eu-west-1
./scripts/deploy.sh --environment prod --region eu-west-1
```

### Cross-Region Considerations

1. **ECR Repository Access**: Ensure the Lambda function has permissions to access ECR repositories in the target region
2. **VPC Configuration**: If using VPC, ensure proper networking setup
3. **KMS Keys**: Consider region-specific KMS keys for encryption
4. **Compliance**: Ensure deployment meets regional compliance requirements

## CI/CD Integration

### GitHub Actions Example

```yaml
name: Deploy ECR Image Scanner

on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Go
        uses: actions/setup-go@v3
        with:
          go-version: '1.19'
      
      - name: Setup SAM CLI
        uses: aws-actions/setup-sam@v2
      
      - name: Configure AWS credentials
        uses: aws-actions/configure-aws-credentials@v2
        with:
          aws-access-key-id: ${{ secrets.AWS_ACCESS_KEY_ID }}
          aws-secret-access-key: ${{ secrets.AWS_SECRET_ACCESS_KEY }}
          aws-region: us-east-1
      
      - name: Run tests
        run: make test
      
      - name: Deploy to staging
        if: github.ref == 'refs/heads/main'
        run: ./scripts/deploy.sh --environment staging --yes
      
      - name: Deploy to production
        if: github.event_name == 'release'
        run: ./scripts/deploy.sh --environment prod --yes
```

### AWS CodePipeline Example

```yaml
version: 0.2
phases:
  install:
    runtime-versions:
      golang: 1.19
    commands:
      - pip install aws-sam-cli
  
  pre_build:
    commands:
      - make deps
      - make test
  
  build:
    commands:
      - make build
      - sam validate
  
  post_build:
    commands:
      - ./scripts/deploy.sh --environment $ENVIRONMENT --yes

artifacts:
  files:
    - '**/*'
```

## Rollback Procedures

### Automatic Rollback

SAM CLI supports automatic rollback on deployment failure:

```bash
sam deploy --on-failure ROLLBACK
```

### Manual Rollback

```bash
# List stack change sets
aws cloudformation list-change-sets --stack-name ecr-image-scanner-dev

# Rollback to previous version
aws cloudformation cancel-update-stack --stack-name ecr-image-scanner-dev

# Or delete and redeploy previous version
aws cloudformation delete-stack --stack-name ecr-image-scanner-dev
git checkout previous-version
./scripts/deploy.sh --environment dev
```

## Cleanup

### Delete Stack

```bash
# Delete development stack
aws cloudformation delete-stack --stack-name ecr-image-scanner-dev

# Wait for deletion to complete
aws cloudformation wait stack-delete-complete --stack-name ecr-image-scanner-dev

# Verify deletion
aws cloudformation describe-stacks --stack-name ecr-image-scanner-dev
```

### Clean Local Artifacts

```bash
# Clean build artifacts
make clean

# Remove SAM build directory
rm -rf .aws-sam/

# Remove generated files
rm -f samconfig.toml
rm -f coverage.out coverage.html
```

## Best Practices

1. **Use Environment-Specific Stacks**: Deploy separate stacks for dev, staging, and prod
2. **Version Control Configuration**: Store `samconfig.toml` in version control
3. **Automated Testing**: Run tests before deployment
4. **Gradual Rollout**: Deploy to staging before production
5. **Monitor Deployments**: Watch CloudFormation events during deployment
6. **Backup Configuration**: Keep backup of working configurations
7. **Security**: Use least-privilege IAM permissions
8. **Cost Optimization**: Set appropriate Lambda memory and timeout values
9. **Logging**: Configure appropriate log levels for each environment
10. **Documentation**: Keep deployment procedures documented and up-to-date
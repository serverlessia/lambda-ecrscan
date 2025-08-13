#!/bin/bash

# ECR Image Scanner Deployment Script
# This script builds and deploys the ECR Image Scanner Lambda function using SAM

set -e

# Default values
ENVIRONMENT="dev"
REGION=""
STACK_NAME=""
GUIDED=false
CONFIRM_CHANGESET=true
LOG_LEVEL="INFO"
MAX_LAYER_SIZE="1073741824"
SCAN_TIMEOUT="300"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Function to show usage
show_usage() {
    cat << EOF
Usage: $0 [OPTIONS]

Deploy ECR Image Scanner Lambda function using SAM

OPTIONS:
    -e, --environment ENV       Environment (dev, staging, prod) [default: dev]
    -r, --region REGION         AWS region [default: current AWS CLI region]
    -s, --stack-name NAME       CloudFormation stack name [default: ecr-image-scanner-ENV]
    -g, --guided                Run SAM deploy in guided mode
    -y, --yes                   Skip confirmation prompts
    -l, --log-level LEVEL       Log level (DEBUG, INFO, WARN, ERROR) [default: INFO]
    --max-layer-size SIZE       Maximum layer size in bytes [default: 1073741824]
    --scan-timeout TIMEOUT     Scan timeout in seconds [default: 300]
    -h, --help                  Show this help message

EXAMPLES:
    $0                          # Deploy to dev environment
    $0 -e staging -r us-west-2  # Deploy to staging in us-west-2
    $0 -g                       # Run guided deployment
    $0 -e prod -y               # Deploy to prod without confirmation

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -e|--environment)
            ENVIRONMENT="$2"
            shift 2
            ;;
        -r|--region)
            REGION="$2"
            shift 2
            ;;
        -s|--stack-name)
            STACK_NAME="$2"
            shift 2
            ;;
        -g|--guided)
            GUIDED=true
            shift
            ;;
        -y|--yes)
            CONFIRM_CHANGESET=false
            shift
            ;;
        -l|--log-level)
            LOG_LEVEL="$2"
            shift 2
            ;;
        --max-layer-size)
            MAX_LAYER_SIZE="$2"
            shift 2
            ;;
        --scan-timeout)
            SCAN_TIMEOUT="$2"
            shift 2
            ;;
        -h|--help)
            show_usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            show_usage
            exit 1
            ;;
    esac
done

# Validate environment
if [[ ! "$ENVIRONMENT" =~ ^(dev|staging|prod)$ ]]; then
    print_error "Invalid environment: $ENVIRONMENT. Must be dev, staging, or prod."
    exit 1
fi

# Set default stack name if not provided
if [[ -z "$STACK_NAME" ]]; then
    STACK_NAME="ecr-image-scanner-$ENVIRONMENT"
fi

# Set default region if not provided
if [[ -z "$REGION" ]]; then
    REGION=$(aws configure get region)
    if [[ -z "$REGION" ]]; then
        print_error "No region specified and no default region configured in AWS CLI"
        exit 1
    fi
fi

print_info "Starting deployment with the following configuration:"
echo "  Environment: $ENVIRONMENT"
echo "  Region: $REGION"
echo "  Stack Name: $STACK_NAME"
echo "  Log Level: $LOG_LEVEL"
echo "  Max Layer Size: $MAX_LAYER_SIZE bytes"
echo "  Scan Timeout: $SCAN_TIMEOUT seconds"
echo "  Guided Mode: $GUIDED"
echo "  Confirm Changeset: $CONFIRM_CHANGESET"
echo

# Check prerequisites
print_info "Checking prerequisites..."

# Check if SAM CLI is installed
if ! command -v sam &> /dev/null; then
    print_error "SAM CLI is not installed. Please install it first."
    print_info "Installation guide: https://docs.aws.amazon.com/serverless-application-model/latest/developerguide/serverless-sam-cli-install.html"
    exit 1
fi

# Check if AWS CLI is configured
if ! aws sts get-caller-identity &> /dev/null; then
    print_error "AWS CLI is not configured or credentials are invalid."
    print_info "Run 'aws configure' to set up your credentials."
    exit 1
fi

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_error "Go is not installed. Please install Go first."
    exit 1
fi

print_success "Prerequisites check passed"

# Build the application
print_info "Building the application..."
if ! make build; then
    print_error "Build failed"
    exit 1
fi
print_success "Build completed"

# Validate SAM template
print_info "Validating SAM template..."
if ! sam validate --region "$REGION"; then
    print_error "SAM template validation failed"
    exit 1
fi
print_success "SAM template validation passed"

# Deploy the application
print_info "Deploying the application..."

if [[ "$GUIDED" == true ]]; then
    # Guided deployment
    print_info "Running guided deployment..."
    sam deploy --guided \
        --region "$REGION" \
        --stack-name "$STACK_NAME"
else
    # Non-guided deployment
    DEPLOY_ARGS=(
        --region "$REGION"
        --stack-name "$STACK_NAME"
        --capabilities CAPABILITY_IAM
        --parameter-overrides
        "Environment=$ENVIRONMENT"
        "LogLevel=$LOG_LEVEL"
        "MaxLayerSize=$MAX_LAYER_SIZE"
        "ScanTimeout=$SCAN_TIMEOUT"
    )
    
    if [[ "$CONFIRM_CHANGESET" == false ]]; then
        DEPLOY_ARGS+=(--no-confirm-changeset)
    fi
    
    sam deploy "${DEPLOY_ARGS[@]}"
fi

if [[ $? -eq 0 ]]; then
    print_success "Deployment completed successfully!"
    
    # Get stack outputs
    print_info "Retrieving stack outputs..."
    aws cloudformation describe-stacks \
        --stack-name "$STACK_NAME" \
        --region "$REGION" \
        --query 'Stacks[0].Outputs[*].[OutputKey,OutputValue]' \
        --output table
    
    print_info "Deployment Summary:"
    echo "  Stack Name: $STACK_NAME"
    echo "  Region: $REGION"
    echo "  Environment: $ENVIRONMENT"
    echo
    print_success "ECR Image Scanner is now deployed and ready to use!"
else
    print_error "Deployment failed"
    exit 1
fi
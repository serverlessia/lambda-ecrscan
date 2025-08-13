#!/bin/bash

# ECR Image Scanner Local Testing Script
# This script builds and tests the ECR Image Scanner locally

set -e

# Default values
TEST_TYPE="all"
VERBOSE=false
BUILD=true
INPUT_FILE=""
OUTPUT_FILE=""

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

Test ECR Image Scanner locally

OPTIONS:
    -t, --test-type TYPE        Type of tests to run (unit, integration, e2e, all) [default: all]
    -v, --verbose               Enable verbose output
    --no-build                  Skip building the binary
    -i, --input FILE            Input file for local binary testing
    -o, --output FILE           Output file for test results
    -h, --help                  Show this help message

TEST TYPES:
    unit                        Run unit tests only
    integration                 Run integration tests only
    e2e                         Run end-to-end tests only
    all                         Run all tests
    binary                      Test local binary execution

EXAMPLES:
    $0                          # Run all tests
    $0 -t unit                  # Run unit tests only
    $0 -t binary -i test/fixtures/sample-input.json
    $0 --no-build -t integration

EOF
}

# Parse command line arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -t|--test-type)
            TEST_TYPE="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=true
            shift
            ;;
        --no-build)
            BUILD=false
            shift
            ;;
        -i|--input)
            INPUT_FILE="$2"
            shift 2
            ;;
        -o|--output)
            OUTPUT_FILE="$2"
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

# Validate test type
if [[ ! "$TEST_TYPE" =~ ^(unit|integration|e2e|all|binary)$ ]]; then
    print_error "Invalid test type: $TEST_TYPE"
    show_usage
    exit 1
fi

print_info "Starting local testing with configuration:"
echo "  Test Type: $TEST_TYPE"
echo "  Verbose: $VERBOSE"
echo "  Build: $BUILD"
if [[ -n "$INPUT_FILE" ]]; then
    echo "  Input File: $INPUT_FILE"
fi
if [[ -n "$OUTPUT_FILE" ]]; then
    echo "  Output File: $OUTPUT_FILE"
fi
echo

# Check prerequisites
print_info "Checking prerequisites..."

# Check if Go is installed
if ! command -v go &> /dev/null; then
    print_error "Go is not installed. Please install Go first."
    exit 1
fi

print_success "Prerequisites check passed"

# Build the application if requested
if [[ "$BUILD" == true ]]; then
    print_info "Building the application..."
    
    # Build Lambda binary
    if ! make build; then
        print_error "Lambda build failed"
        exit 1
    fi
    
    # Build local binary
    if ! make build-local; then
        print_error "Local build failed"
        exit 1
    fi
    
    print_success "Build completed"
fi

# Set verbose flags
VERBOSE_FLAGS=""
if [[ "$VERBOSE" == true ]]; then
    VERBOSE_FLAGS="-v"
fi

# Run tests based on type
case $TEST_TYPE in
    unit)
        print_info "Running unit tests..."
        go test $VERBOSE_FLAGS -short ./...
        ;;
    integration)
        print_info "Running integration tests..."
        go test $VERBOSE_FLAGS -run Integration ./test/integration/...
        ;;
    e2e)
        print_info "Running end-to-end tests..."
        go test $VERBOSE_FLAGS -run EndToEnd ./test/integration/...
        ;;
    all)
        print_info "Running all tests..."
        
        print_info "1. Unit tests..."
        go test $VERBOSE_FLAGS -short ./...
        
        print_info "2. Integration tests..."
        go test $VERBOSE_FLAGS -run Integration ./test/integration/...
        
        print_info "3. End-to-end tests..."
        go test $VERBOSE_FLAGS -run EndToEnd ./test/integration/...
        
        print_info "4. Performance tests..."
        go test $VERBOSE_FLAGS -run Performance ./test/integration/...
        ;;
    binary)
        print_info "Testing local binary execution..."
        
        if [[ ! -f "./scanner" ]]; then
            print_error "Local binary not found. Run with --build or make build-local first."
            exit 1
        fi
        
        if [[ -n "$INPUT_FILE" ]]; then
            if [[ ! -f "$INPUT_FILE" ]]; then
                print_error "Input file not found: $INPUT_FILE"
                exit 1
            fi
            
            print_info "Testing with input file: $INPUT_FILE"
            if [[ -n "$OUTPUT_FILE" ]]; then
                ./scanner < "$INPUT_FILE" > "$OUTPUT_FILE"
                print_success "Results written to: $OUTPUT_FILE"
            else
                ./scanner < "$INPUT_FILE"
            fi
        else
            print_info "Testing with sample input..."
            # Create temporary input file with sample data
            TEMP_INPUT=$(mktemp)
            cat > "$TEMP_INPUT" << 'EOF'
{
  "imageUrl": "123456789012.dkr.ecr.us-east-1.amazonaws.com/test-repo",
  "tag": "latest",
  "scanMode": "basic"
}
EOF
            
            if [[ -n "$OUTPUT_FILE" ]]; then
                ./scanner < "$TEMP_INPUT" > "$OUTPUT_FILE"
                print_success "Results written to: $OUTPUT_FILE"
            else
                ./scanner < "$TEMP_INPUT"
            fi
            
            rm -f "$TEMP_INPUT"
        fi
        ;;
esac

if [[ $? -eq 0 ]]; then
    print_success "All tests completed successfully!"
else
    print_error "Some tests failed"
    exit 1
fi

# Show test coverage if verbose
if [[ "$VERBOSE" == true && "$TEST_TYPE" != "binary" ]]; then
    print_info "Generating test coverage report..."
    go test -coverprofile=coverage.out ./...
    go tool cover -html=coverage.out -o coverage.html
    print_info "Coverage report generated: coverage.html"
fi
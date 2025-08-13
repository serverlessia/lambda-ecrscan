# Requirements Document

## Introduction

This feature implements an AWS Lambda function that performs custom ECR (Elastic Container Registry) image security scanning. The Lambda function will accept image URLs and tags as input, perform its own vulnerability scanning similar to ECR's basic scan functionality with an optional enhanced mode, and return scan results with severity counts. The solution includes proper IAM permissions and deployment via SAM (Serverless Application Model).

## Requirements

### Requirement 1

**User Story:** As a DevOps engineer, I want to trigger custom image vulnerability scans programmatically, so that I can integrate security scanning into my CI/CD pipelines.

#### Acceptance Criteria

1. WHEN the Lambda function is invoked with an image URL and tag THEN the system SHALL perform its own vulnerability scanning similar to ECR basic scan functionality
2. WHEN the Lambda function receives valid input parameters THEN the system SHALL use the AWS SDK for Go to pull image manifests and layers from ECR
3. WHEN the scan is performed THEN the system SHALL analyze the image contents for known vulnerabilities

### Requirement 2

**User Story:** As a security engineer, I want to receive scan results with severity counts, so that I can quickly assess the security posture of container images.

#### Acceptance Criteria

1. WHEN an ECR scan completes THEN the system SHALL return scan results with vulnerability severity counts
2. WHEN scan results are available THEN the system SHALL categorize findings by severity levels (CRITICAL, HIGH, MEDIUM, LOW, INFORMATIONAL)
3. WHEN returning results THEN the system SHALL include total vulnerability count and breakdown by severity

### Requirement 3

**User Story:** As a security engineer, I want the Lambda to support both basic and enhanced scanning modes, so that I can choose the appropriate level of vulnerability detection for my needs.

#### Acceptance Criteria

1. WHEN the Lambda function is invoked THEN the system SHALL support a basic scanning mode by default
2. WHEN enhanced scanning is requested THEN the system SHALL perform more comprehensive vulnerability analysis
3. WHEN scanning mode is specified in input THEN the system SHALL use the requested scanning approach

### Requirement 4

**User Story:** As a cloud architect, I want the Lambda to use minimal IAM permissions, so that the system follows the principle of least privilege.

#### Acceptance Criteria

1. WHEN the Lambda function is deployed THEN the system SHALL have IAM permissions limited to only ECR image retrieval actions
2. WHEN IAM policies are configured THEN the system SHALL include permissions for getting authorization tokens, describing repositories, and pulling image manifests and layers
3. WHEN accessing ECR resources THEN the system SHALL NOT have permissions for actions unrelated to image analysis

### Requirement 5

**User Story:** As a developer, I want to deploy the Lambda using SAM with Go, so that I can leverage Go's performance and AWS best practices.

#### Acceptance Criteria

1. WHEN the project is created THEN the system SHALL use SAM (Serverless Application Model) for infrastructure as code
2. WHEN the Lambda function is configured THEN the system SHALL use the `provided.al2` runtime with a compiled Go binary
3. WHEN the SAM template is defined THEN the system SHALL include proper resource definitions for Lambda function, IAM roles, and build configuration for Go

### Requirement 6

**User Story:** As a QA engineer, I want to test the Lambda function with sample inputs, so that I can verify the functionality works as expected.

#### Acceptance Criteria

1. WHEN the Lambda is deployed THEN the system SHALL be testable with sample image URLs and tags
2. WHEN test inputs are provided THEN the system SHALL process them and return expected response formats
3. WHEN testing is performed THEN the system SHALL demonstrate successful scan initiation and result retrieval

### Requirement 7

**User Story:** As a developer, I want to test the scanning functionality locally using the compiled binary, so that I can validate the logic before deploying to Lambda.

#### Acceptance Criteria

1. WHEN the Go binary is compiled THEN the system SHALL support running locally for testing purposes
2. WHEN local testing is performed THEN the system SHALL accept the same input format as the Lambda function
3. WHEN running locally THEN the system SHALL produce the same output format as when deployed in Lambda

### Requirement 8

**User Story:** As a developer, I want comprehensive unit tests for the scanning logic, so that I can ensure code quality and catch regressions early.

#### Acceptance Criteria

1. WHEN unit tests are written THEN the system SHALL have test coverage for vulnerability scanning logic
2. WHEN unit tests are executed THEN the system SHALL validate ECR client interactions using mocks
3. WHEN unit tests are run THEN the system SHALL verify proper error handling and response formatting
4. WHEN unit tests are implemented THEN the system SHALL include tests for both basic and enhanced scanning modes
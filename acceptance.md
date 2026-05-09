# Acceptance Criteria

## Task 1: Parameter validation utilities

### Acceptance Criteria
- [x] validate_parameter("AWS_ACCOUNT_ID", "123456789012", r"^\d{12}$") returns without error
- [x] validate_parameter("AWS_ACCOUNT_ID", "12345", r"^\d{12}$") raises ValueError with message containing parameter name and pattern
- [x] validate_parameter("ROLE_NAME", "MyRole-123", r"^[\w+=,.@-]{1,64}$") returns without error
- [x] validate_parameter("ROLE_NAME", "", r"^[\w+=,.@-]{1,64}$") raises ValueError for missing parameter
- [x] validate_parameter("ENABLED", "true", r"^true|false$") returns without error
- [x] validate_parameter("ENABLED", "TRUE", r"(?i)^true|false$") returns without error (case insensitive)
- [x] validate_parameter("ENABLED", "yes", r"^true|false$") raises ValueError
- [x] validate_parameter with optional=True allows empty string without error
- [x] validate_parameter with optional=True still validates non-empty values against pattern
- [x] ARN patterns work for KMS keys, SNS topics, and S3 buckets

## Task 2: Cross-account session management

### Acceptance Criteria
- [ ] assume_role("MyRole", "session-name", "123456789012") calls STS assume_role and returns a boto3 Session
- [ ] The returned session uses the temporary credentials from the assume_role response
- [ ] When account_id is not provided, it extracts the account from the current caller identity
- [ ] The function logs the assumed role ARN
- [ ] Role ARN is correctly constructed with the account ID and partition
- [ ] Supports different AWS partitions (aws, aws-us-gov, aws-cn)

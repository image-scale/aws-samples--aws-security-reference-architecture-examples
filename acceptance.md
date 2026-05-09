# Acceptance Criteria

## Task 1: Parameter validation utilities

### Acceptance Criteria
- [ ] validate_parameter("AWS_ACCOUNT_ID", "123456789012", r"^\d{12}$") returns without error
- [ ] validate_parameter("AWS_ACCOUNT_ID", "12345", r"^\d{12}$") raises ValueError with message containing parameter name and pattern
- [ ] validate_parameter("ROLE_NAME", "MyRole-123", r"^[\w+=,.@-]{1,64}$") returns without error
- [ ] validate_parameter("ROLE_NAME", "", r"^[\w+=,.@-]{1,64}$") raises ValueError for missing parameter
- [ ] validate_parameter("ENABLED", "true", r"^true|false$") returns without error
- [ ] validate_parameter("ENABLED", "TRUE", r"(?i)^true|false$") returns without error (case insensitive)
- [ ] validate_parameter("ENABLED", "yes", r"^true|false$") raises ValueError
- [ ] validate_parameter with optional=True allows empty string without error
- [ ] validate_parameter with optional=True still validates non-empty values against pattern
- [ ] ARN patterns work for KMS keys, SNS topics, and S3 buckets

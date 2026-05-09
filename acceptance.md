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
- [x] assume_role("MyRole", "session-name", "123456789012") calls STS assume_role and returns a boto3 Session
- [x] The returned session uses the temporary credentials from the assume_role response
- [x] When account_id is not provided, it extracts the account from the current caller identity
- [x] The function logs the assumed role ARN
- [x] Role ARN is correctly constructed with the account ID and partition
- [x] Supports different AWS partitions (aws, aws-us-gov, aws-cn)

## Task 3: AWS Organizations account enumeration

### Acceptance Criteria
- [ ] get_organization_accounts() returns a list of all active accounts with AccountId and Email
- [ ] Accounts with status other than ACTIVE are excluded from results
- [ ] get_organization_accounts(exclude_accounts=["123..."]) excludes specified account IDs
- [ ] get_account_ids(accounts) extracts just the account IDs from the account list
- [ ] When passed an empty list, get_account_ids calls get_organization_accounts internally
- [ ] Pagination is handled correctly for organizations with many accounts

# Todo

## Plan
Build the AWS SRA library starting with core user-facing functionality. The primary user interactions are through Lambda handlers that configure AWS security services. We'll start with the common utilities that enable cross-account operations, then build individual service configurators. Each task delivers complete, testable functionality with mocked AWS API calls.

## Tasks
- [x] Task 1: Implement parameter validation utilities that verify CloudFormation custom resource parameters against regex patterns, raising clear errors for invalid inputs. Users pass parameters like account IDs (12 digits), role names, boolean strings (true/false), and ARNs that must be validated before service configuration proceeds.

- [x] Task 2: Implement cross-account session management that allows assuming IAM roles in different AWS accounts and returning boto3 sessions for those accounts. Users need to configure resources in member accounts by assuming a configuration role.

- [x] Task 3: Implement AWS Organizations account enumeration that retrieves all active accounts in an organization, with optional exclusion of specific accounts. This enables batch configuration of security services across all member accounts.

- [x] Task 4: Implement region management utilities that determine which AWS regions are enabled for the account, supporting both customer-specified regions and automatic detection of available regions via STS endpoint probing.

- [x] Task 5: Implement service-linked role management that creates AWS service-linked roles if they don't exist. Many AWS security services require service-linked roles before they can be configured.

- [x] Task 6: Implement IAM password policy configuration that sets account-level password policy settings (minimum length, character requirements, expiration, reuse prevention) based on CloudFormation custom resource parameters.

- [x] Task 7: Implement S3 block public access configuration that enables S3 Block Public Access settings at the account level across multiple regions based on CloudFormation parameters.

- [x] Task 8: Implement common prerequisites management that gathers organization data, identifies Control Tower regions, and creates SSM parameters in multiple regions to store configuration information for other SRA solutions.

- [x] Task 9: Implement GuardDuty organization configuration that sets up delegated administrator accounts, enables GuardDuty features (S3 logs, EKS audit, malware protection, runtime monitoring), creates member accounts, and configures publishing destinations.

- [>] Task 10: Implement Macie organization configuration that enables Macie in a delegated admin account, configures member accounts, sets up publishing destinations for findings, and handles disabling Macie when requested.

- [ ] Task 11: Implement SecurityHub organization configuration that enables SecurityHub with delegated administration, configures security standards (CIS, PCI, NIST, Security Best Practices), manages member accounts, and handles SNS-based member account notifications.

- [ ] Task 12: Implement register delegated administrator functionality that registers and deregisters delegated administrator accounts for AWS services within AWS Organizations, enabling centralized security management.

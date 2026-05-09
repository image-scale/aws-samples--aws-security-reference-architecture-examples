# Goal

## Project
aws-security-reference-architecture-examples — a python project.

## Description
A collection of AWS Lambda functions and utilities for configuring AWS security services across multi-account AWS Organizations environments. The library provides automated configuration and management of security services including GuardDuty, Macie, SecurityHub, IAM Password Policy, S3 Block Public Access, CloudTrail, Config, Inspector, and common prerequisites management.

Key capabilities:
- Cross-account role assumption for managing resources across AWS accounts
- AWS Organizations account enumeration and management
- Multi-region service configuration
- CloudFormation custom resource handling with parameter validation
- Service-linked role management
- Delegated administrator account setup for security services

## Scope
- 15+ production source files to implement
- 10+ test files to write
- Reproduce all core functionality for AWS security service configuration

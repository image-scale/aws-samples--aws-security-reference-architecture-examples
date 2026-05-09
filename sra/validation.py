"""Parameter validation utilities for CloudFormation custom resource parameters."""

from __future__ import annotations

import re
from typing import Optional


class ValidationError(ValueError):
    """Raised when a parameter fails validation."""

    pass


def validate_parameter(
    name: str,
    value: Optional[str],
    pattern: str,
    optional: bool = False,
) -> None:
    """Validate a parameter value against a regex pattern.

    Args:
        name: The parameter name (used in error messages).
        value: The parameter value to validate.
        pattern: The regex pattern the value must match.
        optional: If True, empty/None values are allowed. Defaults to False.

    Raises:
        ValidationError: If the value is missing (and not optional) or doesn't match the pattern.
    """
    if value is None or value == "":
        if not optional:
            raise ValidationError(f"'{name}' parameter is missing or empty.")
        return

    if not re.match(pattern, value):
        raise ValidationError(
            f"'{name}' parameter with value of '{value}' does not follow the allowed pattern: {pattern}."
        )


def validate_parameters(params: dict, validations: list[tuple]) -> dict:
    """Validate multiple parameters against their patterns.

    Args:
        params: Dictionary of parameter name/value pairs.
        validations: List of tuples (param_name, pattern) or (param_name, pattern, optional).

    Returns:
        The validated parameters dictionary.

    Raises:
        ValidationError: If any parameter fails validation.
    """
    for validation in validations:
        if len(validation) == 2:
            param_name, pattern = validation
            optional = False
        else:
            param_name, pattern, optional = validation

        validate_parameter(param_name, params.get(param_name), pattern, optional)

    return params


AWS_ACCOUNT_ID_PATTERN = r"^\d{12}$"
ROLE_NAME_PATTERN = r"^[\w+=,.@-]{1,64}$"
BOOLEAN_PATTERN = r"^true|false$"
BOOLEAN_PATTERN_CASE_INSENSITIVE = r"(?i)^true|false$"
REGIONS_PATTERN = r"^$|[a-z0-9-, ]+$"

KMS_KEY_ARN_PATTERN = (
    r"^arn:(aws[a-zA-Z-]*){1}:kms:[a-z0-9-]+:\d{12}:key\/"
    r"[a-f0-9]{8}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{4}-[a-f0-9]{12}$"
)

SNS_TOPIC_ARN_PATTERN = (
    r"^arn:(aws[a-zA-Z-]*){1}:sns:[a-z0-9-]+:\d{12}:"
    r"[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$"
)

S3_BUCKET_ARN_PATTERN = r"^arn:(aws[a-zA-Z-]*){1}:s3:::[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$"

S3_BUCKET_NAME_PATTERN = r"^[0-9a-zA-Z]+([0-9a-zA-Z-]*[0-9a-zA-Z])*$"

FINDING_PUBLISHING_FREQUENCY_PATTERN = r"^FIFTEEN_MINUTES|ONE_HOUR|SIX_HOURS$"

MAX_PASSWORD_AGE_PATTERN = r"^[1-9]$|^[0-9][0-9]$|^[0-9][0-9][0-9]$|^[0-1][0]([0-8][0-9]|[9][0-5])$"

MINIMUM_PASSWORD_LENGTH_PATTERN = r"^[6-9]$|^[0-9][0-9]$|^[0-9][0-2][0-8]$"

PASSWORD_REUSE_PREVENTION_PATTERN = r"^[1-9]$|^1[0-9]$|^2[0-4]$"

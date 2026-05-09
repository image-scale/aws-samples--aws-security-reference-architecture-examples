"""IAM password policy configuration Lambda handler."""

from __future__ import annotations

import logging
from typing import Any, Dict, Optional

import boto3
from botocore.config import Config

from sra.validation import (
    BOOLEAN_PATTERN,
    MAX_PASSWORD_AGE_PATTERN,
    MINIMUM_PASSWORD_LENGTH_PATTERN,
    PASSWORD_REUSE_PREVENTION_PATTERN,
    ValidationError,
    validate_parameter,
)

logger = logging.getLogger("sra")

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})


def parse_bool(value: str) -> bool:
    """Parse a string boolean value.

    Args:
        value: String value ("true" or "false", case insensitive).

    Returns:
        Boolean value.
    """
    return value.lower() == "true"


def validate_password_policy_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Validate password policy parameters.

    Args:
        params: Dictionary of parameter values.

    Returns:
        Validated parameters.

    Raises:
        ValidationError: If any parameter is invalid.
    """
    validate_parameter("MAX_PASSWORD_AGE", params.get("MAX_PASSWORD_AGE"), MAX_PASSWORD_AGE_PATTERN)
    validate_parameter("MINIMUM_PASSWORD_LENGTH", params.get("MINIMUM_PASSWORD_LENGTH"), MINIMUM_PASSWORD_LENGTH_PATTERN)
    validate_parameter("PASSWORD_REUSE_PREVENTION", params.get("PASSWORD_REUSE_PREVENTION"), PASSWORD_REUSE_PREVENTION_PATTERN)
    validate_parameter("ALLOW_USERS_TO_CHANGE_PASSWORD", params.get("ALLOW_USERS_TO_CHANGE_PASSWORD"), BOOLEAN_PATTERN)
    validate_parameter("HARD_EXPIRY", params.get("HARD_EXPIRY"), BOOLEAN_PATTERN)
    validate_parameter("REQUIRE_LOWERCASE_CHARACTERS", params.get("REQUIRE_LOWERCASE_CHARACTERS"), BOOLEAN_PATTERN)
    validate_parameter("REQUIRE_NUMBERS", params.get("REQUIRE_NUMBERS"), BOOLEAN_PATTERN)
    validate_parameter("REQUIRE_SYMBOLS", params.get("REQUIRE_SYMBOLS"), BOOLEAN_PATTERN)
    validate_parameter("REQUIRE_UPPERCASE_CHARACTERS", params.get("REQUIRE_UPPERCASE_CHARACTERS"), BOOLEAN_PATTERN)

    return params


def update_password_policy(
    params: Dict[str, Any],
    session: Optional[boto3.Session] = None,
) -> None:
    """Update the account password policy.

    Args:
        params: Dictionary containing password policy settings.
        session: Existing boto3 session to use. If not provided, creates a new one.
    """
    if not session:
        session = boto3.Session()

    iam_client = session.client("iam", config=BOTO3_CONFIG)

    iam_client.update_account_password_policy(
        AllowUsersToChangePassword=parse_bool(params.get("ALLOW_USERS_TO_CHANGE_PASSWORD", "true")),
        HardExpiry=parse_bool(params.get("HARD_EXPIRY", "false")),
        MaxPasswordAge=int(params.get("MAX_PASSWORD_AGE", 90)),
        MinimumPasswordLength=int(params.get("MINIMUM_PASSWORD_LENGTH", 14)),
        PasswordReusePrevention=int(params.get("PASSWORD_REUSE_PREVENTION", 24)),
        RequireLowercaseCharacters=parse_bool(params.get("REQUIRE_LOWERCASE_CHARACTERS", "true")),
        RequireNumbers=parse_bool(params.get("REQUIRE_NUMBERS", "true")),
        RequireSymbols=parse_bool(params.get("REQUIRE_SYMBOLS", "true")),
        RequireUppercaseCharacters=parse_bool(params.get("REQUIRE_UPPERCASE_CHARACTERS", "true")),
    )

    logger.info("Password policy updated successfully")


def get_password_policy(
    session: Optional[boto3.Session] = None,
) -> Dict[str, Any]:
    """Get the current account password policy.

    Args:
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        Dictionary containing current password policy settings.
    """
    if not session:
        session = boto3.Session()

    iam_client = session.client("iam", config=BOTO3_CONFIG)

    try:
        response = iam_client.get_account_password_policy()
        return response["PasswordPolicy"]
    except iam_client.exceptions.NoSuchEntityException:
        return {}


def process_cloudformation_event(event: Dict[str, Any]) -> str:
    """Process a CloudFormation custom resource event.

    Args:
        event: CloudFormation event data.

    Returns:
        Physical resource ID.
    """
    request_type = event.get("RequestType", "Create")
    params = event.get("ResourceProperties", {})

    if request_type in ["Create", "Update"]:
        validated_params = validate_password_policy_params(params)
        update_password_policy(validated_params)

    return generate_physical_resource_id(params)


def generate_physical_resource_id(params: Dict[str, Any]) -> str:
    """Generate a physical resource ID for CloudFormation.

    Args:
        params: Password policy parameters.

    Returns:
        Physical resource ID string.
    """
    return (
        f"sra-password-policy-{params.get('ALLOW_USERS_TO_CHANGE_PASSWORD', 'true')}-"
        f"{params.get('HARD_EXPIRY', 'false')}-{params.get('MAX_PASSWORD_AGE', '90')}-"
        f"{params.get('MINIMUM_PASSWORD_LENGTH', '14')}-{params.get('PASSWORD_REUSE_PREVENTION', '24')}"
    )


def lambda_handler(event: Dict[str, Any], context: Any) -> None:
    """Lambda handler for password policy configuration.

    Args:
        event: Lambda event data.
        context: Lambda context.

    Raises:
        ValueError: If an unexpected error occurs.
    """
    logger.info("Password policy Lambda handler started")

    try:
        process_cloudformation_event(event)
    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        raise ValueError(str(e)) from e
    except Exception as e:
        logger.exception("Unexpected error")
        raise ValueError(f"Unexpected error: {e}") from e

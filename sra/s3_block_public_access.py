"""S3 Block Public Access configuration Lambda handler."""

from __future__ import annotations

import logging
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config

from sra.validation import BOOLEAN_PATTERN, ValidationError, validate_parameter

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


def validate_s3_bpa_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Validate S3 Block Public Access parameters.

    Args:
        params: Dictionary of parameter values.

    Returns:
        Validated parameters.

    Raises:
        ValidationError: If any parameter is invalid.
    """
    validate_parameter("BLOCK_PUBLIC_ACLS", params.get("BLOCK_PUBLIC_ACLS", "true"), BOOLEAN_PATTERN)
    validate_parameter("IGNORE_PUBLIC_ACLS", params.get("IGNORE_PUBLIC_ACLS", "true"), BOOLEAN_PATTERN)
    validate_parameter("BLOCK_PUBLIC_POLICY", params.get("BLOCK_PUBLIC_POLICY", "true"), BOOLEAN_PATTERN)
    validate_parameter("RESTRICT_PUBLIC_BUCKETS", params.get("RESTRICT_PUBLIC_BUCKETS", "true"), BOOLEAN_PATTERN)

    return params


def set_block_public_access(
    block_public_acls: bool = True,
    ignore_public_acls: bool = True,
    block_public_policy: bool = True,
    restrict_public_buckets: bool = True,
    session: Optional[boto3.Session] = None,
) -> None:
    """Set S3 Block Public Access settings at the account level.

    Args:
        block_public_acls: Block new public ACLs and uploading public objects.
        ignore_public_acls: Ignore all public ACLs on buckets and objects.
        block_public_policy: Block new public bucket policies.
        restrict_public_buckets: Restrict access to buckets with public policies.
        session: Existing boto3 session to use. If not provided, creates a new one.
    """
    if not session:
        session = boto3.Session()

    s3_control_client = session.client("s3control", config=BOTO3_CONFIG)
    sts_client = session.client("sts", config=BOTO3_CONFIG)
    account_id = sts_client.get_caller_identity()["Account"]

    s3_control_client.put_public_access_block(
        AccountId=account_id,
        PublicAccessBlockConfiguration={
            "BlockPublicAcls": block_public_acls,
            "IgnorePublicAcls": ignore_public_acls,
            "BlockPublicPolicy": block_public_policy,
            "RestrictPublicBuckets": restrict_public_buckets,
        },
    )

    logger.info(f"S3 Block Public Access configured for account {account_id}")


def get_block_public_access(
    session: Optional[boto3.Session] = None,
) -> Dict[str, bool]:
    """Get current S3 Block Public Access settings.

    Args:
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        Dictionary with current BPA settings.
    """
    if not session:
        session = boto3.Session()

    s3_control_client = session.client("s3control", config=BOTO3_CONFIG)
    sts_client = session.client("sts", config=BOTO3_CONFIG)
    account_id = sts_client.get_caller_identity()["Account"]

    try:
        response = s3_control_client.get_public_access_block(AccountId=account_id)
        return response["PublicAccessBlockConfiguration"]
    except s3_control_client.exceptions.NoSuchPublicAccessBlockConfiguration:
        return {}


def configure_bpa_for_regions(
    params: Dict[str, Any],
    regions: List[str],
    session: Optional[boto3.Session] = None,
) -> None:
    """Configure S3 Block Public Access across multiple regions.

    Note: S3 control operations are global, but this function accepts regions
    for consistency with other SRA modules.

    Args:
        params: Dictionary containing BPA settings.
        regions: List of regions (used for logging, BPA is account-level).
        session: Existing boto3 session to use. If not provided, creates a new one.
    """
    block_public_acls = parse_bool(params.get("BLOCK_PUBLIC_ACLS", "true"))
    ignore_public_acls = parse_bool(params.get("IGNORE_PUBLIC_ACLS", "true"))
    block_public_policy = parse_bool(params.get("BLOCK_PUBLIC_POLICY", "true"))
    restrict_public_buckets = parse_bool(params.get("RESTRICT_PUBLIC_BUCKETS", "true"))

    set_block_public_access(
        block_public_acls=block_public_acls,
        ignore_public_acls=ignore_public_acls,
        block_public_policy=block_public_policy,
        restrict_public_buckets=restrict_public_buckets,
        session=session,
    )

    logger.info(f"S3 Block Public Access configured (regions: {regions})")


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
        validated_params = validate_s3_bpa_params(params)
        regions = params.get("ENABLED_REGIONS", "us-east-1").split(",")
        configure_bpa_for_regions(validated_params, regions)

    return "sra-s3-block-public-access"


def lambda_handler(event: Dict[str, Any], context: Any) -> None:
    """Lambda handler for S3 Block Public Access configuration.

    Args:
        event: Lambda event data.
        context: Lambda context.

    Raises:
        ValueError: If an unexpected error occurs.
    """
    logger.info("S3 Block Public Access Lambda handler started")

    try:
        process_cloudformation_event(event)
    except ValidationError as e:
        logger.error(f"Validation error: {e}")
        raise ValueError(str(e)) from e
    except Exception as e:
        logger.exception("Unexpected error")
        raise ValueError(f"Unexpected error: {e}") from e

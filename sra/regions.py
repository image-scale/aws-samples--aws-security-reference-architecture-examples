"""Region management utilities for AWS SRA."""

from __future__ import annotations

import logging
from typing import List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

logger = logging.getLogger("sra")

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

DEFAULT_REGIONS = [
    "us-east-1",
    "us-east-2",
    "us-west-1",
    "us-west-2",
    "ap-south-1",
    "ap-northeast-1",
    "ap-northeast-2",
    "ap-northeast-3",
    "ap-southeast-1",
    "ap-southeast-2",
    "ca-central-1",
    "eu-central-1",
    "eu-west-1",
    "eu-west-2",
    "eu-west-3",
    "eu-north-1",
    "sa-east-1",
]


def parse_region_list(regions_string: str) -> List[str]:
    """Parse a comma-separated region string into a list.

    Args:
        regions_string: Comma-separated string of region names.

    Returns:
        List of region names with whitespace stripped.
    """
    if not regions_string or not regions_string.strip():
        return []
    return [r.strip() for r in regions_string.split(",") if r.strip()]


def get_enabled_regions(
    customer_regions: Optional[str] = None,
    session: Optional[boto3.Session] = None,
) -> List[str]:
    """Get list of enabled AWS regions.

    If customer_regions is provided, parses and validates those regions.
    Otherwise, checks DEFAULT_REGIONS for enabled status.

    Args:
        customer_regions: Optional comma-separated string of regions to check.
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        List of enabled region names.
    """
    if not session:
        session = boto3.Session()

    if customer_regions and customer_regions.strip():
        region_list = parse_region_list(customer_regions)
    else:
        region_list = DEFAULT_REGIONS.copy()

    enabled_regions = []
    disabled_regions = []
    invalid_regions = []

    for region in region_list:
        try:
            sts_client = session.client(
                "sts",
                endpoint_url=f"https://sts.{region}.amazonaws.com",
                region_name=region,
                config=BOTO3_CONFIG,
            )
            sts_client.get_caller_identity()
            enabled_regions.append(region)
        except ClientError as error:
            if error.response["Error"]["Code"] == "InvalidClientTokenId":
                disabled_regions.append(region)
                logger.info(f"Region {region} is disabled (InvalidClientTokenId)")
            else:
                logger.error(f"Error checking region {region}: {error}")
        except Exception as error:
            if "Could not connect to the endpoint URL" in str(error):
                invalid_regions.append(region)
                logger.error(f"Region '{region}' is not valid")
            else:
                logger.error(f"Error checking region {region}: {error}")

    if disabled_regions:
        logger.info(f"Disabled regions: {disabled_regions}")
    if invalid_regions:
        logger.info(f"Invalid regions: {invalid_regions}")

    return enabled_regions


def get_available_regions_from_account(
    session: Optional[boto3.Session] = None,
) -> List[str]:
    """Get available regions from AWS Account API.

    Uses the account:ListRegions API to get all enabled regions.

    Args:
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        List of enabled region names.
    """
    if not session:
        session = boto3.Session()

    account_client = session.client("account", config=BOTO3_CONFIG)
    response = account_client.list_regions(
        RegionOptStatusContains=["ENABLED", "ENABLED_BY_DEFAULT"]
    )

    return [region["RegionName"] for region in response["Regions"]]


def filter_regions_by_availability(
    regions: List[str],
    session: Optional[boto3.Session] = None,
) -> List[str]:
    """Filter a list of regions to only those that are enabled.

    Args:
        regions: List of region names to check.
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        Filtered list containing only enabled regions.
    """
    if not session:
        session = boto3.Session()

    enabled = []
    for region in regions:
        try:
            sts_client = session.client(
                "sts",
                endpoint_url=f"https://sts.{region}.amazonaws.com",
                region_name=region,
                config=BOTO3_CONFIG,
            )
            sts_client.get_caller_identity()
            enabled.append(region)
        except Exception:
            pass

    return enabled

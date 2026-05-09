"""Cross-account session management for AWS STS role assumption."""

from __future__ import annotations

import logging
import os
from typing import Optional

import boto3
from botocore.config import Config

logger = logging.getLogger("sra")

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})


def assume_role(
    role_name: str,
    session_name: str,
    account_id: Optional[str] = None,
    session: Optional[boto3.Session] = None,
) -> boto3.Session:
    """Assume an IAM role in the specified account and return a boto3 Session.

    Args:
        role_name: Name of the IAM role to assume (not the full ARN).
        session_name: Identifier for the assumed role session.
        account_id: Target AWS account ID. If not provided, uses the current account.
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        boto3.Session configured with the assumed role's temporary credentials.
    """
    os.environ["AWS_STS_REGIONAL_ENDPOINTS"] = "regional"

    if not session:
        session = boto3.Session()

    sts_client = session.client("sts", config=BOTO3_CONFIG)
    caller_identity = sts_client.get_caller_identity()
    caller_arn = caller_identity["Arn"]
    logger.info(f"Current identity: {caller_arn}")

    if not account_id:
        account_id = caller_arn.split(":")[4]

    partition = caller_arn.split(":")[1]
    role_arn = f"arn:{partition}:iam::{account_id}:role/{role_name}"

    response = sts_client.assume_role(RoleArn=role_arn, RoleSessionName=session_name)
    assumed_role_arn = response["AssumedRoleUser"]["Arn"]
    logger.info(f"Assumed role: {assumed_role_arn}")

    return boto3.Session(
        aws_access_key_id=response["Credentials"]["AccessKeyId"],
        aws_secret_access_key=response["Credentials"]["SecretAccessKey"],
        aws_session_token=response["Credentials"]["SessionToken"],
    )


def get_current_account_id(session: Optional[boto3.Session] = None) -> str:
    """Get the current AWS account ID.

    Args:
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        The AWS account ID of the current caller.
    """
    if not session:
        session = boto3.Session()

    sts_client = session.client("sts", config=BOTO3_CONFIG)
    return sts_client.get_caller_identity()["Account"]


def get_current_partition(session: Optional[boto3.Session] = None) -> str:
    """Get the current AWS partition.

    Args:
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        The AWS partition (aws, aws-us-gov, aws-cn).
    """
    if not session:
        session = boto3.Session()

    sts_client = session.client("sts", config=BOTO3_CONFIG)
    caller_arn = sts_client.get_caller_identity()["Arn"]
    return caller_arn.split(":")[1]

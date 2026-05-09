"""IAM service-linked role management utilities."""

from __future__ import annotations

import logging
from typing import Optional

import boto3
from botocore.config import Config

logger = logging.getLogger("sra")

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})


def create_service_linked_role(
    role_name: str,
    service_principal: str,
    description: str = "",
    session: Optional[boto3.Session] = None,
) -> bool:
    """Create a service-linked role if it doesn't already exist.

    Args:
        role_name: Name of the service-linked role.
        service_principal: AWS service principal (e.g., guardduty.amazonaws.com).
        description: Optional description for the role.
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        True if the role was created, False if it already existed.
    """
    if not session:
        session = boto3.Session()

    iam_client = session.client("iam", config=BOTO3_CONFIG)

    try:
        iam_client.get_role(RoleName=role_name)
        logger.info(f"Service-linked role {role_name} already exists")
        return False
    except iam_client.exceptions.NoSuchEntityException:
        logger.info(f"Creating service-linked role {role_name}")
        iam_client.create_service_linked_role(
            AWSServiceName=service_principal,
            Description=description,
        )
        return True


def delete_service_linked_role(
    role_name: str,
    session: Optional[boto3.Session] = None,
) -> Optional[str]:
    """Delete a service-linked role.

    Args:
        role_name: Name of the service-linked role to delete.
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        Deletion task ID if deletion started, None if role doesn't exist.
    """
    if not session:
        session = boto3.Session()

    iam_client = session.client("iam", config=BOTO3_CONFIG)

    try:
        response = iam_client.delete_service_linked_role(RoleName=role_name)
        logger.info(f"Started deletion of service-linked role {role_name}")
        return response["DeletionTaskId"]
    except iam_client.exceptions.NoSuchEntityException:
        logger.info(f"Service-linked role {role_name} does not exist")
        return None


def service_linked_role_exists(
    role_name: str,
    session: Optional[boto3.Session] = None,
) -> bool:
    """Check if a service-linked role exists.

    Args:
        role_name: Name of the service-linked role.
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        True if the role exists, False otherwise.
    """
    if not session:
        session = boto3.Session()

    iam_client = session.client("iam", config=BOTO3_CONFIG)

    try:
        iam_client.get_role(RoleName=role_name)
        return True
    except iam_client.exceptions.NoSuchEntityException:
        return False

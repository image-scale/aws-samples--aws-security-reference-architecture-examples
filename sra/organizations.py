"""AWS Organizations account enumeration utilities."""

from __future__ import annotations

import logging
from time import sleep
from typing import List, Optional

import boto3
from botocore.config import Config

logger = logging.getLogger("sra")

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})
ORG_PAGE_SIZE = 20
ORG_THROTTLE_PERIOD = 0.2


def get_organization_accounts(
    exclude_accounts: Optional[List[str]] = None,
    session: Optional[boto3.Session] = None,
) -> List[dict]:
    """Get all active accounts in the AWS Organization.

    Args:
        exclude_accounts: List of account IDs to exclude from results.
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        List of account dictionaries with AccountId and Email keys.
    """
    if exclude_accounts is None:
        exclude_accounts = []

    if not session:
        session = boto3.Session()

    org_client = session.client("organizations", config=BOTO3_CONFIG)
    accounts = []

    paginator = org_client.get_paginator("list_accounts")
    for page in paginator.paginate(PaginationConfig={"PageSize": ORG_PAGE_SIZE}):
        for account in page["Accounts"]:
            if account["Status"] == "ACTIVE" and account["Id"] not in exclude_accounts:
                accounts.append({
                    "AccountId": account["Id"],
                    "Email": account["Email"],
                })
        sleep(ORG_THROTTLE_PERIOD)

    return accounts


def get_account_ids(
    accounts: Optional[List[dict]] = None,
    exclude_accounts: Optional[List[str]] = None,
    session: Optional[boto3.Session] = None,
) -> List[str]:
    """Extract account IDs from an account list.

    If accounts is empty or None, fetches all organization accounts first.

    Args:
        accounts: List of account dictionaries with AccountId key.
        exclude_accounts: List of account IDs to exclude (used when fetching accounts).
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        List of account ID strings.
    """
    if not accounts:
        accounts = get_organization_accounts(exclude_accounts, session)

    return [account["AccountId"] for account in accounts]


def get_management_account_id(session: Optional[boto3.Session] = None) -> str:
    """Get the management account ID for the organization.

    Args:
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        The management account ID.
    """
    if not session:
        session = boto3.Session()

    org_client = session.client("organizations", config=BOTO3_CONFIG)
    response = org_client.describe_organization()
    return response["Organization"]["MasterAccountId"]


def get_organization_id(session: Optional[boto3.Session] = None) -> str:
    """Get the organization ID.

    Args:
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        The organization ID.
    """
    if not session:
        session = boto3.Session()

    org_client = session.client("organizations", config=BOTO3_CONFIG)
    response = org_client.describe_organization()
    return response["Organization"]["Id"]


def get_root_organizational_unit_id(session: Optional[boto3.Session] = None) -> str:
    """Get the root organizational unit ID.

    Args:
        session: Existing boto3 session to use. If not provided, creates a new one.

    Returns:
        The root OU ID.
    """
    if not session:
        session = boto3.Session()

    org_client = session.client("organizations", config=BOTO3_CONFIG)
    response = org_client.list_roots()
    return response["Roots"][0]["Id"]

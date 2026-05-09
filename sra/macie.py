"""Macie organization configuration for AWS SRA.

Configures Macie with delegated administrator, member accounts, and export settings.
"""

import logging
from time import sleep
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from sra.iam import create_service_linked_role
from sra.organizations import get_organization_accounts
from sra.sessions import assume_role
from sra.validation import ValidationError, validate_parameter

LOGGER = logging.getLogger(__name__)

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

MACIE_SERVICE_PRINCIPAL = "macie.amazonaws.com"


def parse_bool(value: str) -> bool:
    """Parse boolean string value."""
    return value.lower() == "true"


def validate_macie_params(params: Dict[str, str]) -> Dict[str, str]:
    """Validate Macie configuration parameters.

    Args:
        params: Parameters from CloudFormation event

    Returns:
        Validated parameters
    """
    validate_parameter(
        "DELEGATED_ADMIN_ACCOUNT_ID",
        params.get("DELEGATED_ADMIN_ACCOUNT_ID", ""),
        r"^\d{12}$",
    )
    validate_parameter(
        "CONFIGURATION_ROLE_NAME",
        params.get("CONFIGURATION_ROLE_NAME", ""),
        r"^[\w+=,.@-]{1,64}$",
    )
    validate_parameter(
        "FINDING_PUBLISHING_FREQUENCY",
        params.get("FINDING_PUBLISHING_FREQUENCY", "FIFTEEN_MINUTES"),
        r"^FIFTEEN_MINUTES|ONE_HOUR|SIX_HOURS$",
    )
    validate_parameter(
        "DISABLE_MACIE",
        params.get("DISABLE_MACIE", "false"),
        r"(?i)^true|false$",
    )

    return params


def enable_organization_admin_account(
    admin_account_id: str,
    regions: List[str],
    session: Optional[boto3.Session] = None,
) -> None:
    """Enable Macie delegated admin account in specified regions.

    Args:
        admin_account_id: Account ID to designate as delegated admin
        regions: List of AWS regions
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    for region in regions:
        macie_client = session.client("macie2", region_name=region, config=BOTO3_CONFIG)

        response = macie_client.list_organization_admin_accounts()
        existing_admins = [a["accountId"] for a in response.get("adminAccounts", [])]

        if admin_account_id not in existing_admins:
            try:
                macie_client.enable_organization_admin_account(adminAccountId=admin_account_id)
                LOGGER.info(f"Enabled Macie admin account {admin_account_id} in {region}")
            except ClientError as e:
                if e.response["Error"]["Code"] != "ValidationException":
                    raise
                sleep(10)
                macie_client.enable_organization_admin_account(adminAccountId=admin_account_id)
        else:
            LOGGER.info(f"Macie admin account {admin_account_id} already enabled in {region}")


def disable_organization_admin_account(
    regions: List[str],
    session: Optional[boto3.Session] = None,
) -> None:
    """Disable Macie delegated admin account in specified regions.

    Args:
        regions: List of AWS regions
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    for region in regions:
        macie_client = session.client("macie2", region_name=region, config=BOTO3_CONFIG)

        response = macie_client.list_organization_admin_accounts()

        for admin in response.get("adminAccounts", []):
            if admin.get("status") == "ENABLED":
                macie_client.disable_organization_admin_account(
                    adminAccountId=admin["accountId"]
                )
                LOGGER.info(f"Disabled Macie admin account in {region}")


def enable_macie(
    regions: List[str],
    finding_publishing_frequency: str = "FIFTEEN_MINUTES",
    session: Optional[boto3.Session] = None,
) -> None:
    """Enable Macie in the specified regions.

    Args:
        regions: List of AWS regions
        finding_publishing_frequency: Finding publishing frequency
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    for region in regions:
        macie_client = session.client("macie2", region_name=region, config=BOTO3_CONFIG)

        try:
            macie_client.enable_macie(
                findingPublishingFrequency=finding_publishing_frequency,
                status="ENABLED",
            )
            LOGGER.info(f"Enabled Macie in {region}")
        except macie_client.exceptions.ConflictException:
            LOGGER.info(f"Macie already enabled in {region}")


def disable_macie(
    regions: List[str],
    disassociate_members: bool = False,
    session: Optional[boto3.Session] = None,
) -> None:
    """Disable Macie in the specified regions.

    Args:
        regions: List of AWS regions
        disassociate_members: Whether to disassociate members first
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    for region in regions:
        macie_client = session.client("macie2", region_name=region, config=BOTO3_CONFIG)

        if disassociate_members:
            try:
                paginator = macie_client.get_paginator("list_members")

                for page in paginator.paginate(onlyAssociated="false"):
                    for member in page.get("members", []):
                        account_id = member["accountId"]
                        macie_client.disassociate_member(id=account_id)
                        macie_client.delete_member(id=account_id)
                        LOGGER.info(f"Removed Macie member {account_id} in {region}")
            except ClientError as e:
                LOGGER.warning(f"Error removing members in {region}: {e}")

        try:
            macie_client.disable_macie()
            LOGGER.info(f"Disabled Macie in {region}")
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                LOGGER.debug(f"Macie not enabled in {region}")
            else:
                raise


def create_members(
    macie_client,
    accounts: List[Dict[str, str]],
) -> None:
    """Create Macie member accounts.

    Args:
        macie_client: Macie2 client
        accounts: List of account dictionaries with AccountId and Email
    """
    if not accounts:
        return

    for account in accounts:
        try:
            macie_client.create_member(
                account={
                    "accountId": account["AccountId"],
                    "email": account["Email"],
                }
            )
            sleep(1)
        except ClientError as e:
            LOGGER.info(f"Error creating member {account['AccountId']}: {e}")
            sleep(10)
            try:
                macie_client.create_member(
                    account={
                        "accountId": account["AccountId"],
                        "email": account["Email"],
                    }
                )
            except ClientError:
                LOGGER.warning(f"Failed to create member {account['AccountId']}")

    LOGGER.info(f"Created {len(accounts)} Macie member accounts")


def configure_export_destination(
    macie_client,
    bucket_name: str,
    kms_key_arn: str,
) -> None:
    """Configure Macie classification export destination.

    Args:
        macie_client: Macie2 client
        bucket_name: S3 bucket name for export
        kms_key_arn: KMS key ARN for encryption
    """
    macie_client.put_classification_export_configuration(
        configuration={
            "s3Destination": {
                "bucketName": bucket_name,
                "kmsKeyArn": kms_key_arn,
            }
        }
    )
    LOGGER.info(f"Configured export destination to {bucket_name}")


def configure_macie(
    session: boto3.Session,
    delegated_account_id: str,
    regions: List[str],
    bucket_name: str,
    kms_key_arn: str,
    finding_publishing_frequency: str,
) -> None:
    """Configure Macie in all regions.

    Args:
        session: boto3 session for delegated admin account
        delegated_account_id: Delegated admin account ID
        regions: List of AWS regions
        bucket_name: S3 bucket name for export
        kms_key_arn: KMS key ARN for encryption
        finding_publishing_frequency: Finding publishing frequency
    """
    accounts = get_organization_accounts(exclude_accounts=[delegated_account_id])

    sleep(30)

    for region in regions:
        LOGGER.info(f"Configuring Macie in {region}")

        macie_client = session.client("macie2", region_name=region, config=BOTO3_CONFIG)

        macie_client.update_macie_session(
            findingPublishingFrequency=finding_publishing_frequency,
            status="ENABLED",
        )

        if bucket_name and kms_key_arn:
            configure_export_destination(macie_client, bucket_name, kms_key_arn)

        create_members(macie_client, accounts)

        macie_client.update_organization_configuration(autoEnable=True)

        LOGGER.info(f"Configured Macie in {region}")


def process_create_update(
    params: Dict[str, str],
    regions: List[str],
) -> None:
    """Process Macie create/update event.

    Args:
        params: Event parameters
        regions: List of AWS regions
    """
    delegated_account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]
    configuration_role = params["CONFIGURATION_ROLE_NAME"]

    create_service_linked_role(
        "AWSServiceRoleForAmazonMacie",
        MACIE_SERVICE_PRINCIPAL,
        "Service-linked role for Amazon Macie",
    )

    enable_organization_admin_account(delegated_account_id, regions)

    session = assume_role(configuration_role, "ConfigureMacie", delegated_account_id)

    finding_frequency = params.get("FINDING_PUBLISHING_FREQUENCY", "FIFTEEN_MINUTES")

    enable_macie(regions, finding_frequency)

    configure_macie(
        session,
        delegated_account_id,
        regions,
        params.get("PUBLISHING_DESTINATION_BUCKET_NAME", ""),
        params.get("KMS_KEY_ARN", ""),
        finding_frequency,
    )


def process_delete(
    params: Dict[str, str],
    regions: List[str],
) -> None:
    """Process Macie delete event.

    Args:
        params: Event parameters
        regions: List of AWS regions
    """
    delegated_account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]
    configuration_role = params["CONFIGURATION_ROLE_NAME"]

    session = assume_role(configuration_role, "DeleteMacie", delegated_account_id)

    disable_macie(regions, disassociate_members=True, session=session)
    disable_organization_admin_account(regions)


def process_cloudformation_event(event: Dict[str, Any]) -> str:
    """Process CloudFormation custom resource event.

    Args:
        event: CloudFormation event

    Returns:
        Physical resource ID
    """
    request_type = event.get("RequestType", "")
    properties = event.get("ResourceProperties", {})

    params = validate_macie_params(properties)

    enabled_regions_str = properties.get("ENABLED_REGIONS", "")
    if enabled_regions_str:
        regions = [r.strip() for r in enabled_regions_str.split(",") if r.strip()]
    else:
        regions = ["us-east-1"]

    delegated_account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]

    if request_type in ("Create", "Update"):
        disable_macie_flag = parse_bool(params.get("DISABLE_MACIE", "false"))

        if disable_macie_flag and request_type == "Update":
            process_delete(params, regions)
        else:
            process_create_update(params, regions)
    elif request_type == "Delete":
        process_delete(params, regions)

    return f"sra-macie-{delegated_account_id}"


def lambda_handler(event: Dict[str, Any], context: Any) -> str:
    """Lambda function handler.

    Args:
        event: CloudFormation custom resource event
        context: Lambda context

    Returns:
        Physical resource ID

    Raises:
        ValueError: On validation or processing errors
    """
    try:
        return process_cloudformation_event(event)
    except ValidationError as e:
        raise ValueError(str(e)) from e
    except Exception as e:
        LOGGER.exception("Unexpected error in lambda_handler")
        raise ValueError(f"Error processing event: {e}") from e

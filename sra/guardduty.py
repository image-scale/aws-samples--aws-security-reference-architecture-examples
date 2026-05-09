"""GuardDuty organization configuration for AWS SRA.

Configures GuardDuty with delegated administrator, member accounts, and features.
"""

import logging
import math
from time import sleep
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from sra.iam import create_service_linked_role
from sra.organizations import get_account_ids, get_organization_accounts
from sra.sessions import assume_role
from sra.validation import ValidationError, validate_parameter

LOGGER = logging.getLogger(__name__)

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

GUARDDUTY_SERVICE_PRINCIPAL = "guardduty.amazonaws.com"
MALWARE_PROTECTION_SERVICE_PRINCIPAL = "malware-protection.guardduty.amazonaws.com"

GUARDDUTY_FEATURES = [
    "S3_DATA_EVENTS",
    "EKS_AUDIT_LOGS",
    "EBS_MALWARE_PROTECTION",
    "RDS_LOGIN_EVENTS",
    "LAMBDA_NETWORK_LOGS",
    "RUNTIME_MONITORING",
]


def parse_bool(value: str) -> bool:
    """Parse boolean string value."""
    return value.lower() == "true"


def validate_guardduty_params(params: Dict[str, str]) -> Dict[str, str]:
    """Validate GuardDuty configuration parameters.

    Args:
        params: Parameters from CloudFormation event

    Returns:
        Validated parameters
    """
    true_false_pattern = r"(?i)^true|false$"

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
        "AUTO_ENABLE_S3_LOGS",
        params.get("AUTO_ENABLE_S3_LOGS", "false"),
        true_false_pattern,
    )
    validate_parameter(
        "ENABLE_EKS_AUDIT_LOGS",
        params.get("ENABLE_EKS_AUDIT_LOGS", "false"),
        true_false_pattern,
    )
    validate_parameter(
        "AUTO_ENABLE_MALWARE_PROTECTION",
        params.get("AUTO_ENABLE_MALWARE_PROTECTION", "false"),
        true_false_pattern,
    )
    validate_parameter(
        "ENABLE_RUNTIME_MONITORING",
        params.get("ENABLE_RUNTIME_MONITORING", "false"),
        true_false_pattern,
    )
    validate_parameter(
        "FINDING_PUBLISHING_FREQUENCY",
        params.get("FINDING_PUBLISHING_FREQUENCY", "FIFTEEN_MINUTES"),
        r"^FIFTEEN_MINUTES|ONE_HOUR|SIX_HOURS$",
    )

    return params


def enable_organization_admin_account(
    admin_account_id: str,
    regions: List[str],
    session: Optional[boto3.Session] = None,
) -> None:
    """Enable GuardDuty delegated admin account in specified regions.

    Args:
        admin_account_id: Account ID to designate as delegated admin
        regions: List of AWS regions
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    for region in regions:
        guardduty_client = session.client("guardduty", region_name=region, config=BOTO3_CONFIG)

        response = guardduty_client.list_organization_admin_accounts()
        existing_admins = [a["AdminAccountId"] for a in response.get("AdminAccounts", [])]

        if admin_account_id not in existing_admins:
            try:
                guardduty_client.enable_organization_admin_account(AdminAccountId=admin_account_id)
                LOGGER.info(f"Enabled GuardDuty admin account {admin_account_id} in {region}")
            except ClientError as e:
                if e.response["Error"]["Code"] != "InvalidInputException":
                    raise
                sleep(10)
                guardduty_client.enable_organization_admin_account(AdminAccountId=admin_account_id)
        else:
            LOGGER.info(f"GuardDuty admin account {admin_account_id} already enabled in {region}")


def disable_organization_admin_account(
    regions: List[str],
    session: Optional[boto3.Session] = None,
) -> None:
    """Disable GuardDuty delegated admin account in specified regions.

    Args:
        regions: List of AWS regions
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    for region in regions:
        guardduty_client = session.client("guardduty", region_name=region, config=BOTO3_CONFIG)

        response = guardduty_client.list_organization_admin_accounts()

        for admin in response.get("AdminAccounts", []):
            if admin.get("AdminStatus") == "ENABLED":
                guardduty_client.disable_organization_admin_account(
                    AdminAccountId=admin["AdminAccountId"]
                )
                LOGGER.info(f"Disabled GuardDuty admin account in {region}")


def get_detector_id(
    guardduty_client,
    create_if_missing: bool = False,
) -> Optional[str]:
    """Get the GuardDuty detector ID.

    Args:
        guardduty_client: GuardDuty client
        create_if_missing: Create detector if it doesn't exist

    Returns:
        Detector ID or None
    """
    response = guardduty_client.list_detectors()

    if response.get("DetectorIds"):
        return response["DetectorIds"][0]

    if create_if_missing:
        response = guardduty_client.create_detector(Enable=True)
        return response["DetectorId"]

    return None


def check_for_detectors(
    session: boto3.Session,
    regions: List[str],
) -> bool:
    """Check if GuardDuty detectors exist in all regions.

    Args:
        session: boto3 session
        regions: List of AWS regions

    Returns:
        True if detectors exist in all regions
    """
    for region in regions:
        try:
            guardduty_client = session.client("guardduty", region_name=region, config=BOTO3_CONFIG)
            response = guardduty_client.list_detectors()
            if not response.get("DetectorIds"):
                return False
        except ClientError as e:
            if e.response["Error"]["Code"] == "AccessDeniedException":
                return False
            raise

    return True


def build_features_config(gd_features: Dict[str, bool]) -> List[Dict[str, Any]]:
    """Build GuardDuty features configuration.

    Args:
        gd_features: Dictionary of feature names to enabled status

    Returns:
        List of feature configuration dictionaries
    """
    features = []

    for name, enabled in gd_features.items():
        status = "ENABLED" if enabled else "DISABLED"

        if name == "RUNTIME_MONITORING":
            features.append({
                "Name": name,
                "Status": status,
                "AdditionalConfiguration": [],
            })
        else:
            features.append({"Name": name, "Status": status})

    return features


def build_org_features_config(gd_features: Dict[str, bool]) -> List[Dict[str, Any]]:
    """Build GuardDuty organization features configuration.

    Args:
        gd_features: Dictionary of feature names to enabled status

    Returns:
        List of organization feature configuration dictionaries
    """
    features = []

    for name, enabled in gd_features.items():
        auto_enable = "ALL" if enabled else "NONE"

        if name == "RUNTIME_MONITORING":
            features.append({
                "Name": name,
                "AutoEnable": auto_enable,
                "AdditionalConfiguration": [],
            })
        else:
            features.append({"Name": name, "AutoEnable": auto_enable})

    return features


def update_guardduty_configuration(
    guardduty_client,
    detector_id: str,
    gd_features: Dict[str, bool],
    finding_publishing_frequency: str,
) -> None:
    """Update GuardDuty detector and organization configuration.

    Args:
        guardduty_client: GuardDuty client
        detector_id: Detector ID
        gd_features: Feature configuration
        finding_publishing_frequency: Finding publishing frequency
    """
    detector_features = build_features_config(gd_features)
    org_features = build_org_features_config(gd_features)

    guardduty_client.update_detector(
        DetectorId=detector_id,
        FindingPublishingFrequency=finding_publishing_frequency,
        Features=detector_features,
    )

    guardduty_client.update_organization_configuration(
        DetectorId=detector_id,
        AutoEnable=True,
        Features=org_features,
    )

    LOGGER.info(f"Updated GuardDuty configuration for detector {detector_id}")


def create_publishing_destination(
    guardduty_client,
    detector_id: str,
    bucket_arn: str,
    kms_key_arn: str,
) -> None:
    """Create or update GuardDuty publishing destination.

    Args:
        guardduty_client: GuardDuty client
        detector_id: Detector ID
        bucket_arn: S3 bucket ARN for findings
        kms_key_arn: KMS key ARN for encryption
    """
    response = guardduty_client.list_publishing_destinations(DetectorId=detector_id)

    destination_properties = {
        "DestinationArn": bucket_arn,
        "KmsKeyArn": kms_key_arn,
    }

    destinations = response.get("Destinations", [])

    if destinations:
        guardduty_client.update_publishing_destination(
            DetectorId=detector_id,
            DestinationId=destinations[0]["DestinationId"],
            DestinationProperties=destination_properties,
        )
        LOGGER.info(f"Updated publishing destination for detector {detector_id}")
    else:
        guardduty_client.create_publishing_destination(
            DetectorId=detector_id,
            DestinationType="S3",
            DestinationProperties=destination_properties,
        )
        LOGGER.info(f"Created publishing destination for detector {detector_id}")


def create_members(
    guardduty_client,
    detector_id: str,
    accounts: List[Dict[str, str]],
) -> None:
    """Create GuardDuty member accounts.

    Args:
        guardduty_client: GuardDuty client
        detector_id: Detector ID
        accounts: List of account dictionaries with AccountId and Email
    """
    if not accounts:
        return

    batch_size = 50
    num_batches = math.ceil(len(accounts) / batch_size)

    for i in range(num_batches):
        batch = accounts[i * batch_size : (i + 1) * batch_size]

        account_details = [
            {"AccountId": a["AccountId"], "Email": a["Email"]}
            for a in batch
        ]

        response = guardduty_client.create_members(
            DetectorId=detector_id,
            AccountDetails=account_details,
        )

        if response.get("UnprocessedAccounts"):
            LOGGER.warning(f"Unprocessed accounts: {response['UnprocessedAccounts']}")

    LOGGER.info(f"Created {len(accounts)} GuardDuty member accounts")


def update_member_detectors(
    guardduty_client,
    detector_id: str,
    account_ids: List[str],
    gd_features: Dict[str, bool],
) -> None:
    """Update member detector configurations.

    Args:
        guardduty_client: GuardDuty client
        detector_id: Detector ID
        account_ids: List of member account IDs
        gd_features: Feature configuration
    """
    if not account_ids:
        return

    features = build_features_config(gd_features)
    batch_size = 50
    num_batches = math.ceil(len(account_ids) / batch_size)

    for i in range(num_batches):
        batch = account_ids[i * batch_size : (i + 1) * batch_size]

        response = guardduty_client.update_member_detectors(
            DetectorId=detector_id,
            AccountIds=batch,
            Features=features,
        )

        if response.get("UnprocessedAccounts"):
            LOGGER.warning(f"Unprocessed accounts: {response['UnprocessedAccounts']}")

    LOGGER.info(f"Updated {len(account_ids)} member detectors")


def configure_guardduty(
    session: boto3.Session,
    delegated_account_id: str,
    gd_features: Dict[str, bool],
    regions: List[str],
    finding_publishing_frequency: str,
    kms_key_arn: str,
    publishing_bucket_arn: str,
) -> None:
    """Configure GuardDuty in all regions.

    Args:
        session: boto3 session for delegated admin account
        delegated_account_id: Delegated admin account ID
        gd_features: Feature configuration
        regions: List of AWS regions
        finding_publishing_frequency: Finding publishing frequency
        kms_key_arn: KMS key ARN for encryption
        publishing_bucket_arn: S3 bucket ARN for findings
    """
    accounts = get_organization_accounts(exclude_accounts=[delegated_account_id])
    account_ids = get_account_ids(accounts)

    for region in regions:
        LOGGER.info(f"Configuring GuardDuty in {region}")

        guardduty_client = session.client("guardduty", region_name=region, config=BOTO3_CONFIG)
        detector_id = get_detector_id(guardduty_client, create_if_missing=True)

        if not detector_id:
            LOGGER.error(f"No detector found in {region}")
            continue

        create_publishing_destination(
            guardduty_client,
            detector_id,
            publishing_bucket_arn,
            kms_key_arn,
        )

        update_guardduty_configuration(
            guardduty_client,
            detector_id,
            gd_features,
            finding_publishing_frequency,
        )

        create_members(guardduty_client, detector_id, accounts)
        update_member_detectors(guardduty_client, detector_id, account_ids, gd_features)


def delete_detector(
    guardduty_client,
    detector_id: str,
    disassociate_members: bool = True,
) -> None:
    """Delete a GuardDuty detector.

    Args:
        guardduty_client: GuardDuty client
        detector_id: Detector ID to delete
        disassociate_members: Whether to disassociate members first
    """
    if disassociate_members:
        paginator = guardduty_client.get_paginator("list_members")

        account_ids = []
        for page in paginator.paginate(DetectorId=detector_id, OnlyAssociated="false"):
            for member in page.get("Members", []):
                account_ids.append(member["AccountId"])

        if account_ids:
            guardduty_client.disassociate_members(
                DetectorId=detector_id,
                AccountIds=account_ids,
            )
            guardduty_client.delete_members(
                DetectorId=detector_id,
                AccountIds=account_ids,
            )

    guardduty_client.delete_detector(DetectorId=detector_id)
    LOGGER.info(f"Deleted detector {detector_id}")


def process_create_update(
    params: Dict[str, str],
    regions: List[str],
) -> None:
    """Process GuardDuty create/update event.

    Args:
        params: Event parameters
        regions: List of AWS regions
    """
    delegated_account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]
    configuration_role = params["CONFIGURATION_ROLE_NAME"]

    create_service_linked_role(
        "AWSServiceRoleForAmazonGuardDuty",
        GUARDDUTY_SERVICE_PRINCIPAL,
        "Service-linked role for Amazon GuardDuty",
    )
    create_service_linked_role(
        "AWSServiceRoleForAmazonGuardDutyMalwareProtection",
        MALWARE_PROTECTION_SERVICE_PRINCIPAL,
        "Service-linked role for Amazon GuardDuty Malware Protection",
    )

    enable_organization_admin_account(delegated_account_id, regions)
    sleep(30)

    session = assume_role(configuration_role, "ConfigureGuardDuty", delegated_account_id)

    max_retries = 30
    for i in range(max_retries):
        if check_for_detectors(session, regions):
            break
        LOGGER.info(f"Waiting for detectors... ({i + 1}/{max_retries})")
        sleep(10)
    else:
        raise ValueError("GuardDuty detectors not created in time")

    gd_features = {
        "S3_DATA_EVENTS": parse_bool(params.get("AUTO_ENABLE_S3_LOGS", "false")),
        "EKS_AUDIT_LOGS": parse_bool(params.get("ENABLE_EKS_AUDIT_LOGS", "false")),
        "EBS_MALWARE_PROTECTION": parse_bool(params.get("AUTO_ENABLE_MALWARE_PROTECTION", "false")),
        "RDS_LOGIN_EVENTS": parse_bool(params.get("ENABLE_RDS_LOGIN_EVENTS", "false")),
        "LAMBDA_NETWORK_LOGS": parse_bool(params.get("ENABLE_LAMBDA_NETWORK_LOGS", "false")),
        "RUNTIME_MONITORING": parse_bool(params.get("ENABLE_RUNTIME_MONITORING", "false")),
    }

    configure_guardduty(
        session,
        delegated_account_id,
        gd_features,
        regions,
        params.get("FINDING_PUBLISHING_FREQUENCY", "FIFTEEN_MINUTES"),
        params.get("KMS_KEY_ARN", ""),
        params.get("PUBLISHING_DESTINATION_BUCKET_ARN", ""),
    )


def process_delete(
    params: Dict[str, str],
    regions: List[str],
) -> None:
    """Process GuardDuty delete event.

    Args:
        params: Event parameters
        regions: List of AWS regions
    """
    delegated_account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]
    configuration_role = params["CONFIGURATION_ROLE_NAME"]

    session = assume_role(configuration_role, "DeleteGuardDuty", delegated_account_id)

    for region in regions:
        guardduty_client = session.client("guardduty", region_name=region, config=BOTO3_CONFIG)
        detector_id = get_detector_id(guardduty_client)

        if detector_id:
            delete_detector(guardduty_client, detector_id)

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

    params = validate_guardduty_params(properties)

    enabled_regions_str = properties.get("ENABLED_REGIONS", "")
    if enabled_regions_str:
        regions = [r.strip() for r in enabled_regions_str.split(",") if r.strip()]
    else:
        regions = ["us-east-1"]

    delegated_account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]

    if request_type in ("Create", "Update"):
        process_create_update(params, regions)
    elif request_type == "Delete":
        process_delete(params, regions)

    return f"sra-guardduty-{delegated_account_id}"


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

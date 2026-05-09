"""SecurityHub organization configuration for AWS SRA.

Configures SecurityHub with delegated administrator, member accounts, and security standards.
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

SECURITYHUB_SERVICE_PRINCIPAL = "securityhub.amazonaws.com"

STANDARD_ARNS = {
    "sbp": "arn:{partition}:securityhub:{region}::standards/aws-foundational-security-best-practices/v/{version}",
    "cis": "arn:{partition}:securityhub:::ruleset/cis-aws-foundations-benchmark/v/{version}",
    "pci": "arn:{partition}:securityhub:{region}::standards/pci-dss/v/{version}",
    "nist": "arn:{partition}:securityhub:{region}::standards/nist-800-53/v/{version}",
}


def parse_bool(value: str) -> bool:
    """Parse boolean string value."""
    return value.lower() == "true"


def validate_securityhub_params(params: Dict[str, str]) -> Dict[str, str]:
    """Validate SecurityHub configuration parameters.

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
        "ENABLE_CIS_STANDARD",
        params.get("ENABLE_CIS_STANDARD", "false"),
        true_false_pattern,
    )
    validate_parameter(
        "ENABLE_PCI_STANDARD",
        params.get("ENABLE_PCI_STANDARD", "false"),
        true_false_pattern,
    )
    validate_parameter(
        "ENABLE_NIST_STANDARD",
        params.get("ENABLE_NIST_STANDARD", "false"),
        true_false_pattern,
    )
    validate_parameter(
        "ENABLE_SECURITY_BEST_PRACTICES_STANDARD",
        params.get("ENABLE_SECURITY_BEST_PRACTICES_STANDARD", "true"),
        true_false_pattern,
    )
    validate_parameter(
        "DISABLE_SECURITY_HUB",
        params.get("DISABLE_SECURITY_HUB", "false"),
        true_false_pattern,
    )

    return params


def get_standards_config(params: Dict[str, str]) -> Dict[str, Any]:
    """Get standards configuration from parameters.

    Args:
        params: Event parameters

    Returns:
        Standards configuration dictionary
    """
    return {
        "standards_to_enable": {
            "sbp": parse_bool(params.get("ENABLE_SECURITY_BEST_PRACTICES_STANDARD", "true")),
            "cis": parse_bool(params.get("ENABLE_CIS_STANDARD", "false")),
            "pci": parse_bool(params.get("ENABLE_PCI_STANDARD", "false")),
            "nist": parse_bool(params.get("ENABLE_NIST_STANDARD", "false")),
        },
        "sbp_version": params.get("SECURITY_BEST_PRACTICES_VERSION", "1.0.0"),
        "cis_version": params.get("CIS_VERSION", "1.2.0"),
        "pci_version": params.get("PCI_VERSION", "3.2.1"),
        "nist_version": params.get("NIST_VERSION", "5.0.0"),
    }


def enable_organization_admin_account(
    admin_account_id: str,
    regions: List[str],
    session: Optional[boto3.Session] = None,
) -> None:
    """Enable SecurityHub delegated admin account in specified regions.

    Args:
        admin_account_id: Account ID to designate as delegated admin
        regions: List of AWS regions
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    for region in regions:
        securityhub_client = session.client("securityhub", region_name=region, config=BOTO3_CONFIG)

        try:
            paginator = securityhub_client.get_paginator("list_organization_admin_accounts")
            is_enabled = False

            for page in paginator.paginate():
                for admin in page.get("AdminAccounts", []):
                    if admin["AccountId"] == admin_account_id and admin["Status"] == "ENABLED":
                        is_enabled = True
                        break

            if not is_enabled:
                securityhub_client.enable_organization_admin_account(AdminAccountId=admin_account_id)
                LOGGER.info(f"Enabled SecurityHub admin account {admin_account_id} in {region}")
            else:
                LOGGER.info(f"SecurityHub admin account {admin_account_id} already enabled in {region}")

        except ClientError as e:
            if e.response["Error"]["Code"] == "ResourceConflictException":
                LOGGER.info(f"SecurityHub admin already enabled in {region}")
            else:
                raise


def disable_organization_admin_account(
    regions: List[str],
    session: Optional[boto3.Session] = None,
) -> None:
    """Disable SecurityHub delegated admin account in specified regions.

    Args:
        regions: List of AWS regions
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    for region in regions:
        securityhub_client = session.client("securityhub", region_name=region, config=BOTO3_CONFIG)

        try:
            paginator = securityhub_client.get_paginator("list_organization_admin_accounts")

            for page in paginator.paginate():
                for admin in page.get("AdminAccounts", []):
                    if admin.get("Status") == "ENABLED":
                        securityhub_client.disable_organization_admin_account(
                            AdminAccountId=admin["AccountId"]
                        )
                        LOGGER.info(f"Disabled SecurityHub admin account in {region}")
        except ClientError as e:
            LOGGER.warning(f"Error disabling admin in {region}: {e}")


def enable_securityhub(
    regions: List[str],
    standards_config: Optional[Dict[str, Any]] = None,
    partition: str = "aws",
    session: Optional[boto3.Session] = None,
) -> None:
    """Enable SecurityHub in the specified regions.

    Args:
        regions: List of AWS regions
        standards_config: Standards configuration
        partition: AWS partition
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    for region in regions:
        securityhub_client = session.client("securityhub", region_name=region, config=BOTO3_CONFIG)

        try:
            securityhub_client.enable_security_hub(EnableDefaultStandards=False)
            LOGGER.info(f"Enabled SecurityHub in {region}")
        except securityhub_client.exceptions.ResourceConflictException:
            LOGGER.info(f"SecurityHub already enabled in {region}")

        if standards_config:
            configure_standards(securityhub_client, region, standards_config, partition)


def configure_standards(
    securityhub_client,
    region: str,
    standards_config: Dict[str, Any],
    partition: str = "aws",
) -> None:
    """Configure SecurityHub standards.

    Args:
        securityhub_client: SecurityHub client
        region: AWS region
        standards_config: Standards configuration
        partition: AWS partition
    """
    standards_to_enable = standards_config.get("standards_to_enable", {})

    for standard_key, enabled in standards_to_enable.items():
        if not enabled:
            continue

        version = standards_config.get(f"{standard_key}_version", "1.0.0")
        arn_template = STANDARD_ARNS.get(standard_key)

        if not arn_template:
            continue

        standard_arn = arn_template.format(
            partition=partition,
            region=region,
            version=version,
        )

        try:
            securityhub_client.batch_enable_standards(
                StandardsSubscriptionRequests=[{"StandardsArn": standard_arn}]
            )
            LOGGER.info(f"Enabled standard {standard_key} in {region}")
        except ClientError as e:
            LOGGER.warning(f"Error enabling standard {standard_key} in {region}: {e}")


def disable_securityhub(
    regions: List[str],
    disassociate_members: bool = False,
    session: Optional[boto3.Session] = None,
) -> None:
    """Disable SecurityHub in the specified regions.

    Args:
        regions: List of AWS regions
        disassociate_members: Whether to disassociate members first
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    for region in regions:
        securityhub_client = session.client("securityhub", region_name=region, config=BOTO3_CONFIG)

        if disassociate_members:
            try:
                paginator = securityhub_client.get_paginator("list_members")
                account_ids = []

                for page in paginator.paginate(OnlyAssociated=False):
                    for member in page.get("Members", []):
                        account_ids.append(member["AccountId"])

                if account_ids:
                    securityhub_client.disassociate_members(AccountIds=account_ids)
                    securityhub_client.delete_members(AccountIds=account_ids)
                    LOGGER.info(f"Removed {len(account_ids)} SecurityHub members in {region}")
            except ClientError as e:
                LOGGER.warning(f"Error removing members in {region}: {e}")

        try:
            securityhub_client.disable_security_hub()
            LOGGER.info(f"Disabled SecurityHub in {region}")
        except securityhub_client.exceptions.ResourceNotFoundException:
            LOGGER.debug(f"SecurityHub not enabled in {region}")
        except ClientError as e:
            LOGGER.warning(f"Error disabling SecurityHub in {region}: {e}")


def create_members(
    securityhub_client,
    accounts: List[Dict[str, str]],
) -> None:
    """Create SecurityHub member accounts.

    Args:
        securityhub_client: SecurityHub client
        accounts: List of account dictionaries with AccountId and Email
    """
    if not accounts:
        return

    account_details = [
        {"AccountId": a["AccountId"], "Email": a["Email"]}
        for a in accounts
    ]

    try:
        response = securityhub_client.create_members(AccountDetails=account_details)

        if response.get("UnprocessedAccounts"):
            LOGGER.warning(f"Unprocessed accounts: {response['UnprocessedAccounts']}")

        LOGGER.info(f"Created {len(accounts)} SecurityHub member accounts")
    except ClientError as e:
        LOGGER.warning(f"Error creating members: {e}")


def update_organization_configuration(
    securityhub_client,
    auto_enable: bool = True,
) -> None:
    """Update SecurityHub organization configuration.

    Args:
        securityhub_client: SecurityHub client
        auto_enable: Whether to auto-enable new accounts
    """
    try:
        securityhub_client.update_organization_configuration(AutoEnable=auto_enable)
        LOGGER.info(f"Updated organization configuration: AutoEnable={auto_enable}")
    except ClientError as e:
        LOGGER.warning(f"Error updating organization configuration: {e}")


def configure_securityhub(
    session: boto3.Session,
    delegated_account_id: str,
    regions: List[str],
    standards_config: Dict[str, Any],
    partition: str = "aws",
) -> None:
    """Configure SecurityHub in all regions.

    Args:
        session: boto3 session for delegated admin account
        delegated_account_id: Delegated admin account ID
        regions: List of AWS regions
        standards_config: Standards configuration
        partition: AWS partition
    """
    accounts = get_organization_accounts(exclude_accounts=[delegated_account_id])

    for region in regions:
        LOGGER.info(f"Configuring SecurityHub in {region}")

        securityhub_client = session.client("securityhub", region_name=region, config=BOTO3_CONFIG)

        configure_standards(securityhub_client, region, standards_config, partition)
        create_members(securityhub_client, accounts)
        update_organization_configuration(securityhub_client)

        LOGGER.info(f"Configured SecurityHub in {region}")


def process_create_update(
    params: Dict[str, str],
    regions: List[str],
) -> None:
    """Process SecurityHub create/update event.

    Args:
        params: Event parameters
        regions: List of AWS regions
    """
    delegated_account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]
    configuration_role = params["CONFIGURATION_ROLE_NAME"]
    partition = params.get("AWS_PARTITION", "aws")

    create_service_linked_role(
        "AWSServiceRoleForSecurityHub",
        SECURITYHUB_SERVICE_PRINCIPAL,
        "Service-linked role for AWS Security Hub",
    )

    standards_config = get_standards_config(params)

    enable_securityhub(regions, standards_config, partition)
    sleep(20)

    enable_organization_admin_account(delegated_account_id, regions)
    sleep(30)

    session = assume_role(configuration_role, "ConfigureSecurityHub", delegated_account_id)

    enable_securityhub(regions, standards_config, partition, session)

    configure_securityhub(session, delegated_account_id, regions, standards_config, partition)


def process_delete(
    params: Dict[str, str],
    regions: List[str],
) -> None:
    """Process SecurityHub delete event.

    Args:
        params: Event parameters
        regions: List of AWS regions
    """
    delegated_account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]
    configuration_role = params["CONFIGURATION_ROLE_NAME"]

    session = assume_role(configuration_role, "DeleteSecurityHub", delegated_account_id)

    disable_securityhub(regions, disassociate_members=True, session=session)
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

    params = validate_securityhub_params(properties)

    enabled_regions_str = properties.get("ENABLED_REGIONS", "")
    if enabled_regions_str:
        regions = [r.strip() for r in enabled_regions_str.split(",") if r.strip()]
    else:
        regions = ["us-east-1"]

    delegated_account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]

    if request_type in ("Create", "Update"):
        disable_flag = parse_bool(params.get("DISABLE_SECURITY_HUB", "false"))

        if disable_flag and request_type == "Update":
            process_delete(params, regions)
        else:
            process_create_update(params, regions)
    elif request_type == "Delete":
        process_delete(params, regions)

    return f"sra-securityhub-{delegated_account_id}"


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

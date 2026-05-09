"""Delegated administrator registration for AWS SRA.

Registers and deregisters delegated administrator accounts for AWS services
within AWS Organizations.
"""

import logging
from typing import Any, Dict, List, Optional

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from sra.validation import ValidationError, validate_parameter

LOGGER = logging.getLogger(__name__)

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

VALID_SERVICE_PRINCIPALS = [
    "access-analyzer.amazonaws.com",
    "auditmanager.amazonaws.com",
    "config-multiaccountsetup.amazonaws.com",
    "config.amazonaws.com",
    "guardduty.amazonaws.com",
    "macie.amazonaws.com",
    "securityhub.amazonaws.com",
    "stacksets.cloudformation.amazonaws.com",
    "storage-lens.s3.amazonaws.com",
    "inspector2.amazonaws.com",
    "detective.amazonaws.com",
]


def validate_delegated_admin_params(params: Dict[str, Any]) -> Dict[str, Any]:
    """Validate delegated admin parameters.

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

    return params


def validate_service_principals(service_principals: List[str]) -> None:
    """Validate service principals are in the allowed list.

    Args:
        service_principals: List of service principals

    Raises:
        ValidationError: If an invalid service principal is provided
    """
    for principal in service_principals:
        if principal not in VALID_SERVICE_PRINCIPALS:
            raise ValidationError(
                f"Invalid service principal: {principal}. "
                f"Valid values: {VALID_SERVICE_PRINCIPALS}"
            )


def enable_aws_service_access(
    service_principal: str,
    session: Optional[boto3.Session] = None,
) -> None:
    """Enable AWS service access for a service principal.

    Args:
        service_principal: AWS service principal
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    org_client = session.client("organizations", config=BOTO3_CONFIG)

    try:
        org_client.enable_aws_service_access(ServicePrincipal=service_principal)
        LOGGER.info(f"Enabled AWS service access for {service_principal}")
    except ClientError as e:
        LOGGER.warning(f"Error enabling service access for {service_principal}: {e}")


def disable_aws_service_access(
    service_principal: str,
    session: Optional[boto3.Session] = None,
) -> None:
    """Disable AWS service access for a service principal.

    Args:
        service_principal: AWS service principal
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    org_client = session.client("organizations", config=BOTO3_CONFIG)

    try:
        org_client.disable_aws_service_access(ServicePrincipal=service_principal)
        LOGGER.info(f"Disabled AWS service access for {service_principal}")
    except ClientError as e:
        LOGGER.warning(f"Error disabling service access for {service_principal}: {e}")


def register_delegated_administrator(
    account_id: str,
    service_principal: str,
    session: Optional[boto3.Session] = None,
) -> None:
    """Register a delegated administrator account for a service.

    Args:
        account_id: Account ID to register as delegated admin
        service_principal: AWS service principal
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    org_client = session.client("organizations", config=BOTO3_CONFIG)

    try:
        org_client.register_delegated_administrator(
            AccountId=account_id,
            ServicePrincipal=service_principal,
        )
        LOGGER.info(f"Registered {account_id} as delegated admin for {service_principal}")

        response = org_client.list_delegated_administrators(ServicePrincipal=service_principal)

        if not response.get("DelegatedAdministrators"):
            raise ValueError(f"Failed to register delegated administrator for {service_principal}")

    except org_client.exceptions.AccountAlreadyRegisteredException:
        LOGGER.info(f"Account {account_id} already registered for {service_principal}")


def deregister_delegated_administrator(
    account_id: str,
    service_principal: str,
    session: Optional[boto3.Session] = None,
) -> None:
    """Deregister a delegated administrator account for a service.

    Args:
        account_id: Account ID to deregister
        service_principal: AWS service principal
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    org_client = session.client("organizations", config=BOTO3_CONFIG)

    try:
        org_client.deregister_delegated_administrator(
            AccountId=account_id,
            ServicePrincipal=service_principal,
        )
        LOGGER.info(f"Deregistered {account_id} as delegated admin for {service_principal}")
    except org_client.exceptions.AccountNotRegisteredException:
        LOGGER.info(f"Account {account_id} not registered for {service_principal}")
    except ClientError as e:
        LOGGER.warning(f"Error deregistering delegated admin for {service_principal}: {e}")


def list_delegated_administrators(
    service_principal: Optional[str] = None,
    session: Optional[boto3.Session] = None,
) -> List[Dict[str, Any]]:
    """List delegated administrator accounts.

    Args:
        service_principal: Optional service principal to filter by
        session: Optional boto3 session

    Returns:
        List of delegated administrator accounts
    """
    if session is None:
        session = boto3.Session()

    org_client = session.client("organizations", config=BOTO3_CONFIG)

    try:
        if service_principal:
            response = org_client.list_delegated_administrators(
                ServicePrincipal=service_principal
            )
        else:
            response = org_client.list_delegated_administrators()

        return response.get("DelegatedAdministrators", [])
    except ClientError as e:
        LOGGER.warning(f"Error listing delegated administrators: {e}")
        return []


def parse_service_principal_list(principals_param: Any) -> List[str]:
    """Parse service principals from parameter value.

    Args:
        principals_param: Service principals as list or comma-separated string

    Returns:
        List of service principals
    """
    if isinstance(principals_param, list):
        return [p.strip() for p in principals_param if p.strip()]
    elif isinstance(principals_param, str):
        return [p.strip() for p in principals_param.split(",") if p.strip()]
    return []


def process_create(
    params: Dict[str, Any],
    service_principals: List[str],
) -> None:
    """Process create event.

    Args:
        params: Event parameters
        service_principals: List of service principals
    """
    account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]

    for principal in service_principals:
        enable_aws_service_access(principal)
        register_delegated_administrator(account_id, principal)


def process_update(
    params: Dict[str, Any],
    service_principals: List[str],
    old_service_principals: List[str],
) -> None:
    """Process update event.

    Args:
        params: Event parameters
        service_principals: New list of service principals
        old_service_principals: Previous list of service principals
    """
    account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]

    add_list = set(service_principals) - set(old_service_principals)
    remove_list = set(old_service_principals) - set(service_principals)

    for principal in add_list:
        enable_aws_service_access(principal)
        register_delegated_administrator(account_id, principal)

    for principal in remove_list:
        deregister_delegated_administrator(account_id, principal)
        disable_aws_service_access(principal)


def process_delete(
    params: Dict[str, Any],
    service_principals: List[str],
) -> None:
    """Process delete event.

    Args:
        params: Event parameters
        service_principals: List of service principals
    """
    account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]

    for principal in service_principals:
        deregister_delegated_administrator(account_id, principal)
        disable_aws_service_access(principal)


def process_cloudformation_event(event: Dict[str, Any]) -> str:
    """Process CloudFormation custom resource event.

    Args:
        event: CloudFormation event

    Returns:
        Physical resource ID
    """
    request_type = event.get("RequestType", "")
    properties = event.get("ResourceProperties", {})

    params = validate_delegated_admin_params(properties)

    service_principals = parse_service_principal_list(
        properties.get("AWS_SERVICE_PRINCIPAL_LIST", [])
    )
    validate_service_principals(service_principals)

    account_id = params["DELEGATED_ADMIN_ACCOUNT_ID"]

    if request_type == "Create":
        process_create(params, service_principals)
    elif request_type == "Update":
        old_properties = event.get("OldResourceProperties", {})
        old_service_principals = parse_service_principal_list(
            old_properties.get("AWS_SERVICE_PRINCIPAL_LIST", [])
        )
        process_update(params, service_principals, old_service_principals)
    elif request_type == "Delete":
        process_delete(params, service_principals)

    return f"DelegatedAdminResourceId-{account_id}"


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

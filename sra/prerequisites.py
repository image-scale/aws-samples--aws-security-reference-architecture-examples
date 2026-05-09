"""Common prerequisites management for AWS SRA.

Creates SSM parameters with organization, account, and region data.
"""

import logging
from typing import Any, Dict, List, Optional, Sequence

import boto3
from botocore.config import Config
from botocore.exceptions import ClientError

from sra.validation import ValidationError, validate_parameter

LOGGER = logging.getLogger(__name__)

BOTO3_CONFIG = Config(retries={"max_attempts": 10, "mode": "standard"})

SRA_CONTROL_TOWER_SSM_PATH = "/sra/control-tower"
SRA_REGIONS_SSM_PATH = "/sra/regions"

SRA_SSM_PARAMETERS = [
    "/sra/control-tower/root-organizational-unit-id",
    "/sra/control-tower/organization-id",
    "/sra/control-tower/management-account-id",
    "/sra/control-tower/home-region",
    "/sra/control-tower/audit-account-id",
    "/sra/control-tower/log-archive-account-id",
    "/sra/regions/enabled-regions",
    "/sra/regions/enabled-regions-without-home-region",
    "/sra/regions/customer-control-tower-regions",
    "/sra/regions/customer-control-tower-regions-without-home-region",
]

EMPTY_VALUE = "NONE"


def validate_prerequisites_params(params: Dict[str, str]) -> Dict[str, str]:
    """Validate prerequisites parameters.

    Args:
        params: Parameters from CloudFormation event

    Returns:
        Validated parameters
    """
    validate_parameter("TAG_KEY", params.get("TAG_KEY", ""), r"^.{1,128}$")
    validate_parameter("TAG_VALUE", params.get("TAG_VALUE", ""), r"^.{1,256}$")
    return params


def get_organization_info(
    session: Optional[boto3.Session] = None,
) -> Dict[str, Any]:
    """Get organization information from AWS Organizations.

    Args:
        session: Optional boto3 session

    Returns:
        Dictionary with organization info and SSM parameter data
    """
    if session is None:
        session = boto3.Session()

    org_client = session.client("organizations", config=BOTO3_CONFIG)

    org = org_client.describe_organization()["Organization"]
    root_id = org_client.list_roots()["Roots"][0]["Id"]

    ssm_info = [
        {
            "name": f"{SRA_CONTROL_TOWER_SSM_PATH}/root-organizational-unit-id",
            "value": root_id,
            "parameter_type": "String",
        },
        {
            "name": f"{SRA_CONTROL_TOWER_SSM_PATH}/organization-id",
            "value": org["Id"],
            "parameter_type": "String",
        },
        {
            "name": f"{SRA_CONTROL_TOWER_SSM_PATH}/management-account-id",
            "value": org["MasterAccountId"],
            "parameter_type": "String",
        },
    ]

    helper_data = {
        "ManagementAccountId": org["MasterAccountId"],
        "OrganizationId": org["Id"],
        "RootOrganizationalUnitId": root_id,
    }

    LOGGER.info(f"Organization info: {helper_data}")
    return {"info": ssm_info, "helper": helper_data}


def get_account_info(
    home_region: str,
    audit_account_id: str,
    log_archive_account_id: str,
) -> Dict[str, Any]:
    """Get account information for SSM parameters.

    Args:
        home_region: Home region for the deployment
        audit_account_id: Security/audit account ID
        log_archive_account_id: Log archive account ID

    Returns:
        Dictionary with account info and SSM parameter data
    """
    ssm_info = [
        {
            "name": f"{SRA_CONTROL_TOWER_SSM_PATH}/home-region",
            "value": home_region,
            "parameter_type": "String",
        },
        {
            "name": f"{SRA_CONTROL_TOWER_SSM_PATH}/audit-account-id",
            "value": audit_account_id or EMPTY_VALUE,
            "parameter_type": "String",
        },
        {
            "name": f"{SRA_CONTROL_TOWER_SSM_PATH}/log-archive-account-id",
            "value": log_archive_account_id or EMPTY_VALUE,
            "parameter_type": "String",
        },
    ]

    helper_data = {
        "HomeRegion": home_region,
        "AuditAccountId": audit_account_id or EMPTY_VALUE,
        "LogArchiveAccountId": log_archive_account_id or EMPTY_VALUE,
    }

    LOGGER.info(f"Account info: {helper_data}")
    return {"info": ssm_info, "helper": helper_data}


def get_region_info(
    enabled_regions: List[str],
    home_region: str,
    customer_regions: Optional[List[str]] = None,
) -> Dict[str, Any]:
    """Get region information for SSM parameters.

    Args:
        enabled_regions: List of enabled AWS regions
        home_region: Home region for the deployment
        customer_regions: Optional list of customer-specified regions

    Returns:
        Dictionary with region info and SSM parameter data
    """
    enabled_regions_without_home = [r for r in enabled_regions if r != home_region]

    if customer_regions is None:
        customer_regions = enabled_regions.copy()

    customer_regions_without_home = [r for r in customer_regions if r != home_region]

    ssm_info = [
        {
            "name": f"{SRA_REGIONS_SSM_PATH}/enabled-regions",
            "value": ",".join(enabled_regions),
            "parameter_type": "StringList",
        },
        {
            "name": f"{SRA_REGIONS_SSM_PATH}/enabled-regions-without-home-region",
            "value": ",".join(enabled_regions_without_home),
            "parameter_type": "StringList",
        },
        {
            "name": f"{SRA_REGIONS_SSM_PATH}/customer-control-tower-regions",
            "value": ",".join(customer_regions),
            "parameter_type": "StringList",
        },
        {
            "name": f"{SRA_REGIONS_SSM_PATH}/customer-control-tower-regions-without-home-region",
            "value": ",".join(customer_regions_without_home),
            "parameter_type": "StringList",
        },
    ]

    helper_data = {
        "EnabledRegions": enabled_regions,
        "EnabledRegionsWithoutHomeRegion": enabled_regions_without_home,
        "CustomerControlTowerRegions": customer_regions,
        "CustomerControlTowerRegionsWithoutHomeRegion": customer_regions_without_home,
    }

    LOGGER.info(f"Region info: {helper_data}")
    return {"info": ssm_info, "helper": helper_data}


def create_ssm_parameter(
    ssm_client,
    name: str,
    value: str,
    parameter_type: str,
) -> None:
    """Create or update an SSM parameter.

    Args:
        ssm_client: Boto3 SSM client
        name: Parameter name
        value: Parameter value
        parameter_type: Parameter type (String or StringList)
    """
    if not value:
        value = EMPTY_VALUE

    response = ssm_client.put_parameter(
        Name=name,
        Value=value,
        Type=parameter_type,
        Overwrite=True,
    )
    LOGGER.debug(f"Created SSM parameter {name}: {response}")


def add_tags_to_ssm_parameter(
    ssm_client,
    parameter_name: str,
    tags: Sequence[Dict[str, str]],
) -> None:
    """Add tags to an SSM parameter.

    Args:
        ssm_client: Boto3 SSM client
        parameter_name: SSM parameter name
        tags: List of tag dictionaries with Key and Value
    """
    response = ssm_client.add_tags_to_resource(
        ResourceType="Parameter",
        ResourceId=parameter_name,
        Tags=tags,
    )
    LOGGER.debug(f"Added tags to {parameter_name}: {response}")


def create_ssm_parameters_in_regions(
    ssm_parameters: List[Dict[str, str]],
    tags: Sequence[Dict[str, str]],
    regions: List[str],
    session: Optional[boto3.Session] = None,
) -> None:
    """Create SSM parameters in multiple regions.

    Args:
        ssm_parameters: List of parameter definitions
        tags: Tags to apply to parameters
        regions: List of regions to create parameters in
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    parameters_created = set()

    for region in regions:
        ssm_client = session.client("ssm", region_name=region, config=BOTO3_CONFIG)

        for param in ssm_parameters:
            create_ssm_parameter(
                ssm_client,
                name=param["name"],
                value=param["value"],
                parameter_type=param["parameter_type"],
            )
            add_tags_to_ssm_parameter(ssm_client, param["name"], tags)
            parameters_created.add(param["name"])

        LOGGER.info(f"Created SSM parameters in {region}")

    LOGGER.info(f"Created parameters: {list(parameters_created)}")


def delete_ssm_parameters_in_regions(
    regions: List[str],
    session: Optional[boto3.Session] = None,
) -> None:
    """Delete SSM parameters in multiple regions.

    Args:
        regions: List of regions to delete parameters from
        session: Optional boto3 session
    """
    if session is None:
        session = boto3.Session()

    for region in regions:
        ssm_client = session.client("ssm", region_name=region, config=BOTO3_CONFIG)

        try:
            ssm_client.delete_parameters(Names=SRA_SSM_PARAMETERS)
            LOGGER.info(f"Deleted SSM parameters in {region}")
        except ClientError as e:
            LOGGER.warning(f"Error deleting parameters in {region}: {e}")


def process_cloudformation_event(event: Dict[str, Any]) -> str:
    """Process CloudFormation custom resource event.

    Args:
        event: CloudFormation event

    Returns:
        Physical resource ID
    """
    request_type = event.get("RequestType", "")
    properties = event.get("ResourceProperties", {})

    if request_type == "Delete":
        LOGGER.info("SRA SSM Parameters are being retained on delete.")
        return "MANAGEMENT-ACCOUNT-PARAMETERS"

    params = validate_prerequisites_params(properties)
    tags = [{"Key": params["TAG_KEY"], "Value": params["TAG_VALUE"]}]

    home_region = properties.get("HOME_REGION", "us-east-1")
    audit_account_id = properties.get("AUDIT_ACCOUNT_ID", "")
    log_archive_account_id = properties.get("LOG_ARCHIVE_ACCOUNT_ID", "")
    enabled_regions_str = properties.get("ENABLED_REGIONS", "")
    customer_regions_str = properties.get("CUSTOMER_REGIONS", "")

    if enabled_regions_str:
        enabled_regions = [r.strip() for r in enabled_regions_str.split(",") if r.strip()]
    else:
        enabled_regions = [home_region]

    customer_regions = None
    if customer_regions_str:
        customer_regions = [r.strip() for r in customer_regions_str.split(",") if r.strip()]

    org_info = get_organization_info()
    account_info = get_account_info(home_region, audit_account_id, log_archive_account_id)
    region_info = get_region_info(enabled_regions, home_region, customer_regions)

    all_ssm_params = org_info["info"] + account_info["info"] + region_info["info"]
    create_ssm_parameters_in_regions(all_ssm_params, tags, enabled_regions)

    return "MANAGEMENT-ACCOUNT-PARAMETERS"


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

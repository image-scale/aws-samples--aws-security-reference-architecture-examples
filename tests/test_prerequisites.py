"""Tests for the prerequisites module."""

from unittest.mock import MagicMock, patch

import pytest

from sra.prerequisites import (
    SRA_CONTROL_TOWER_SSM_PATH,
    SRA_REGIONS_SSM_PATH,
    add_tags_to_ssm_parameter,
    create_ssm_parameter,
    create_ssm_parameters_in_regions,
    delete_ssm_parameters_in_regions,
    get_account_info,
    get_organization_info,
    get_region_info,
    lambda_handler,
    process_cloudformation_event,
    validate_prerequisites_params,
)
from sra.validation import ValidationError


class TestValidatePrerequisitesParams:
    """Tests for validate_prerequisites_params function."""

    def test_validates_valid_params(self):
        """Validates correct parameters without error."""
        params = {
            "TAG_KEY": "sra-solution",
            "TAG_VALUE": "common-prerequisites",
        }

        result = validate_prerequisites_params(params)
        assert result == params

    def test_raises_for_empty_tag_key(self):
        """Raises ValidationError for empty tag key."""
        params = {
            "TAG_KEY": "",
            "TAG_VALUE": "common-prerequisites",
        }

        with pytest.raises(ValidationError):
            validate_prerequisites_params(params)

    def test_raises_for_missing_tag_value(self):
        """Raises ValidationError for missing tag value."""
        params = {
            "TAG_KEY": "sra-solution",
        }

        with pytest.raises(ValidationError):
            validate_prerequisites_params(params)


class TestGetOrganizationInfo:
    """Tests for get_organization_info function."""

    def test_returns_organization_data(self):
        """Returns organization ID, root OU ID, and management account."""
        with patch("sra.prerequisites.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_org_client.describe_organization.return_value = {
                "Organization": {
                    "Id": "o-abc123",
                    "MasterAccountId": "111111111111",
                }
            }
            mock_org_client.list_roots.return_value = {
                "Roots": [{"Id": "r-root"}]
            }

            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            result = get_organization_info()

            assert result["helper"]["OrganizationId"] == "o-abc123"
            assert result["helper"]["ManagementAccountId"] == "111111111111"
            assert result["helper"]["RootOrganizationalUnitId"] == "r-root"

    def test_returns_ssm_parameter_info(self):
        """Returns SSM parameter definitions."""
        with patch("sra.prerequisites.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_org_client.describe_organization.return_value = {
                "Organization": {
                    "Id": "o-abc123",
                    "MasterAccountId": "111111111111",
                }
            }
            mock_org_client.list_roots.return_value = {
                "Roots": [{"Id": "r-root"}]
            }

            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            result = get_organization_info()

            param_names = [p["name"] for p in result["info"]]
            assert f"{SRA_CONTROL_TOWER_SSM_PATH}/organization-id" in param_names
            assert f"{SRA_CONTROL_TOWER_SSM_PATH}/management-account-id" in param_names
            assert f"{SRA_CONTROL_TOWER_SSM_PATH}/root-organizational-unit-id" in param_names


class TestGetAccountInfo:
    """Tests for get_account_info function."""

    def test_returns_account_data(self):
        """Returns home region, audit account, and log archive account."""
        result = get_account_info(
            home_region="us-east-1",
            audit_account_id="222222222222",
            log_archive_account_id="333333333333",
        )

        assert result["helper"]["HomeRegion"] == "us-east-1"
        assert result["helper"]["AuditAccountId"] == "222222222222"
        assert result["helper"]["LogArchiveAccountId"] == "333333333333"

    def test_returns_ssm_parameter_info(self):
        """Returns SSM parameter definitions for account data."""
        result = get_account_info(
            home_region="eu-west-1",
            audit_account_id="222222222222",
            log_archive_account_id="333333333333",
        )

        param_names = [p["name"] for p in result["info"]]
        assert f"{SRA_CONTROL_TOWER_SSM_PATH}/home-region" in param_names
        assert f"{SRA_CONTROL_TOWER_SSM_PATH}/audit-account-id" in param_names
        assert f"{SRA_CONTROL_TOWER_SSM_PATH}/log-archive-account-id" in param_names

    def test_uses_empty_value_for_missing_accounts(self):
        """Uses NONE for missing account IDs."""
        result = get_account_info(
            home_region="us-east-1",
            audit_account_id="",
            log_archive_account_id="",
        )

        assert result["helper"]["AuditAccountId"] == "NONE"
        assert result["helper"]["LogArchiveAccountId"] == "NONE"


class TestGetRegionInfo:
    """Tests for get_region_info function."""

    def test_returns_enabled_regions(self):
        """Returns enabled regions information."""
        result = get_region_info(
            enabled_regions=["us-east-1", "eu-west-1", "ap-northeast-1"],
            home_region="us-east-1",
        )

        assert result["helper"]["EnabledRegions"] == ["us-east-1", "eu-west-1", "ap-northeast-1"]

    def test_excludes_home_region_from_without_home_list(self):
        """Excludes home region from without-home-region lists."""
        result = get_region_info(
            enabled_regions=["us-east-1", "eu-west-1", "ap-northeast-1"],
            home_region="us-east-1",
        )

        assert "us-east-1" not in result["helper"]["EnabledRegionsWithoutHomeRegion"]
        assert "eu-west-1" in result["helper"]["EnabledRegionsWithoutHomeRegion"]

    def test_uses_enabled_regions_as_customer_regions_by_default(self):
        """Uses enabled regions as customer regions when not specified."""
        result = get_region_info(
            enabled_regions=["us-east-1", "eu-west-1"],
            home_region="us-east-1",
        )

        assert result["helper"]["CustomerControlTowerRegions"] == ["us-east-1", "eu-west-1"]

    def test_uses_specified_customer_regions(self):
        """Uses specified customer regions when provided."""
        result = get_region_info(
            enabled_regions=["us-east-1", "eu-west-1", "ap-northeast-1"],
            home_region="us-east-1",
            customer_regions=["us-east-1", "eu-west-1"],
        )

        assert result["helper"]["CustomerControlTowerRegions"] == ["us-east-1", "eu-west-1"]
        assert result["helper"]["CustomerControlTowerRegionsWithoutHomeRegion"] == ["eu-west-1"]

    def test_returns_ssm_parameter_info(self):
        """Returns SSM parameter definitions for region data."""
        result = get_region_info(
            enabled_regions=["us-east-1", "eu-west-1"],
            home_region="us-east-1",
        )

        param_names = [p["name"] for p in result["info"]]
        assert f"{SRA_REGIONS_SSM_PATH}/enabled-regions" in param_names
        assert f"{SRA_REGIONS_SSM_PATH}/enabled-regions-without-home-region" in param_names
        assert f"{SRA_REGIONS_SSM_PATH}/customer-control-tower-regions" in param_names


class TestCreateSsmParameter:
    """Tests for create_ssm_parameter function."""

    def test_creates_string_parameter(self):
        """Creates a String SSM parameter."""
        mock_ssm_client = MagicMock()

        create_ssm_parameter(
            mock_ssm_client,
            name="/sra/test/param",
            value="test-value",
            parameter_type="String",
        )

        mock_ssm_client.put_parameter.assert_called_once_with(
            Name="/sra/test/param",
            Value="test-value",
            Type="String",
            Overwrite=True,
        )

    def test_creates_string_list_parameter(self):
        """Creates a StringList SSM parameter."""
        mock_ssm_client = MagicMock()

        create_ssm_parameter(
            mock_ssm_client,
            name="/sra/test/regions",
            value="us-east-1,eu-west-1",
            parameter_type="StringList",
        )

        mock_ssm_client.put_parameter.assert_called_once_with(
            Name="/sra/test/regions",
            Value="us-east-1,eu-west-1",
            Type="StringList",
            Overwrite=True,
        )

    def test_uses_empty_value_marker_for_empty_string(self):
        """Uses NONE for empty values."""
        mock_ssm_client = MagicMock()

        create_ssm_parameter(
            mock_ssm_client,
            name="/sra/test/param",
            value="",
            parameter_type="String",
        )

        mock_ssm_client.put_parameter.assert_called_once_with(
            Name="/sra/test/param",
            Value="NONE",
            Type="String",
            Overwrite=True,
        )


class TestAddTagsToSsmParameter:
    """Tests for add_tags_to_ssm_parameter function."""

    def test_adds_tags(self):
        """Adds tags to SSM parameter."""
        mock_ssm_client = MagicMock()
        tags = [{"Key": "sra-solution", "Value": "prerequisites"}]

        add_tags_to_ssm_parameter(mock_ssm_client, "/sra/test/param", tags)

        mock_ssm_client.add_tags_to_resource.assert_called_once_with(
            ResourceType="Parameter",
            ResourceId="/sra/test/param",
            Tags=tags,
        )


class TestCreateSsmParametersInRegions:
    """Tests for create_ssm_parameters_in_regions function."""

    def test_creates_parameters_in_multiple_regions(self):
        """Creates SSM parameters in all specified regions."""
        with patch("sra.prerequisites.boto3.Session") as mock_session_class:
            mock_ssm_client = MagicMock()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_ssm_client
            mock_session_class.return_value = mock_session

            params = [
                {"name": "/sra/test/param1", "value": "val1", "parameter_type": "String"},
                {"name": "/sra/test/param2", "value": "val2", "parameter_type": "String"},
            ]
            tags = [{"Key": "test", "Value": "value"}]
            regions = ["us-east-1", "eu-west-1"]

            create_ssm_parameters_in_regions(params, tags, regions)

            assert mock_session.client.call_count == 2
            assert mock_ssm_client.put_parameter.call_count == 4


class TestDeleteSsmParametersInRegions:
    """Tests for delete_ssm_parameters_in_regions function."""

    def test_deletes_parameters_in_regions(self):
        """Deletes SSM parameters in all specified regions."""
        with patch("sra.prerequisites.boto3.Session") as mock_session_class:
            mock_ssm_client = MagicMock()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_ssm_client
            mock_session_class.return_value = mock_session

            delete_ssm_parameters_in_regions(["us-east-1", "eu-west-1"])

            assert mock_ssm_client.delete_parameters.call_count == 2


class TestProcessCloudFormationEvent:
    """Tests for process_cloudformation_event function."""

    def test_processes_create_event(self):
        """Processes Create event and creates SSM parameters."""
        with patch("sra.prerequisites.get_organization_info") as mock_org, \
             patch("sra.prerequisites.create_ssm_parameters_in_regions") as mock_create:
            mock_org.return_value = {
                "info": [{"name": "/test", "value": "val", "parameter_type": "String"}],
                "helper": {"OrganizationId": "o-123"},
            }

            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "TAG_KEY": "sra-solution",
                    "TAG_VALUE": "prerequisites",
                    "HOME_REGION": "us-east-1",
                    "AUDIT_ACCOUNT_ID": "222222222222",
                    "LOG_ARCHIVE_ACCOUNT_ID": "333333333333",
                    "ENABLED_REGIONS": "us-east-1,eu-west-1",
                },
            }

            result = process_cloudformation_event(event)

            assert result == "MANAGEMENT-ACCOUNT-PARAMETERS"
            mock_create.assert_called_once()

    def test_processes_update_event(self):
        """Processes Update event and updates SSM parameters."""
        with patch("sra.prerequisites.get_organization_info") as mock_org, \
             patch("sra.prerequisites.create_ssm_parameters_in_regions") as mock_create:
            mock_org.return_value = {
                "info": [{"name": "/test", "value": "val", "parameter_type": "String"}],
                "helper": {"OrganizationId": "o-123"},
            }

            event = {
                "RequestType": "Update",
                "ResourceProperties": {
                    "TAG_KEY": "sra-solution",
                    "TAG_VALUE": "prerequisites",
                    "HOME_REGION": "us-east-1",
                },
            }

            result = process_cloudformation_event(event)

            assert result == "MANAGEMENT-ACCOUNT-PARAMETERS"
            mock_create.assert_called_once()

    def test_skips_delete_event(self):
        """Does not create parameters for Delete event."""
        with patch("sra.prerequisites.create_ssm_parameters_in_regions") as mock_create:
            event = {
                "RequestType": "Delete",
                "ResourceProperties": {
                    "TAG_KEY": "sra-solution",
                    "TAG_VALUE": "prerequisites",
                },
            }

            result = process_cloudformation_event(event)

            assert result == "MANAGEMENT-ACCOUNT-PARAMETERS"
            mock_create.assert_not_called()

    def test_parses_enabled_regions(self):
        """Parses enabled regions from comma-separated string."""
        with patch("sra.prerequisites.get_organization_info") as mock_org, \
             patch("sra.prerequisites.create_ssm_parameters_in_regions") as mock_create:
            mock_org.return_value = {
                "info": [],
                "helper": {},
            }

            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "TAG_KEY": "sra-solution",
                    "TAG_VALUE": "prerequisites",
                    "HOME_REGION": "us-east-1",
                    "ENABLED_REGIONS": "us-east-1, eu-west-1, ap-northeast-1",
                },
            }

            process_cloudformation_event(event)

            call_args = mock_create.call_args
            regions = call_args[0][2]
            assert regions == ["us-east-1", "eu-west-1", "ap-northeast-1"]


class TestLambdaHandler:
    """Tests for lambda_handler function."""

    def test_processes_event(self):
        """Processes CloudFormation event."""
        with patch("sra.prerequisites.process_cloudformation_event") as mock_process:
            mock_process.return_value = "MANAGEMENT-ACCOUNT-PARAMETERS"

            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "TAG_KEY": "sra-solution",
                    "TAG_VALUE": "prerequisites",
                },
            }

            result = lambda_handler(event, None)

            assert result == "MANAGEMENT-ACCOUNT-PARAMETERS"
            mock_process.assert_called_once_with(event)

    def test_raises_on_validation_error(self):
        """Raises ValueError on validation error."""
        event = {
            "RequestType": "Create",
            "ResourceProperties": {
                "TAG_KEY": "",
                "TAG_VALUE": "prerequisites",
            },
        }

        with pytest.raises(ValueError):
            lambda_handler(event, None)

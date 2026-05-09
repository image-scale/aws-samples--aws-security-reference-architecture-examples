"""Tests for the securityhub module."""

from unittest.mock import MagicMock, patch

import pytest

from sra.securityhub import (
    configure_securityhub,
    configure_standards,
    create_members,
    disable_organization_admin_account,
    disable_securityhub,
    enable_organization_admin_account,
    enable_securityhub,
    get_standards_config,
    lambda_handler,
    parse_bool,
    process_cloudformation_event,
    update_organization_configuration,
    validate_securityhub_params,
)
from sra.validation import ValidationError


class TestParseBool:
    """Tests for parse_bool function."""

    def test_parses_true(self):
        """Parses 'true' as True."""
        assert parse_bool("true") is True

    def test_parses_false(self):
        """Parses 'false' as False."""
        assert parse_bool("false") is False

    def test_case_insensitive(self):
        """Parsing is case insensitive."""
        assert parse_bool("TRUE") is True
        assert parse_bool("False") is False


class TestValidateSecurityhubParams:
    """Tests for validate_securityhub_params function."""

    def test_validates_valid_params(self):
        """Validates correct parameters without error."""
        params = {
            "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
            "CONFIGURATION_ROLE_NAME": "sra-securityhub-config",
            "ENABLE_CIS_STANDARD": "true",
            "ENABLE_PCI_STANDARD": "false",
            "ENABLE_NIST_STANDARD": "false",
            "ENABLE_SECURITY_BEST_PRACTICES_STANDARD": "true",
            "DISABLE_SECURITY_HUB": "false",
        }

        result = validate_securityhub_params(params)
        assert result == params

    def test_raises_for_invalid_account_id(self):
        """Raises ValidationError for invalid account ID."""
        params = {
            "DELEGATED_ADMIN_ACCOUNT_ID": "invalid",
            "CONFIGURATION_ROLE_NAME": "sra-securityhub-config",
        }

        with pytest.raises(ValidationError):
            validate_securityhub_params(params)


class TestGetStandardsConfig:
    """Tests for get_standards_config function."""

    def test_returns_standards_config(self):
        """Returns standards configuration from parameters."""
        params = {
            "ENABLE_SECURITY_BEST_PRACTICES_STANDARD": "true",
            "ENABLE_CIS_STANDARD": "true",
            "ENABLE_PCI_STANDARD": "false",
            "ENABLE_NIST_STANDARD": "false",
            "SECURITY_BEST_PRACTICES_VERSION": "1.0.0",
            "CIS_VERSION": "1.4.0",
        }

        result = get_standards_config(params)

        assert result["standards_to_enable"]["sbp"] is True
        assert result["standards_to_enable"]["cis"] is True
        assert result["standards_to_enable"]["pci"] is False
        assert result["sbp_version"] == "1.0.0"
        assert result["cis_version"] == "1.4.0"


class TestEnableOrganizationAdminAccount:
    """Tests for enable_organization_admin_account function."""

    def test_enables_admin_account(self):
        """Enables delegated admin account when not already enabled."""
        with patch("sra.securityhub.boto3.Session") as mock_session_class:
            mock_securityhub = MagicMock()
            mock_paginator = MagicMock()
            mock_paginator.paginate.return_value = [{"AdminAccounts": []}]
            mock_securityhub.get_paginator.return_value = mock_paginator
            mock_session = MagicMock()
            mock_session.client.return_value = mock_securityhub
            mock_session_class.return_value = mock_session

            enable_organization_admin_account("123456789012", ["us-east-1"])

            mock_securityhub.enable_organization_admin_account.assert_called_once_with(
                AdminAccountId="123456789012"
            )

    def test_skips_if_already_enabled(self):
        """Skips enabling if admin account already exists."""
        with patch("sra.securityhub.boto3.Session") as mock_session_class:
            mock_securityhub = MagicMock()
            mock_paginator = MagicMock()
            mock_paginator.paginate.return_value = [
                {"AdminAccounts": [{"AccountId": "123456789012", "Status": "ENABLED"}]}
            ]
            mock_securityhub.get_paginator.return_value = mock_paginator
            mock_session = MagicMock()
            mock_session.client.return_value = mock_securityhub
            mock_session_class.return_value = mock_session

            enable_organization_admin_account("123456789012", ["us-east-1"])

            mock_securityhub.enable_organization_admin_account.assert_not_called()


class TestDisableOrganizationAdminAccount:
    """Tests for disable_organization_admin_account function."""

    def test_disables_admin_account(self):
        """Disables delegated admin account."""
        with patch("sra.securityhub.boto3.Session") as mock_session_class:
            mock_securityhub = MagicMock()
            mock_paginator = MagicMock()
            mock_paginator.paginate.return_value = [
                {"AdminAccounts": [{"AccountId": "123456789012", "Status": "ENABLED"}]}
            ]
            mock_securityhub.get_paginator.return_value = mock_paginator
            mock_session = MagicMock()
            mock_session.client.return_value = mock_securityhub
            mock_session_class.return_value = mock_session

            disable_organization_admin_account(["us-east-1"])

            mock_securityhub.disable_organization_admin_account.assert_called_once_with(
                AdminAccountId="123456789012"
            )


class TestEnableSecurityhub:
    """Tests for enable_securityhub function."""

    def test_enables_securityhub(self):
        """Enables SecurityHub in specified regions."""
        with patch("sra.securityhub.boto3.Session") as mock_session_class:
            mock_securityhub = MagicMock()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_securityhub
            mock_session_class.return_value = mock_session

            enable_securityhub(["us-east-1"])

            mock_securityhub.enable_security_hub.assert_called_once_with(EnableDefaultStandards=False)

    def test_handles_already_enabled(self):
        """Handles SecurityHub already enabled."""
        with patch("sra.securityhub.boto3.Session") as mock_session_class:
            mock_securityhub = MagicMock()
            mock_securityhub.exceptions.ResourceConflictException = Exception
            mock_securityhub.enable_security_hub.side_effect = Exception()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_securityhub
            mock_session_class.return_value = mock_session

            enable_securityhub(["us-east-1"])


class TestConfigureStandards:
    """Tests for configure_standards function."""

    def test_enables_standards(self):
        """Enables configured standards."""
        mock_securityhub = MagicMock()
        standards_config = {
            "standards_to_enable": {"sbp": True, "cis": True, "pci": False, "nist": False},
            "sbp_version": "1.0.0",
            "cis_version": "1.2.0",
        }

        configure_standards(mock_securityhub, "us-east-1", standards_config)

        assert mock_securityhub.batch_enable_standards.call_count == 2


class TestDisableSecurityhub:
    """Tests for disable_securityhub function."""

    def test_disables_securityhub(self):
        """Disables SecurityHub in specified regions."""
        with patch("sra.securityhub.boto3.Session") as mock_session_class:
            mock_securityhub = MagicMock()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_securityhub
            mock_session_class.return_value = mock_session

            disable_securityhub(["us-east-1"])

            mock_securityhub.disable_security_hub.assert_called_once()

    def test_disassociates_members_when_requested(self):
        """Disassociates and deletes members when requested."""
        with patch("sra.securityhub.boto3.Session") as mock_session_class:
            mock_securityhub = MagicMock()
            mock_paginator = MagicMock()
            mock_paginator.paginate.return_value = [
                {"Members": [{"AccountId": "111111111111"}]}
            ]
            mock_securityhub.get_paginator.return_value = mock_paginator
            mock_session = MagicMock()
            mock_session.client.return_value = mock_securityhub
            mock_session_class.return_value = mock_session

            disable_securityhub(["us-east-1"], disassociate_members=True)

            mock_securityhub.disassociate_members.assert_called_once()
            mock_securityhub.delete_members.assert_called_once()


class TestCreateMembers:
    """Tests for create_members function."""

    def test_creates_member_accounts(self):
        """Creates SecurityHub member accounts."""
        mock_securityhub = MagicMock()
        mock_securityhub.create_members.return_value = {}
        accounts = [
            {"AccountId": "111111111111", "Email": "a@test.com"},
            {"AccountId": "222222222222", "Email": "b@test.com"},
        ]

        create_members(mock_securityhub, accounts)

        mock_securityhub.create_members.assert_called_once()
        call_args = mock_securityhub.create_members.call_args
        assert len(call_args.kwargs["AccountDetails"]) == 2

    def test_handles_empty_accounts(self):
        """Handles empty accounts list."""
        mock_securityhub = MagicMock()

        create_members(mock_securityhub, [])

        mock_securityhub.create_members.assert_not_called()


class TestUpdateOrganizationConfiguration:
    """Tests for update_organization_configuration function."""

    def test_updates_configuration(self):
        """Updates organization configuration."""
        mock_securityhub = MagicMock()

        update_organization_configuration(mock_securityhub, auto_enable=True)

        mock_securityhub.update_organization_configuration.assert_called_once_with(AutoEnable=True)


class TestConfigureSecurityhub:
    """Tests for configure_securityhub function."""

    def test_configures_securityhub_in_regions(self):
        """Configures SecurityHub in all specified regions."""
        with patch("sra.securityhub.get_organization_accounts") as mock_get_accounts:
            mock_get_accounts.return_value = [
                {"AccountId": "111111111111", "Email": "a@test.com"}
            ]

            mock_securityhub = MagicMock()
            mock_securityhub.create_members.return_value = {}
            mock_session = MagicMock()
            mock_session.client.return_value = mock_securityhub

            standards_config = {
                "standards_to_enable": {"sbp": True},
                "sbp_version": "1.0.0",
            }

            configure_securityhub(
                mock_session,
                "999999999999",
                ["us-east-1"],
                standards_config,
            )

            mock_securityhub.batch_enable_standards.assert_called()
            mock_securityhub.create_members.assert_called()
            mock_securityhub.update_organization_configuration.assert_called()


class TestProcessCloudFormationEvent:
    """Tests for process_cloudformation_event function."""

    def test_processes_create_event(self):
        """Processes Create event and configures SecurityHub."""
        with patch("sra.securityhub.process_create_update") as mock_create:
            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-securityhub-config",
                    "ENABLED_REGIONS": "us-east-1",
                },
            }

            result = process_cloudformation_event(event)

            assert "sra-securityhub-123456789012" in result
            mock_create.assert_called_once()

    def test_processes_update_event(self):
        """Processes Update event and updates SecurityHub."""
        with patch("sra.securityhub.process_create_update") as mock_create:
            event = {
                "RequestType": "Update",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-securityhub-config",
                },
            }

            result = process_cloudformation_event(event)

            assert "sra-securityhub-123456789012" in result
            mock_create.assert_called_once()

    def test_processes_delete_event(self):
        """Processes Delete event and removes SecurityHub."""
        with patch("sra.securityhub.process_delete") as mock_delete:
            event = {
                "RequestType": "Delete",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-securityhub-config",
                },
            }

            result = process_cloudformation_event(event)

            assert "sra-securityhub-123456789012" in result
            mock_delete.assert_called_once()

    def test_processes_disable_securityhub_on_update(self):
        """Processes Update event with DISABLE_SECURITY_HUB=true."""
        with patch("sra.securityhub.process_delete") as mock_delete:
            event = {
                "RequestType": "Update",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-securityhub-config",
                    "DISABLE_SECURITY_HUB": "true",
                },
            }

            process_cloudformation_event(event)

            mock_delete.assert_called_once()


class TestLambdaHandler:
    """Tests for lambda_handler function."""

    def test_processes_event(self):
        """Processes CloudFormation event."""
        with patch("sra.securityhub.process_cloudformation_event") as mock_process:
            mock_process.return_value = "sra-securityhub-123456789012"

            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-securityhub-config",
                },
            }

            result = lambda_handler(event, None)

            assert result == "sra-securityhub-123456789012"

    def test_raises_on_validation_error(self):
        """Raises ValueError on validation error."""
        event = {
            "RequestType": "Create",
            "ResourceProperties": {
                "DELEGATED_ADMIN_ACCOUNT_ID": "invalid",
                "CONFIGURATION_ROLE_NAME": "sra-securityhub-config",
            },
        }

        with pytest.raises(ValueError):
            lambda_handler(event, None)

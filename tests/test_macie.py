"""Tests for the macie module."""

from unittest.mock import MagicMock, patch

import pytest

from sra.macie import (
    configure_export_destination,
    configure_macie,
    create_members,
    disable_macie,
    disable_organization_admin_account,
    enable_macie,
    enable_organization_admin_account,
    lambda_handler,
    parse_bool,
    process_cloudformation_event,
    validate_macie_params,
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


class TestValidateMacieParams:
    """Tests for validate_macie_params function."""

    def test_validates_valid_params(self):
        """Validates correct parameters without error."""
        params = {
            "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
            "CONFIGURATION_ROLE_NAME": "sra-macie-config",
            "FINDING_PUBLISHING_FREQUENCY": "FIFTEEN_MINUTES",
            "DISABLE_MACIE": "false",
        }

        result = validate_macie_params(params)
        assert result == params

    def test_raises_for_invalid_account_id(self):
        """Raises ValidationError for invalid account ID."""
        params = {
            "DELEGATED_ADMIN_ACCOUNT_ID": "invalid",
            "CONFIGURATION_ROLE_NAME": "sra-macie-config",
        }

        with pytest.raises(ValidationError):
            validate_macie_params(params)

    def test_raises_for_invalid_frequency(self):
        """Raises ValidationError for invalid finding frequency."""
        params = {
            "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
            "CONFIGURATION_ROLE_NAME": "sra-macie-config",
            "FINDING_PUBLISHING_FREQUENCY": "INVALID",
        }

        with pytest.raises(ValidationError):
            validate_macie_params(params)


class TestEnableOrganizationAdminAccount:
    """Tests for enable_organization_admin_account function."""

    def test_enables_admin_account(self):
        """Enables delegated admin account when not already enabled."""
        with patch("sra.macie.boto3.Session") as mock_session_class:
            mock_macie = MagicMock()
            mock_macie.list_organization_admin_accounts.return_value = {
                "adminAccounts": []
            }
            mock_session = MagicMock()
            mock_session.client.return_value = mock_macie
            mock_session_class.return_value = mock_session

            enable_organization_admin_account("123456789012", ["us-east-1"])

            mock_macie.enable_organization_admin_account.assert_called_once_with(
                adminAccountId="123456789012"
            )

    def test_skips_if_already_enabled(self):
        """Skips enabling if admin account already exists."""
        with patch("sra.macie.boto3.Session") as mock_session_class:
            mock_macie = MagicMock()
            mock_macie.list_organization_admin_accounts.return_value = {
                "adminAccounts": [{"accountId": "123456789012"}]
            }
            mock_session = MagicMock()
            mock_session.client.return_value = mock_macie
            mock_session_class.return_value = mock_session

            enable_organization_admin_account("123456789012", ["us-east-1"])

            mock_macie.enable_organization_admin_account.assert_not_called()


class TestDisableOrganizationAdminAccount:
    """Tests for disable_organization_admin_account function."""

    def test_disables_admin_account(self):
        """Disables delegated admin account."""
        with patch("sra.macie.boto3.Session") as mock_session_class:
            mock_macie = MagicMock()
            mock_macie.list_organization_admin_accounts.return_value = {
                "adminAccounts": [
                    {"accountId": "123456789012", "status": "ENABLED"}
                ]
            }
            mock_session = MagicMock()
            mock_session.client.return_value = mock_macie
            mock_session_class.return_value = mock_session

            disable_organization_admin_account(["us-east-1"])

            mock_macie.disable_organization_admin_account.assert_called_once_with(
                adminAccountId="123456789012"
            )


class TestEnableMacie:
    """Tests for enable_macie function."""

    def test_enables_macie(self):
        """Enables Macie in specified regions."""
        with patch("sra.macie.boto3.Session") as mock_session_class:
            mock_macie = MagicMock()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_macie
            mock_session_class.return_value = mock_session

            enable_macie(["us-east-1"], "FIFTEEN_MINUTES")

            mock_macie.enable_macie.assert_called_once_with(
                findingPublishingFrequency="FIFTEEN_MINUTES",
                status="ENABLED",
            )

    def test_handles_already_enabled(self):
        """Handles Macie already enabled."""
        with patch("sra.macie.boto3.Session") as mock_session_class:
            mock_macie = MagicMock()
            mock_macie.exceptions.ConflictException = Exception
            mock_macie.enable_macie.side_effect = Exception()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_macie
            mock_session_class.return_value = mock_session

            enable_macie(["us-east-1"])


class TestDisableMacie:
    """Tests for disable_macie function."""

    def test_disables_macie(self):
        """Disables Macie in specified regions."""
        with patch("sra.macie.boto3.Session") as mock_session_class:
            mock_macie = MagicMock()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_macie
            mock_session_class.return_value = mock_session

            disable_macie(["us-east-1"])

            mock_macie.disable_macie.assert_called_once()

    def test_disassociates_members_when_requested(self):
        """Disassociates and deletes members when requested."""
        with patch("sra.macie.boto3.Session") as mock_session_class:
            mock_macie = MagicMock()
            mock_paginator = MagicMock()
            mock_paginator.paginate.return_value = [
                {"members": [{"accountId": "111111111111"}]}
            ]
            mock_macie.get_paginator.return_value = mock_paginator
            mock_session = MagicMock()
            mock_session.client.return_value = mock_macie
            mock_session_class.return_value = mock_session

            disable_macie(["us-east-1"], disassociate_members=True)

            mock_macie.disassociate_member.assert_called_once()
            mock_macie.delete_member.assert_called_once()


class TestCreateMembers:
    """Tests for create_members function."""

    def test_creates_member_accounts(self):
        """Creates Macie member accounts."""
        mock_macie = MagicMock()
        accounts = [
            {"AccountId": "111111111111", "Email": "a@test.com"},
            {"AccountId": "222222222222", "Email": "b@test.com"},
        ]

        with patch("sra.macie.sleep"):
            create_members(mock_macie, accounts)

        assert mock_macie.create_member.call_count == 2

    def test_handles_empty_accounts(self):
        """Handles empty accounts list."""
        mock_macie = MagicMock()

        create_members(mock_macie, [])

        mock_macie.create_member.assert_not_called()


class TestConfigureExportDestination:
    """Tests for configure_export_destination function."""

    def test_configures_export(self):
        """Configures S3 export destination."""
        mock_macie = MagicMock()

        configure_export_destination(
            mock_macie,
            "my-bucket",
            "arn:aws:kms:us-east-1:123456789012:key/abc",
        )

        mock_macie.put_classification_export_configuration.assert_called_once()
        call_args = mock_macie.put_classification_export_configuration.call_args
        config = call_args.kwargs["configuration"]["s3Destination"]
        assert config["bucketName"] == "my-bucket"
        assert "kmsKeyArn" in config


class TestConfigureMacie:
    """Tests for configure_macie function."""

    def test_configures_macie_in_regions(self):
        """Configures Macie in all specified regions."""
        with patch("sra.macie.get_organization_accounts") as mock_get_accounts, \
             patch("sra.macie.sleep"):
            mock_get_accounts.return_value = [
                {"AccountId": "111111111111", "Email": "a@test.com"}
            ]

            mock_macie = MagicMock()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_macie

            configure_macie(
                mock_session,
                "999999999999",
                ["us-east-1"],
                "my-bucket",
                "arn:aws:kms:us-east-1:123456789012:key/abc",
                "FIFTEEN_MINUTES",
            )

            mock_macie.update_macie_session.assert_called()
            mock_macie.put_classification_export_configuration.assert_called()
            mock_macie.update_organization_configuration.assert_called_once_with(autoEnable=True)


class TestProcessCloudFormationEvent:
    """Tests for process_cloudformation_event function."""

    def test_processes_create_event(self):
        """Processes Create event and configures Macie."""
        with patch("sra.macie.process_create_update") as mock_create:
            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-macie-config",
                    "ENABLED_REGIONS": "us-east-1",
                },
            }

            result = process_cloudformation_event(event)

            assert "sra-macie-123456789012" in result
            mock_create.assert_called_once()

    def test_processes_update_event(self):
        """Processes Update event and updates Macie."""
        with patch("sra.macie.process_create_update") as mock_create:
            event = {
                "RequestType": "Update",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-macie-config",
                },
            }

            result = process_cloudformation_event(event)

            assert "sra-macie-123456789012" in result
            mock_create.assert_called_once()

    def test_processes_delete_event(self):
        """Processes Delete event and removes Macie."""
        with patch("sra.macie.process_delete") as mock_delete:
            event = {
                "RequestType": "Delete",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-macie-config",
                },
            }

            result = process_cloudformation_event(event)

            assert "sra-macie-123456789012" in result
            mock_delete.assert_called_once()

    def test_processes_disable_macie_on_update(self):
        """Processes Update event with DISABLE_MACIE=true."""
        with patch("sra.macie.process_delete") as mock_delete:
            event = {
                "RequestType": "Update",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-macie-config",
                    "DISABLE_MACIE": "true",
                },
            }

            process_cloudformation_event(event)

            mock_delete.assert_called_once()


class TestLambdaHandler:
    """Tests for lambda_handler function."""

    def test_processes_event(self):
        """Processes CloudFormation event."""
        with patch("sra.macie.process_cloudformation_event") as mock_process:
            mock_process.return_value = "sra-macie-123456789012"

            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-macie-config",
                },
            }

            result = lambda_handler(event, None)

            assert result == "sra-macie-123456789012"

    def test_raises_on_validation_error(self):
        """Raises ValueError on validation error."""
        event = {
            "RequestType": "Create",
            "ResourceProperties": {
                "DELEGATED_ADMIN_ACCOUNT_ID": "invalid",
                "CONFIGURATION_ROLE_NAME": "sra-macie-config",
            },
        }

        with pytest.raises(ValueError):
            lambda_handler(event, None)

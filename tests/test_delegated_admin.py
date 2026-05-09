"""Tests for the delegated_admin module."""

from unittest.mock import MagicMock, patch

import pytest

from sra.delegated_admin import (
    VALID_SERVICE_PRINCIPALS,
    deregister_delegated_administrator,
    disable_aws_service_access,
    enable_aws_service_access,
    lambda_handler,
    list_delegated_administrators,
    parse_service_principal_list,
    process_cloudformation_event,
    process_create,
    process_delete,
    process_update,
    register_delegated_administrator,
    validate_delegated_admin_params,
    validate_service_principals,
)
from sra.validation import ValidationError


class TestValidateDelegatedAdminParams:
    """Tests for validate_delegated_admin_params function."""

    def test_validates_valid_params(self):
        """Validates correct parameters without error."""
        params = {"DELEGATED_ADMIN_ACCOUNT_ID": "123456789012"}

        result = validate_delegated_admin_params(params)
        assert result == params

    def test_raises_for_invalid_account_id(self):
        """Raises ValidationError for invalid account ID."""
        params = {"DELEGATED_ADMIN_ACCOUNT_ID": "invalid"}

        with pytest.raises(ValidationError):
            validate_delegated_admin_params(params)


class TestValidateServicePrincipals:
    """Tests for validate_service_principals function."""

    def test_validates_valid_principals(self):
        """Validates correct service principals without error."""
        principals = ["securityhub.amazonaws.com", "macie.amazonaws.com"]

        validate_service_principals(principals)

    def test_raises_for_invalid_principal(self):
        """Raises ValidationError for invalid service principal."""
        principals = ["invalid.amazonaws.com"]

        with pytest.raises(ValidationError):
            validate_service_principals(principals)


class TestParseServicePrincipalList:
    """Tests for parse_service_principal_list function."""

    def test_parses_list(self):
        """Parses list of service principals."""
        principals = ["securityhub.amazonaws.com", "macie.amazonaws.com"]

        result = parse_service_principal_list(principals)

        assert result == ["securityhub.amazonaws.com", "macie.amazonaws.com"]

    def test_parses_comma_separated_string(self):
        """Parses comma-separated string."""
        principals = "securityhub.amazonaws.com, macie.amazonaws.com"

        result = parse_service_principal_list(principals)

        assert result == ["securityhub.amazonaws.com", "macie.amazonaws.com"]

    def test_handles_empty_values(self):
        """Handles empty values in list."""
        principals = ["securityhub.amazonaws.com", "", "macie.amazonaws.com"]

        result = parse_service_principal_list(principals)

        assert result == ["securityhub.amazonaws.com", "macie.amazonaws.com"]


class TestEnableAwsServiceAccess:
    """Tests for enable_aws_service_access function."""

    def test_enables_service_access(self):
        """Enables AWS service access."""
        with patch("sra.delegated_admin.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            enable_aws_service_access("securityhub.amazonaws.com")

            mock_org_client.enable_aws_service_access.assert_called_once_with(
                ServicePrincipal="securityhub.amazonaws.com"
            )


class TestDisableAwsServiceAccess:
    """Tests for disable_aws_service_access function."""

    def test_disables_service_access(self):
        """Disables AWS service access."""
        with patch("sra.delegated_admin.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            disable_aws_service_access("securityhub.amazonaws.com")

            mock_org_client.disable_aws_service_access.assert_called_once_with(
                ServicePrincipal="securityhub.amazonaws.com"
            )


class TestRegisterDelegatedAdministrator:
    """Tests for register_delegated_administrator function."""

    def test_registers_delegated_admin(self):
        """Registers delegated administrator account."""
        with patch("sra.delegated_admin.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_org_client.list_delegated_administrators.return_value = {
                "DelegatedAdministrators": [{"Id": "123456789012"}]
            }
            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            register_delegated_administrator("123456789012", "securityhub.amazonaws.com")

            mock_org_client.register_delegated_administrator.assert_called_once_with(
                AccountId="123456789012",
                ServicePrincipal="securityhub.amazonaws.com",
            )

    def test_handles_already_registered(self):
        """Handles account already registered."""
        with patch("sra.delegated_admin.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_org_client.exceptions.AccountAlreadyRegisteredException = Exception
            mock_org_client.register_delegated_administrator.side_effect = Exception()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            register_delegated_administrator("123456789012", "securityhub.amazonaws.com")


class TestDeregisterDelegatedAdministrator:
    """Tests for deregister_delegated_administrator function."""

    def test_deregisters_delegated_admin(self):
        """Deregisters delegated administrator account."""
        with patch("sra.delegated_admin.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            deregister_delegated_administrator("123456789012", "securityhub.amazonaws.com")

            mock_org_client.deregister_delegated_administrator.assert_called_once_with(
                AccountId="123456789012",
                ServicePrincipal="securityhub.amazonaws.com",
            )

    def test_handles_not_registered(self):
        """Handles account not registered."""
        with patch("sra.delegated_admin.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_org_client.exceptions.AccountNotRegisteredException = Exception
            mock_org_client.deregister_delegated_administrator.side_effect = Exception()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            deregister_delegated_administrator("123456789012", "securityhub.amazonaws.com")


class TestListDelegatedAdministrators:
    """Tests for list_delegated_administrators function."""

    def test_lists_delegated_admins(self):
        """Lists delegated administrator accounts."""
        with patch("sra.delegated_admin.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_org_client.list_delegated_administrators.return_value = {
                "DelegatedAdministrators": [
                    {"Id": "123456789012", "Name": "Test Account"}
                ]
            }
            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            result = list_delegated_administrators()

            assert len(result) == 1
            assert result[0]["Id"] == "123456789012"

    def test_filters_by_service_principal(self):
        """Filters by service principal."""
        with patch("sra.delegated_admin.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_org_client.list_delegated_administrators.return_value = {
                "DelegatedAdministrators": []
            }
            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            list_delegated_administrators(service_principal="securityhub.amazonaws.com")

            mock_org_client.list_delegated_administrators.assert_called_once_with(
                ServicePrincipal="securityhub.amazonaws.com"
            )


class TestProcessCreate:
    """Tests for process_create function."""

    def test_enables_and_registers(self):
        """Enables service access and registers delegated admin."""
        with patch("sra.delegated_admin.enable_aws_service_access") as mock_enable, \
             patch("sra.delegated_admin.register_delegated_administrator") as mock_register:
            params = {"DELEGATED_ADMIN_ACCOUNT_ID": "123456789012"}
            principals = ["securityhub.amazonaws.com", "macie.amazonaws.com"]

            process_create(params, principals)

            assert mock_enable.call_count == 2
            assert mock_register.call_count == 2


class TestProcessUpdate:
    """Tests for process_update function."""

    def test_adds_new_principals(self):
        """Adds new service principals."""
        with patch("sra.delegated_admin.enable_aws_service_access") as mock_enable, \
             patch("sra.delegated_admin.register_delegated_administrator") as mock_register, \
             patch("sra.delegated_admin.deregister_delegated_administrator"), \
             patch("sra.delegated_admin.disable_aws_service_access"):
            params = {"DELEGATED_ADMIN_ACCOUNT_ID": "123456789012"}
            new_principals = ["securityhub.amazonaws.com", "macie.amazonaws.com"]
            old_principals = ["securityhub.amazonaws.com"]

            process_update(params, new_principals, old_principals)

            mock_enable.assert_called_once_with("macie.amazonaws.com")
            mock_register.assert_called_once()

    def test_removes_old_principals(self):
        """Removes old service principals."""
        with patch("sra.delegated_admin.enable_aws_service_access"), \
             patch("sra.delegated_admin.register_delegated_administrator"), \
             patch("sra.delegated_admin.deregister_delegated_administrator") as mock_deregister, \
             patch("sra.delegated_admin.disable_aws_service_access") as mock_disable:
            params = {"DELEGATED_ADMIN_ACCOUNT_ID": "123456789012"}
            new_principals = ["securityhub.amazonaws.com"]
            old_principals = ["securityhub.amazonaws.com", "macie.amazonaws.com"]

            process_update(params, new_principals, old_principals)

            mock_deregister.assert_called_once()
            mock_disable.assert_called_once()


class TestProcessDelete:
    """Tests for process_delete function."""

    def test_deregisters_and_disables(self):
        """Deregisters delegated admin and disables service access."""
        with patch("sra.delegated_admin.deregister_delegated_administrator") as mock_deregister, \
             patch("sra.delegated_admin.disable_aws_service_access") as mock_disable:
            params = {"DELEGATED_ADMIN_ACCOUNT_ID": "123456789012"}
            principals = ["securityhub.amazonaws.com", "macie.amazonaws.com"]

            process_delete(params, principals)

            assert mock_deregister.call_count == 2
            assert mock_disable.call_count == 2


class TestProcessCloudFormationEvent:
    """Tests for process_cloudformation_event function."""

    def test_processes_create_event(self):
        """Processes Create event."""
        with patch("sra.delegated_admin.process_create") as mock_create:
            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "AWS_SERVICE_PRINCIPAL_LIST": ["securityhub.amazonaws.com"],
                },
            }

            result = process_cloudformation_event(event)

            assert "DelegatedAdminResourceId-123456789012" in result
            mock_create.assert_called_once()

    def test_processes_update_event(self):
        """Processes Update event."""
        with patch("sra.delegated_admin.process_update") as mock_update:
            event = {
                "RequestType": "Update",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "AWS_SERVICE_PRINCIPAL_LIST": ["securityhub.amazonaws.com", "macie.amazonaws.com"],
                },
                "OldResourceProperties": {
                    "AWS_SERVICE_PRINCIPAL_LIST": ["securityhub.amazonaws.com"],
                },
            }

            result = process_cloudformation_event(event)

            assert "DelegatedAdminResourceId-123456789012" in result
            mock_update.assert_called_once()

    def test_processes_delete_event(self):
        """Processes Delete event."""
        with patch("sra.delegated_admin.process_delete") as mock_delete:
            event = {
                "RequestType": "Delete",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "AWS_SERVICE_PRINCIPAL_LIST": ["securityhub.amazonaws.com"],
                },
            }

            result = process_cloudformation_event(event)

            assert "DelegatedAdminResourceId-123456789012" in result
            mock_delete.assert_called_once()


class TestLambdaHandler:
    """Tests for lambda_handler function."""

    def test_processes_event(self):
        """Processes CloudFormation event."""
        with patch("sra.delegated_admin.process_cloudformation_event") as mock_process:
            mock_process.return_value = "DelegatedAdminResourceId-123456789012"

            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "AWS_SERVICE_PRINCIPAL_LIST": ["securityhub.amazonaws.com"],
                },
            }

            result = lambda_handler(event, None)

            assert result == "DelegatedAdminResourceId-123456789012"

    def test_raises_on_validation_error(self):
        """Raises ValueError on validation error."""
        event = {
            "RequestType": "Create",
            "ResourceProperties": {
                "DELEGATED_ADMIN_ACCOUNT_ID": "invalid",
                "AWS_SERVICE_PRINCIPAL_LIST": ["securityhub.amazonaws.com"],
            },
        }

        with pytest.raises(ValueError):
            lambda_handler(event, None)

    def test_raises_on_invalid_principal(self):
        """Raises ValueError on invalid service principal."""
        event = {
            "RequestType": "Create",
            "ResourceProperties": {
                "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                "AWS_SERVICE_PRINCIPAL_LIST": ["invalid.amazonaws.com"],
            },
        }

        with pytest.raises(ValueError):
            lambda_handler(event, None)


class TestValidServicePrincipals:
    """Tests for valid service principals constant."""

    def test_includes_security_services(self):
        """Includes common security service principals."""
        assert "securityhub.amazonaws.com" in VALID_SERVICE_PRINCIPALS
        assert "guardduty.amazonaws.com" in VALID_SERVICE_PRINCIPALS
        assert "macie.amazonaws.com" in VALID_SERVICE_PRINCIPALS
        assert "access-analyzer.amazonaws.com" in VALID_SERVICE_PRINCIPALS
        assert "config.amazonaws.com" in VALID_SERVICE_PRINCIPALS

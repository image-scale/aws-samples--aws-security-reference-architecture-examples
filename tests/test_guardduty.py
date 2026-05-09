"""Tests for the guardduty module."""

from unittest.mock import MagicMock, patch

import pytest

from sra.guardduty import (
    build_features_config,
    build_org_features_config,
    check_for_detectors,
    configure_guardduty,
    create_members,
    create_publishing_destination,
    delete_detector,
    disable_organization_admin_account,
    enable_organization_admin_account,
    get_detector_id,
    lambda_handler,
    parse_bool,
    process_cloudformation_event,
    update_guardduty_configuration,
    update_member_detectors,
    validate_guardduty_params,
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


class TestValidateGuarddutyParams:
    """Tests for validate_guardduty_params function."""

    def test_validates_valid_params(self):
        """Validates correct parameters without error."""
        params = {
            "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
            "CONFIGURATION_ROLE_NAME": "sra-guardduty-config",
            "AUTO_ENABLE_S3_LOGS": "true",
            "ENABLE_EKS_AUDIT_LOGS": "true",
            "AUTO_ENABLE_MALWARE_PROTECTION": "false",
            "ENABLE_RUNTIME_MONITORING": "true",
            "FINDING_PUBLISHING_FREQUENCY": "FIFTEEN_MINUTES",
        }

        result = validate_guardduty_params(params)
        assert result == params

    def test_raises_for_invalid_account_id(self):
        """Raises ValidationError for invalid account ID."""
        params = {
            "DELEGATED_ADMIN_ACCOUNT_ID": "invalid",
            "CONFIGURATION_ROLE_NAME": "sra-guardduty-config",
        }

        with pytest.raises(ValidationError):
            validate_guardduty_params(params)

    def test_raises_for_invalid_frequency(self):
        """Raises ValidationError for invalid finding frequency."""
        params = {
            "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
            "CONFIGURATION_ROLE_NAME": "sra-guardduty-config",
            "FINDING_PUBLISHING_FREQUENCY": "INVALID",
        }

        with pytest.raises(ValidationError):
            validate_guardduty_params(params)


class TestEnableOrganizationAdminAccount:
    """Tests for enable_organization_admin_account function."""

    def test_enables_admin_account(self):
        """Enables delegated admin account when not already enabled."""
        with patch("sra.guardduty.boto3.Session") as mock_session_class:
            mock_guardduty = MagicMock()
            mock_guardduty.list_organization_admin_accounts.return_value = {
                "AdminAccounts": []
            }
            mock_session = MagicMock()
            mock_session.client.return_value = mock_guardduty
            mock_session_class.return_value = mock_session

            enable_organization_admin_account("123456789012", ["us-east-1"])

            mock_guardduty.enable_organization_admin_account.assert_called_once_with(
                AdminAccountId="123456789012"
            )

    def test_skips_if_already_enabled(self):
        """Skips enabling if admin account already exists."""
        with patch("sra.guardduty.boto3.Session") as mock_session_class:
            mock_guardduty = MagicMock()
            mock_guardduty.list_organization_admin_accounts.return_value = {
                "AdminAccounts": [{"AdminAccountId": "123456789012"}]
            }
            mock_session = MagicMock()
            mock_session.client.return_value = mock_guardduty
            mock_session_class.return_value = mock_session

            enable_organization_admin_account("123456789012", ["us-east-1"])

            mock_guardduty.enable_organization_admin_account.assert_not_called()


class TestDisableOrganizationAdminAccount:
    """Tests for disable_organization_admin_account function."""

    def test_disables_admin_account(self):
        """Disables delegated admin account."""
        with patch("sra.guardduty.boto3.Session") as mock_session_class:
            mock_guardduty = MagicMock()
            mock_guardduty.list_organization_admin_accounts.return_value = {
                "AdminAccounts": [
                    {"AdminAccountId": "123456789012", "AdminStatus": "ENABLED"}
                ]
            }
            mock_session = MagicMock()
            mock_session.client.return_value = mock_guardduty
            mock_session_class.return_value = mock_session

            disable_organization_admin_account(["us-east-1"])

            mock_guardduty.disable_organization_admin_account.assert_called_once_with(
                AdminAccountId="123456789012"
            )


class TestGetDetectorId:
    """Tests for get_detector_id function."""

    def test_returns_existing_detector(self):
        """Returns existing detector ID."""
        mock_guardduty = MagicMock()
        mock_guardduty.list_detectors.return_value = {
            "DetectorIds": ["abc123"]
        }

        result = get_detector_id(mock_guardduty)

        assert result == "abc123"

    def test_returns_none_when_no_detector(self):
        """Returns None when no detector exists."""
        mock_guardduty = MagicMock()
        mock_guardduty.list_detectors.return_value = {"DetectorIds": []}

        result = get_detector_id(mock_guardduty)

        assert result is None

    def test_creates_detector_when_missing(self):
        """Creates detector when missing and create_if_missing is True."""
        mock_guardduty = MagicMock()
        mock_guardduty.list_detectors.return_value = {"DetectorIds": []}
        mock_guardduty.create_detector.return_value = {"DetectorId": "new123"}

        result = get_detector_id(mock_guardduty, create_if_missing=True)

        assert result == "new123"
        mock_guardduty.create_detector.assert_called_once_with(Enable=True)


class TestCheckForDetectors:
    """Tests for check_for_detectors function."""

    def test_returns_true_when_detectors_exist(self):
        """Returns True when detectors exist in all regions."""
        mock_guardduty = MagicMock()
        mock_guardduty.list_detectors.return_value = {"DetectorIds": ["abc123"]}
        mock_session = MagicMock()
        mock_session.client.return_value = mock_guardduty

        result = check_for_detectors(mock_session, ["us-east-1", "eu-west-1"])

        assert result is True

    def test_returns_false_when_detector_missing(self):
        """Returns False when detector is missing in any region."""
        mock_guardduty = MagicMock()
        mock_guardduty.list_detectors.return_value = {"DetectorIds": []}
        mock_session = MagicMock()
        mock_session.client.return_value = mock_guardduty

        result = check_for_detectors(mock_session, ["us-east-1"])

        assert result is False


class TestBuildFeaturesConfig:
    """Tests for build_features_config function."""

    def test_builds_enabled_features(self):
        """Builds features config with enabled status."""
        features = {
            "S3_DATA_EVENTS": True,
            "EKS_AUDIT_LOGS": False,
        }

        result = build_features_config(features)

        assert {"Name": "S3_DATA_EVENTS", "Status": "ENABLED"} in result
        assert {"Name": "EKS_AUDIT_LOGS", "Status": "DISABLED"} in result

    def test_handles_runtime_monitoring(self):
        """Handles RUNTIME_MONITORING with AdditionalConfiguration."""
        features = {"RUNTIME_MONITORING": True}

        result = build_features_config(features)

        runtime_config = next(f for f in result if f["Name"] == "RUNTIME_MONITORING")
        assert runtime_config["Status"] == "ENABLED"
        assert "AdditionalConfiguration" in runtime_config


class TestBuildOrgFeaturesConfig:
    """Tests for build_org_features_config function."""

    def test_builds_org_features_with_auto_enable(self):
        """Builds org features config with AutoEnable."""
        features = {
            "S3_DATA_EVENTS": True,
            "EKS_AUDIT_LOGS": False,
        }

        result = build_org_features_config(features)

        assert {"Name": "S3_DATA_EVENTS", "AutoEnable": "ALL"} in result
        assert {"Name": "EKS_AUDIT_LOGS", "AutoEnable": "NONE"} in result


class TestUpdateGuarddutyConfiguration:
    """Tests for update_guardduty_configuration function."""

    def test_updates_detector_and_org_config(self):
        """Updates both detector and organization configuration."""
        mock_guardduty = MagicMock()
        features = {"S3_DATA_EVENTS": True}

        update_guardduty_configuration(
            mock_guardduty,
            "detector123",
            features,
            "FIFTEEN_MINUTES",
        )

        mock_guardduty.update_detector.assert_called_once()
        mock_guardduty.update_organization_configuration.assert_called_once()


class TestCreatePublishingDestination:
    """Tests for create_publishing_destination function."""

    def test_creates_new_destination(self):
        """Creates publishing destination when none exists."""
        mock_guardduty = MagicMock()
        mock_guardduty.list_publishing_destinations.return_value = {"Destinations": []}

        create_publishing_destination(
            mock_guardduty,
            "detector123",
            "arn:aws:s3:::my-bucket",
            "arn:aws:kms:us-east-1:123456789012:key/abc",
        )

        mock_guardduty.create_publishing_destination.assert_called_once()

    def test_updates_existing_destination(self):
        """Updates publishing destination when one exists."""
        mock_guardduty = MagicMock()
        mock_guardduty.list_publishing_destinations.return_value = {
            "Destinations": [{"DestinationId": "dest123"}]
        }

        create_publishing_destination(
            mock_guardduty,
            "detector123",
            "arn:aws:s3:::my-bucket",
            "arn:aws:kms:us-east-1:123456789012:key/abc",
        )

        mock_guardduty.update_publishing_destination.assert_called_once()


class TestCreateMembers:
    """Tests for create_members function."""

    def test_creates_member_accounts(self):
        """Creates GuardDuty member accounts."""
        mock_guardduty = MagicMock()
        mock_guardduty.create_members.return_value = {}
        accounts = [
            {"AccountId": "111111111111", "Email": "a@test.com"},
            {"AccountId": "222222222222", "Email": "b@test.com"},
        ]

        create_members(mock_guardduty, "detector123", accounts)

        mock_guardduty.create_members.assert_called_once()
        call_args = mock_guardduty.create_members.call_args
        assert len(call_args.kwargs["AccountDetails"]) == 2

    def test_handles_empty_accounts(self):
        """Handles empty accounts list."""
        mock_guardduty = MagicMock()

        create_members(mock_guardduty, "detector123", [])

        mock_guardduty.create_members.assert_not_called()


class TestUpdateMemberDetectors:
    """Tests for update_member_detectors function."""

    def test_updates_member_configurations(self):
        """Updates member detector configurations."""
        mock_guardduty = MagicMock()
        mock_guardduty.update_member_detectors.return_value = {}
        account_ids = ["111111111111", "222222222222"]
        features = {"S3_DATA_EVENTS": True}

        update_member_detectors(mock_guardduty, "detector123", account_ids, features)

        mock_guardduty.update_member_detectors.assert_called_once()


class TestConfigureGuardduty:
    """Tests for configure_guardduty function."""

    def test_configures_guardduty_in_regions(self):
        """Configures GuardDuty in all specified regions."""
        with patch("sra.guardduty.get_organization_accounts") as mock_get_accounts, \
             patch("sra.guardduty.get_account_ids") as mock_get_ids:
            mock_get_accounts.return_value = [
                {"AccountId": "111111111111", "Email": "a@test.com"}
            ]
            mock_get_ids.return_value = ["111111111111"]

            mock_guardduty = MagicMock()
            mock_guardduty.list_detectors.return_value = {"DetectorIds": ["det123"]}
            mock_guardduty.list_publishing_destinations.return_value = {"Destinations": []}
            mock_guardduty.create_members.return_value = {}
            mock_guardduty.update_member_detectors.return_value = {}

            mock_session = MagicMock()
            mock_session.client.return_value = mock_guardduty

            configure_guardduty(
                mock_session,
                "999999999999",
                {"S3_DATA_EVENTS": True},
                ["us-east-1"],
                "FIFTEEN_MINUTES",
                "arn:aws:kms:us-east-1:123456789012:key/abc",
                "arn:aws:s3:::bucket",
            )

            mock_guardduty.update_detector.assert_called()
            mock_guardduty.create_publishing_destination.assert_called()


class TestDeleteDetector:
    """Tests for delete_detector function."""

    def test_deletes_detector_with_members(self):
        """Deletes detector after disassociating members."""
        mock_guardduty = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [
            {"Members": [{"AccountId": "111111111111"}]}
        ]
        mock_guardduty.get_paginator.return_value = mock_paginator

        delete_detector(mock_guardduty, "detector123", disassociate_members=True)

        mock_guardduty.disassociate_members.assert_called_once()
        mock_guardduty.delete_members.assert_called_once()
        mock_guardduty.delete_detector.assert_called_once_with(DetectorId="detector123")


class TestProcessCloudFormationEvent:
    """Tests for process_cloudformation_event function."""

    def test_processes_create_event(self):
        """Processes Create event and configures GuardDuty."""
        with patch("sra.guardduty.process_create_update") as mock_create:
            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-guardduty-config",
                    "ENABLED_REGIONS": "us-east-1",
                },
            }

            result = process_cloudformation_event(event)

            assert "sra-guardduty-123456789012" in result
            mock_create.assert_called_once()

    def test_processes_update_event(self):
        """Processes Update event and updates GuardDuty."""
        with patch("sra.guardduty.process_create_update") as mock_create:
            event = {
                "RequestType": "Update",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-guardduty-config",
                },
            }

            result = process_cloudformation_event(event)

            assert "sra-guardduty-123456789012" in result
            mock_create.assert_called_once()

    def test_processes_delete_event(self):
        """Processes Delete event and removes GuardDuty."""
        with patch("sra.guardduty.process_delete") as mock_delete:
            event = {
                "RequestType": "Delete",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-guardduty-config",
                },
            }

            result = process_cloudformation_event(event)

            assert "sra-guardduty-123456789012" in result
            mock_delete.assert_called_once()


class TestLambdaHandler:
    """Tests for lambda_handler function."""

    def test_processes_event(self):
        """Processes CloudFormation event."""
        with patch("sra.guardduty.process_cloudformation_event") as mock_process:
            mock_process.return_value = "sra-guardduty-123456789012"

            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "DELEGATED_ADMIN_ACCOUNT_ID": "123456789012",
                    "CONFIGURATION_ROLE_NAME": "sra-guardduty-config",
                },
            }

            result = lambda_handler(event, None)

            assert result == "sra-guardduty-123456789012"

    def test_raises_on_validation_error(self):
        """Raises ValueError on validation error."""
        event = {
            "RequestType": "Create",
            "ResourceProperties": {
                "DELEGATED_ADMIN_ACCOUNT_ID": "invalid",
                "CONFIGURATION_ROLE_NAME": "sra-guardduty-config",
            },
        }

        with pytest.raises(ValueError):
            lambda_handler(event, None)

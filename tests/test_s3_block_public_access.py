"""Tests for the s3_block_public_access module."""

from unittest.mock import MagicMock, patch

import pytest

from sra.s3_block_public_access import (
    configure_bpa_for_regions,
    get_block_public_access,
    lambda_handler,
    parse_bool,
    process_cloudformation_event,
    set_block_public_access,
    validate_s3_bpa_params,
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


class TestValidateS3BpaParams:
    """Tests for validate_s3_bpa_params function."""

    def test_validates_valid_params(self):
        """Validates correct parameters without error."""
        params = {
            "BLOCK_PUBLIC_ACLS": "true",
            "IGNORE_PUBLIC_ACLS": "true",
            "BLOCK_PUBLIC_POLICY": "true",
            "RESTRICT_PUBLIC_BUCKETS": "true",
        }

        result = validate_s3_bpa_params(params)
        assert result == params

    def test_validates_false_values(self):
        """Validates 'false' values without error."""
        params = {
            "BLOCK_PUBLIC_ACLS": "false",
            "IGNORE_PUBLIC_ACLS": "false",
            "BLOCK_PUBLIC_POLICY": "false",
            "RESTRICT_PUBLIC_BUCKETS": "false",
        }

        result = validate_s3_bpa_params(params)
        assert result == params

    def test_raises_for_invalid_value(self):
        """Raises ValidationError for invalid boolean value."""
        params = {
            "BLOCK_PUBLIC_ACLS": "yes",
            "IGNORE_PUBLIC_ACLS": "true",
            "BLOCK_PUBLIC_POLICY": "true",
            "RESTRICT_PUBLIC_BUCKETS": "true",
        }

        with pytest.raises(ValidationError):
            validate_s3_bpa_params(params)


class TestSetBlockPublicAccess:
    """Tests for set_block_public_access function."""

    def test_sets_all_bpa_settings(self):
        """Sets all four BPA settings via S3Control API."""
        with patch("sra.s3_block_public_access.boto3.Session") as mock_session_class:
            mock_s3_control = MagicMock()
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

            mock_session = MagicMock()
            mock_session.client.side_effect = lambda service, **kwargs: {
                "s3control": mock_s3_control,
                "sts": mock_sts,
            }[service]
            mock_session_class.return_value = mock_session

            set_block_public_access(
                block_public_acls=True,
                ignore_public_acls=True,
                block_public_policy=True,
                restrict_public_buckets=True,
            )

            mock_s3_control.put_public_access_block.assert_called_once_with(
                AccountId="123456789012",
                PublicAccessBlockConfiguration={
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                },
            )

    def test_sets_individual_settings(self):
        """Can set individual BPA settings independently."""
        with patch("sra.s3_block_public_access.boto3.Session") as mock_session_class:
            mock_s3_control = MagicMock()
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

            mock_session = MagicMock()
            mock_session.client.side_effect = lambda service, **kwargs: {
                "s3control": mock_s3_control,
                "sts": mock_sts,
            }[service]
            mock_session_class.return_value = mock_session

            set_block_public_access(
                block_public_acls=True,
                ignore_public_acls=False,
                block_public_policy=True,
                restrict_public_buckets=False,
            )

            call_kwargs = mock_s3_control.put_public_access_block.call_args.kwargs
            config = call_kwargs["PublicAccessBlockConfiguration"]
            assert config["BlockPublicAcls"] is True
            assert config["IgnorePublicAcls"] is False
            assert config["BlockPublicPolicy"] is True
            assert config["RestrictPublicBuckets"] is False


class TestGetBlockPublicAccess:
    """Tests for get_block_public_access function."""

    def test_returns_current_settings(self):
        """Returns current BPA settings."""
        with patch("sra.s3_block_public_access.boto3.Session") as mock_session_class:
            mock_s3_control = MagicMock()
            mock_s3_control.get_public_access_block.return_value = {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": False,
                    "RestrictPublicBuckets": True,
                }
            }
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

            mock_session = MagicMock()
            mock_session.client.side_effect = lambda service, **kwargs: {
                "s3control": mock_s3_control,
                "sts": mock_sts,
            }[service]
            mock_session_class.return_value = mock_session

            result = get_block_public_access()

            assert result["BlockPublicAcls"] is True
            assert result["BlockPublicPolicy"] is False

    def test_returns_empty_dict_when_no_config(self):
        """Returns empty dict when no BPA config exists."""
        with patch("sra.s3_block_public_access.boto3.Session") as mock_session_class:
            mock_s3_control = MagicMock()
            mock_s3_control.exceptions.NoSuchPublicAccessBlockConfiguration = Exception
            mock_s3_control.get_public_access_block.side_effect = Exception()
            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123456789012"}

            mock_session = MagicMock()
            mock_session.client.side_effect = lambda service, **kwargs: {
                "s3control": mock_s3_control,
                "sts": mock_sts,
            }[service]
            mock_session_class.return_value = mock_session

            result = get_block_public_access()

            assert result == {}


class TestConfigureBpaForRegions:
    """Tests for configure_bpa_for_regions function."""

    def test_configures_bpa_with_params(self):
        """Configures BPA using provided parameters."""
        with patch("sra.s3_block_public_access.set_block_public_access") as mock_set:
            params = {
                "BLOCK_PUBLIC_ACLS": "true",
                "IGNORE_PUBLIC_ACLS": "false",
                "BLOCK_PUBLIC_POLICY": "true",
                "RESTRICT_PUBLIC_BUCKETS": "false",
            }

            configure_bpa_for_regions(params, ["us-east-1", "eu-west-1"])

            mock_set.assert_called_once_with(
                block_public_acls=True,
                ignore_public_acls=False,
                block_public_policy=True,
                restrict_public_buckets=False,
                session=None,
            )

    def test_uses_default_values(self):
        """Uses default values when parameters not provided."""
        with patch("sra.s3_block_public_access.set_block_public_access") as mock_set:
            configure_bpa_for_regions({}, ["us-east-1"])

            mock_set.assert_called_once_with(
                block_public_acls=True,
                ignore_public_acls=True,
                block_public_policy=True,
                restrict_public_buckets=True,
                session=None,
            )


class TestProcessCloudFormationEvent:
    """Tests for process_cloudformation_event function."""

    def test_processes_create_event(self):
        """Processes Create event and configures BPA."""
        with patch("sra.s3_block_public_access.configure_bpa_for_regions") as mock_config:
            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "BLOCK_PUBLIC_ACLS": "true",
                    "IGNORE_PUBLIC_ACLS": "true",
                    "BLOCK_PUBLIC_POLICY": "true",
                    "RESTRICT_PUBLIC_BUCKETS": "true",
                    "ENABLED_REGIONS": "us-east-1,eu-west-1",
                },
            }

            process_cloudformation_event(event)

            mock_config.assert_called_once()

    def test_processes_update_event(self):
        """Processes Update event and configures BPA."""
        with patch("sra.s3_block_public_access.configure_bpa_for_regions") as mock_config:
            event = {
                "RequestType": "Update",
                "ResourceProperties": {
                    "BLOCK_PUBLIC_ACLS": "true",
                    "IGNORE_PUBLIC_ACLS": "true",
                    "BLOCK_PUBLIC_POLICY": "true",
                    "RESTRICT_PUBLIC_BUCKETS": "true",
                },
            }

            process_cloudformation_event(event)

            mock_config.assert_called_once()

    def test_skips_delete_event(self):
        """Does not configure BPA for Delete event."""
        with patch("sra.s3_block_public_access.configure_bpa_for_regions") as mock_config:
            event = {
                "RequestType": "Delete",
                "ResourceProperties": {},
            }

            process_cloudformation_event(event)

            mock_config.assert_not_called()

    def test_returns_physical_resource_id(self):
        """Returns physical resource ID."""
        with patch("sra.s3_block_public_access.configure_bpa_for_regions"):
            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "BLOCK_PUBLIC_ACLS": "true",
                    "IGNORE_PUBLIC_ACLS": "true",
                    "BLOCK_PUBLIC_POLICY": "true",
                    "RESTRICT_PUBLIC_BUCKETS": "true",
                },
            }

            result = process_cloudformation_event(event)

            assert "sra-s3-block-public-access" in result


class TestLambdaHandler:
    """Tests for lambda_handler function."""

    def test_processes_event(self):
        """Processes CloudFormation event."""
        with patch("sra.s3_block_public_access.process_cloudformation_event") as mock_process:
            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "BLOCK_PUBLIC_ACLS": "true",
                    "IGNORE_PUBLIC_ACLS": "true",
                    "BLOCK_PUBLIC_POLICY": "true",
                    "RESTRICT_PUBLIC_BUCKETS": "true",
                },
            }

            lambda_handler(event, None)

            mock_process.assert_called_once_with(event)

    def test_raises_on_validation_error(self):
        """Raises ValueError on validation error."""
        event = {
            "RequestType": "Create",
            "ResourceProperties": {
                "BLOCK_PUBLIC_ACLS": "invalid",
                "IGNORE_PUBLIC_ACLS": "true",
                "BLOCK_PUBLIC_POLICY": "true",
                "RESTRICT_PUBLIC_BUCKETS": "true",
            },
        }

        with pytest.raises(ValueError):
            lambda_handler(event, None)

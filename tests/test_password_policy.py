"""Tests for the password_policy module."""

from unittest.mock import MagicMock, patch

import pytest

from sra.password_policy import (
    generate_physical_resource_id,
    get_password_policy,
    lambda_handler,
    parse_bool,
    process_cloudformation_event,
    update_password_policy,
    validate_password_policy_params,
)
from sra.validation import ValidationError


class TestParseBool:
    """Tests for parse_bool function."""

    def test_parses_true_lowercase(self):
        """Parses 'true' as True."""
        assert parse_bool("true") is True

    def test_parses_false_lowercase(self):
        """Parses 'false' as False."""
        assert parse_bool("false") is False

    def test_parses_true_uppercase(self):
        """Parses 'TRUE' as True (case insensitive)."""
        assert parse_bool("TRUE") is True

    def test_parses_false_mixed_case(self):
        """Parses 'False' as False (case insensitive)."""
        assert parse_bool("False") is False


class TestValidatePasswordPolicyParams:
    """Tests for validate_password_policy_params function."""

    def test_validates_valid_params(self):
        """Validates correct parameters without error."""
        params = {
            "MAX_PASSWORD_AGE": "90",
            "MINIMUM_PASSWORD_LENGTH": "14",
            "PASSWORD_REUSE_PREVENTION": "24",
            "ALLOW_USERS_TO_CHANGE_PASSWORD": "true",
            "HARD_EXPIRY": "false",
            "REQUIRE_LOWERCASE_CHARACTERS": "true",
            "REQUIRE_NUMBERS": "true",
            "REQUIRE_SYMBOLS": "true",
            "REQUIRE_UPPERCASE_CHARACTERS": "true",
        }

        result = validate_password_policy_params(params)
        assert result == params

    def test_raises_for_invalid_max_age(self):
        """Raises ValidationError for invalid max password age."""
        params = {
            "MAX_PASSWORD_AGE": "0",
            "MINIMUM_PASSWORD_LENGTH": "14",
            "PASSWORD_REUSE_PREVENTION": "24",
            "ALLOW_USERS_TO_CHANGE_PASSWORD": "true",
            "HARD_EXPIRY": "false",
            "REQUIRE_LOWERCASE_CHARACTERS": "true",
            "REQUIRE_NUMBERS": "true",
            "REQUIRE_SYMBOLS": "true",
            "REQUIRE_UPPERCASE_CHARACTERS": "true",
        }

        with pytest.raises(ValidationError):
            validate_password_policy_params(params)

    def test_raises_for_invalid_min_length(self):
        """Raises ValidationError for invalid minimum password length."""
        params = {
            "MAX_PASSWORD_AGE": "90",
            "MINIMUM_PASSWORD_LENGTH": "5",
            "PASSWORD_REUSE_PREVENTION": "24",
            "ALLOW_USERS_TO_CHANGE_PASSWORD": "true",
            "HARD_EXPIRY": "false",
            "REQUIRE_LOWERCASE_CHARACTERS": "true",
            "REQUIRE_NUMBERS": "true",
            "REQUIRE_SYMBOLS": "true",
            "REQUIRE_UPPERCASE_CHARACTERS": "true",
        }

        with pytest.raises(ValidationError):
            validate_password_policy_params(params)


class TestUpdatePasswordPolicy:
    """Tests for update_password_policy function."""

    def test_updates_password_policy(self):
        """Calls IAM update_account_password_policy with correct parameters."""
        with patch("sra.password_policy.boto3.Session") as mock_session_class:
            mock_iam_client = MagicMock()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_iam_client
            mock_session_class.return_value = mock_session

            params = {
                "MAX_PASSWORD_AGE": "90",
                "MINIMUM_PASSWORD_LENGTH": "14",
                "PASSWORD_REUSE_PREVENTION": "24",
                "ALLOW_USERS_TO_CHANGE_PASSWORD": "true",
                "HARD_EXPIRY": "false",
                "REQUIRE_LOWERCASE_CHARACTERS": "true",
                "REQUIRE_NUMBERS": "true",
                "REQUIRE_SYMBOLS": "true",
                "REQUIRE_UPPERCASE_CHARACTERS": "true",
            }

            update_password_policy(params)

            mock_iam_client.update_account_password_policy.assert_called_once_with(
                AllowUsersToChangePassword=True,
                HardExpiry=False,
                MaxPasswordAge=90,
                MinimumPasswordLength=14,
                PasswordReusePrevention=24,
                RequireLowercaseCharacters=True,
                RequireNumbers=True,
                RequireSymbols=True,
                RequireUppercaseCharacters=True,
            )

    def test_converts_boolean_strings_to_bools(self):
        """Correctly converts boolean strings to Python booleans."""
        with patch("sra.password_policy.boto3.Session") as mock_session_class:
            mock_iam_client = MagicMock()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_iam_client
            mock_session_class.return_value = mock_session

            params = {
                "MAX_PASSWORD_AGE": "60",
                "MINIMUM_PASSWORD_LENGTH": "8",
                "PASSWORD_REUSE_PREVENTION": "12",
                "ALLOW_USERS_TO_CHANGE_PASSWORD": "false",
                "HARD_EXPIRY": "true",
                "REQUIRE_LOWERCASE_CHARACTERS": "false",
                "REQUIRE_NUMBERS": "false",
                "REQUIRE_SYMBOLS": "false",
                "REQUIRE_UPPERCASE_CHARACTERS": "false",
            }

            update_password_policy(params)

            call_kwargs = mock_iam_client.update_account_password_policy.call_args.kwargs
            assert call_kwargs["AllowUsersToChangePassword"] is False
            assert call_kwargs["HardExpiry"] is True
            assert call_kwargs["RequireLowercaseCharacters"] is False

    def test_converts_integer_strings_to_ints(self):
        """Correctly converts integer strings to Python integers."""
        with patch("sra.password_policy.boto3.Session") as mock_session_class:
            mock_iam_client = MagicMock()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_iam_client
            mock_session_class.return_value = mock_session

            params = {
                "MAX_PASSWORD_AGE": "365",
                "MINIMUM_PASSWORD_LENGTH": "20",
                "PASSWORD_REUSE_PREVENTION": "10",
                "ALLOW_USERS_TO_CHANGE_PASSWORD": "true",
                "HARD_EXPIRY": "false",
                "REQUIRE_LOWERCASE_CHARACTERS": "true",
                "REQUIRE_NUMBERS": "true",
                "REQUIRE_SYMBOLS": "true",
                "REQUIRE_UPPERCASE_CHARACTERS": "true",
            }

            update_password_policy(params)

            call_kwargs = mock_iam_client.update_account_password_policy.call_args.kwargs
            assert call_kwargs["MaxPasswordAge"] == 365
            assert call_kwargs["MinimumPasswordLength"] == 20
            assert call_kwargs["PasswordReusePrevention"] == 10


class TestGetPasswordPolicy:
    """Tests for get_password_policy function."""

    def test_returns_password_policy(self):
        """Returns current password policy."""
        with patch("sra.password_policy.boto3.Session") as mock_session_class:
            mock_iam_client = MagicMock()
            mock_iam_client.get_account_password_policy.return_value = {
                "PasswordPolicy": {
                    "MinimumPasswordLength": 14,
                    "RequireSymbols": True,
                }
            }
            mock_session = MagicMock()
            mock_session.client.return_value = mock_iam_client
            mock_session_class.return_value = mock_session

            result = get_password_policy()

            assert result["MinimumPasswordLength"] == 14
            assert result["RequireSymbols"] is True

    def test_returns_empty_dict_when_no_policy(self):
        """Returns empty dict when no password policy exists."""
        with patch("sra.password_policy.boto3.Session") as mock_session_class:
            mock_iam_client = MagicMock()
            mock_iam_client.exceptions.NoSuchEntityException = Exception
            mock_iam_client.get_account_password_policy.side_effect = Exception()
            mock_session = MagicMock()
            mock_session.client.return_value = mock_iam_client
            mock_session_class.return_value = mock_session

            result = get_password_policy()

            assert result == {}


class TestProcessCloudFormationEvent:
    """Tests for process_cloudformation_event function."""

    def test_processes_create_event(self):
        """Processes Create event and updates password policy."""
        with patch("sra.password_policy.update_password_policy") as mock_update:
            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "MAX_PASSWORD_AGE": "90",
                    "MINIMUM_PASSWORD_LENGTH": "14",
                    "PASSWORD_REUSE_PREVENTION": "24",
                    "ALLOW_USERS_TO_CHANGE_PASSWORD": "true",
                    "HARD_EXPIRY": "false",
                    "REQUIRE_LOWERCASE_CHARACTERS": "true",
                    "REQUIRE_NUMBERS": "true",
                    "REQUIRE_SYMBOLS": "true",
                    "REQUIRE_UPPERCASE_CHARACTERS": "true",
                },
            }

            process_cloudformation_event(event)

            mock_update.assert_called_once()

    def test_processes_update_event(self):
        """Processes Update event and updates password policy."""
        with patch("sra.password_policy.update_password_policy") as mock_update:
            event = {
                "RequestType": "Update",
                "ResourceProperties": {
                    "MAX_PASSWORD_AGE": "60",
                    "MINIMUM_PASSWORD_LENGTH": "12",
                    "PASSWORD_REUSE_PREVENTION": "12",
                    "ALLOW_USERS_TO_CHANGE_PASSWORD": "true",
                    "HARD_EXPIRY": "false",
                    "REQUIRE_LOWERCASE_CHARACTERS": "true",
                    "REQUIRE_NUMBERS": "true",
                    "REQUIRE_SYMBOLS": "true",
                    "REQUIRE_UPPERCASE_CHARACTERS": "true",
                },
            }

            process_cloudformation_event(event)

            mock_update.assert_called_once()

    def test_skips_delete_event(self):
        """Does not update policy for Delete event."""
        with patch("sra.password_policy.update_password_policy") as mock_update:
            event = {
                "RequestType": "Delete",
                "ResourceProperties": {},
            }

            process_cloudformation_event(event)

            mock_update.assert_not_called()

    def test_returns_physical_resource_id(self):
        """Returns physical resource ID."""
        with patch("sra.password_policy.update_password_policy"):
            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "MAX_PASSWORD_AGE": "90",
                    "MINIMUM_PASSWORD_LENGTH": "14",
                    "PASSWORD_REUSE_PREVENTION": "24",
                    "ALLOW_USERS_TO_CHANGE_PASSWORD": "true",
                    "HARD_EXPIRY": "false",
                    "REQUIRE_LOWERCASE_CHARACTERS": "true",
                    "REQUIRE_NUMBERS": "true",
                    "REQUIRE_SYMBOLS": "true",
                    "REQUIRE_UPPERCASE_CHARACTERS": "true",
                },
            }

            result = process_cloudformation_event(event)

            assert "sra-password-policy" in result


class TestGeneratePhysicalResourceId:
    """Tests for generate_physical_resource_id function."""

    def test_generates_id_with_params(self):
        """Generates physical resource ID including parameter values."""
        params = {
            "ALLOW_USERS_TO_CHANGE_PASSWORD": "true",
            "HARD_EXPIRY": "false",
            "MAX_PASSWORD_AGE": "90",
            "MINIMUM_PASSWORD_LENGTH": "14",
            "PASSWORD_REUSE_PREVENTION": "24",
        }

        result = generate_physical_resource_id(params)

        assert "true" in result
        assert "false" in result
        assert "90" in result
        assert "14" in result
        assert "24" in result


class TestLambdaHandler:
    """Tests for lambda_handler function."""

    def test_processes_event(self):
        """Processes CloudFormation event."""
        with patch("sra.password_policy.process_cloudformation_event") as mock_process:
            event = {
                "RequestType": "Create",
                "ResourceProperties": {
                    "MAX_PASSWORD_AGE": "90",
                    "MINIMUM_PASSWORD_LENGTH": "14",
                    "PASSWORD_REUSE_PREVENTION": "24",
                    "ALLOW_USERS_TO_CHANGE_PASSWORD": "true",
                    "HARD_EXPIRY": "false",
                    "REQUIRE_LOWERCASE_CHARACTERS": "true",
                    "REQUIRE_NUMBERS": "true",
                    "REQUIRE_SYMBOLS": "true",
                    "REQUIRE_UPPERCASE_CHARACTERS": "true",
                },
            }

            lambda_handler(event, None)

            mock_process.assert_called_once_with(event)

    def test_raises_on_validation_error(self):
        """Raises ValueError on validation error."""
        event = {
            "RequestType": "Create",
            "ResourceProperties": {
                "MAX_PASSWORD_AGE": "invalid",
                "MINIMUM_PASSWORD_LENGTH": "14",
                "PASSWORD_REUSE_PREVENTION": "24",
                "ALLOW_USERS_TO_CHANGE_PASSWORD": "true",
                "HARD_EXPIRY": "false",
                "REQUIRE_LOWERCASE_CHARACTERS": "true",
                "REQUIRE_NUMBERS": "true",
                "REQUIRE_SYMBOLS": "true",
                "REQUIRE_UPPERCASE_CHARACTERS": "true",
            },
        }

        with pytest.raises(ValueError):
            lambda_handler(event, None)

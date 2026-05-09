"""Tests for the sessions module."""

from unittest.mock import MagicMock, patch

import boto3
import pytest
from moto import mock_aws

from sra.sessions import (
    assume_role,
    get_current_account_id,
    get_current_partition,
)


@mock_aws
class TestAssumeRole:
    """Tests for assume_role function."""

    def test_assume_role_returns_session(self):
        """assume_role returns a boto3 Session with assumed credentials."""
        sts_client = boto3.client("sts", region_name="us-east-1")
        identity = sts_client.get_caller_identity()
        account_id = identity["Account"]

        with patch("sra.sessions.boto3.Session") as mock_session_class:
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {
                "Arn": f"arn:aws:iam::{account_id}:user/test-user",
                "Account": account_id,
            }
            mock_sts_client.assume_role.return_value = {
                "AssumedRoleUser": {
                    "Arn": f"arn:aws:sts::{account_id}:assumed-role/TestRole/test-session"
                },
                "Credentials": {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "SessionToken": "session-token",
                },
            }

            mock_session_instance = MagicMock()
            mock_session_instance.client.return_value = mock_sts_client
            mock_session_class.return_value = mock_session_instance

            result = assume_role("TestRole", "test-session", account_id)

            assert result is not None
            mock_sts_client.assume_role.assert_called_once()
            call_args = mock_sts_client.assume_role.call_args
            assert call_args.kwargs["RoleSessionName"] == "test-session"

    def test_assume_role_constructs_correct_role_arn(self):
        """Role ARN is correctly constructed with account ID and partition."""
        account_id = "123456789012"

        with patch("sra.sessions.boto3.Session") as mock_session_class:
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {
                "Arn": f"arn:aws:iam::{account_id}:user/test-user",
                "Account": account_id,
            }
            mock_sts_client.assume_role.return_value = {
                "AssumedRoleUser": {
                    "Arn": f"arn:aws:sts::{account_id}:assumed-role/MyRole/session"
                },
                "Credentials": {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "SessionToken": "session-token",
                },
            }

            mock_session_instance = MagicMock()
            mock_session_instance.client.return_value = mock_sts_client
            mock_session_class.return_value = mock_session_instance

            assume_role("MyRole", "session-name", account_id)

            call_args = mock_sts_client.assume_role.call_args
            role_arn = call_args.kwargs["RoleArn"]
            assert role_arn == f"arn:aws:iam::{account_id}:role/MyRole"

    def test_assume_role_uses_account_from_caller_identity_when_not_provided(self):
        """When account_id is not provided, extracts from caller identity."""
        expected_account = "987654321098"

        with patch("sra.sessions.boto3.Session") as mock_session_class:
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {
                "Arn": f"arn:aws:iam::{expected_account}:user/test-user",
                "Account": expected_account,
            }
            mock_sts_client.assume_role.return_value = {
                "AssumedRoleUser": {
                    "Arn": f"arn:aws:sts::{expected_account}:assumed-role/Role/session"
                },
                "Credentials": {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "SessionToken": "session-token",
                },
            }

            mock_session_instance = MagicMock()
            mock_session_instance.client.return_value = mock_sts_client
            mock_session_class.return_value = mock_session_instance

            assume_role("SomeRole", "session-name")

            call_args = mock_sts_client.assume_role.call_args
            role_arn = call_args.kwargs["RoleArn"]
            assert expected_account in role_arn

    def test_assume_role_supports_govcloud_partition(self):
        """Supports aws-us-gov partition."""
        account_id = "123456789012"

        with patch("sra.sessions.boto3.Session") as mock_session_class:
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {
                "Arn": f"arn:aws-us-gov:iam::{account_id}:user/test-user",
                "Account": account_id,
            }
            mock_sts_client.assume_role.return_value = {
                "AssumedRoleUser": {
                    "Arn": f"arn:aws-us-gov:sts::{account_id}:assumed-role/Role/session"
                },
                "Credentials": {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "SessionToken": "session-token",
                },
            }

            mock_session_instance = MagicMock()
            mock_session_instance.client.return_value = mock_sts_client
            mock_session_class.return_value = mock_session_instance

            assume_role("GovRole", "session-name", account_id)

            call_args = mock_sts_client.assume_role.call_args
            role_arn = call_args.kwargs["RoleArn"]
            assert role_arn.startswith("arn:aws-us-gov:iam::")

    def test_assume_role_supports_china_partition(self):
        """Supports aws-cn partition."""
        account_id = "123456789012"

        with patch("sra.sessions.boto3.Session") as mock_session_class:
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {
                "Arn": f"arn:aws-cn:iam::{account_id}:user/test-user",
                "Account": account_id,
            }
            mock_sts_client.assume_role.return_value = {
                "AssumedRoleUser": {
                    "Arn": f"arn:aws-cn:sts::{account_id}:assumed-role/Role/session"
                },
                "Credentials": {
                    "AccessKeyId": "AKIAIOSFODNN7EXAMPLE",
                    "SecretAccessKey": "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY",
                    "SessionToken": "session-token",
                },
            }

            mock_session_instance = MagicMock()
            mock_session_instance.client.return_value = mock_sts_client
            mock_session_class.return_value = mock_session_instance

            assume_role("ChinaRole", "session-name", account_id)

            call_args = mock_sts_client.assume_role.call_args
            role_arn = call_args.kwargs["RoleArn"]
            assert role_arn.startswith("arn:aws-cn:iam::")

    def test_assume_role_returns_session_with_credentials(self):
        """The returned session is created with temporary credentials."""
        account_id = "123456789012"
        expected_access_key = "AKIAIOSFODNN7EXAMPLE"
        expected_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
        expected_session_token = "session-token-value"

        with patch("sra.sessions.boto3.Session") as mock_session_class:
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {
                "Arn": f"arn:aws:iam::{account_id}:user/test-user",
                "Account": account_id,
            }
            mock_sts_client.assume_role.return_value = {
                "AssumedRoleUser": {
                    "Arn": f"arn:aws:sts::{account_id}:assumed-role/Role/session"
                },
                "Credentials": {
                    "AccessKeyId": expected_access_key,
                    "SecretAccessKey": expected_secret_key,
                    "SessionToken": expected_session_token,
                },
            }

            call_count = [0]
            def session_side_effect(*args, **kwargs):
                call_count[0] += 1
                if call_count[0] == 1:
                    mock_session_instance = MagicMock()
                    mock_session_instance.client.return_value = mock_sts_client
                    return mock_session_instance
                return MagicMock()

            mock_session_class.side_effect = session_side_effect

            assume_role("SomeRole", "session-name", account_id)

            assert call_count[0] >= 2
            second_call_kwargs = mock_session_class.call_args_list[1].kwargs
            assert second_call_kwargs["aws_access_key_id"] == expected_access_key
            assert second_call_kwargs["aws_secret_access_key"] == expected_secret_key
            assert second_call_kwargs["aws_session_token"] == expected_session_token


@mock_aws
class TestGetCurrentAccountId:
    """Tests for get_current_account_id function."""

    def test_get_current_account_id_returns_account(self):
        """get_current_account_id returns the account ID."""
        expected_account = "111122223333"

        with patch("sra.sessions.boto3.Session") as mock_session_class:
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {
                "Account": expected_account,
                "Arn": f"arn:aws:iam::{expected_account}:user/test",
            }

            mock_session_instance = MagicMock()
            mock_session_instance.client.return_value = mock_sts_client
            mock_session_class.return_value = mock_session_instance

            result = get_current_account_id()

            assert result == expected_account


@mock_aws
class TestGetCurrentPartition:
    """Tests for get_current_partition function."""

    def test_get_current_partition_returns_aws(self):
        """get_current_partition returns 'aws' for standard partition."""
        with patch("sra.sessions.boto3.Session") as mock_session_class:
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {
                "Account": "123456789012",
                "Arn": "arn:aws:iam::123456789012:user/test",
            }

            mock_session_instance = MagicMock()
            mock_session_instance.client.return_value = mock_sts_client
            mock_session_class.return_value = mock_session_instance

            result = get_current_partition()

            assert result == "aws"

    def test_get_current_partition_returns_govcloud(self):
        """get_current_partition returns 'aws-us-gov' for GovCloud."""
        with patch("sra.sessions.boto3.Session") as mock_session_class:
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {
                "Account": "123456789012",
                "Arn": "arn:aws-us-gov:iam::123456789012:user/test",
            }

            mock_session_instance = MagicMock()
            mock_session_instance.client.return_value = mock_sts_client
            mock_session_class.return_value = mock_session_instance

            result = get_current_partition()

            assert result == "aws-us-gov"

    def test_get_current_partition_returns_china(self):
        """get_current_partition returns 'aws-cn' for China region."""
        with patch("sra.sessions.boto3.Session") as mock_session_class:
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {
                "Account": "123456789012",
                "Arn": "arn:aws-cn:iam::123456789012:user/test",
            }

            mock_session_instance = MagicMock()
            mock_session_instance.client.return_value = mock_sts_client
            mock_session_class.return_value = mock_session_instance

            result = get_current_partition()

            assert result == "aws-cn"

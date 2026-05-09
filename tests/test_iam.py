"""Tests for the iam module."""

from unittest.mock import MagicMock, patch

import pytest

from sra.iam import (
    create_service_linked_role,
    delete_service_linked_role,
    service_linked_role_exists,
)


class MockNoSuchEntityException(Exception):
    """Mock exception for IAM NoSuchEntityException."""
    pass


class TestCreateServiceLinkedRole:
    """Tests for create_service_linked_role function."""

    def test_creates_role_when_not_exists(self):
        """Creates role when it doesn't exist."""
        with patch("sra.iam.boto3.Session") as mock_session_class:
            mock_iam_client = MagicMock()
            mock_iam_client.exceptions.NoSuchEntityException = MockNoSuchEntityException
            mock_iam_client.get_role.side_effect = MockNoSuchEntityException()

            mock_session = MagicMock()
            mock_session.client.return_value = mock_iam_client
            mock_session_class.return_value = mock_session

            result = create_service_linked_role(
                "AWSServiceRoleForGuardDuty",
                "guardduty.amazonaws.com",
                "GuardDuty service role",
            )

            assert result is True
            mock_iam_client.create_service_linked_role.assert_called_once_with(
                AWSServiceName="guardduty.amazonaws.com",
                Description="GuardDuty service role",
            )

    def test_returns_false_when_role_exists(self):
        """Returns False when role already exists."""
        with patch("sra.iam.boto3.Session") as mock_session_class:
            mock_iam_client = MagicMock()
            mock_iam_client.get_role.return_value = {
                "Role": {"RoleName": "AWSServiceRoleForGuardDuty"}
            }

            mock_session = MagicMock()
            mock_session.client.return_value = mock_iam_client
            mock_session_class.return_value = mock_session

            result = create_service_linked_role(
                "AWSServiceRoleForGuardDuty",
                "guardduty.amazonaws.com",
            )

            assert result is False
            mock_iam_client.create_service_linked_role.assert_not_called()

    def test_idempotent_creation(self):
        """Function is idempotent - doesn't fail if role exists."""
        with patch("sra.iam.boto3.Session") as mock_session_class:
            mock_iam_client = MagicMock()
            mock_iam_client.get_role.return_value = {
                "Role": {"RoleName": "ExistingRole"}
            }

            mock_session = MagicMock()
            mock_session.client.return_value = mock_iam_client
            mock_session_class.return_value = mock_session

            result = create_service_linked_role("ExistingRole", "service.amazonaws.com")

            assert result is False

    def test_accepts_optional_description(self):
        """Accepts optional description parameter."""
        with patch("sra.iam.boto3.Session") as mock_session_class:
            mock_iam_client = MagicMock()
            mock_iam_client.exceptions.NoSuchEntityException = MockNoSuchEntityException
            mock_iam_client.get_role.side_effect = MockNoSuchEntityException()

            mock_session = MagicMock()
            mock_session.client.return_value = mock_iam_client
            mock_session_class.return_value = mock_session

            create_service_linked_role("MyRole", "myservice.amazonaws.com")

            call_args = mock_iam_client.create_service_linked_role.call_args
            assert call_args.kwargs["Description"] == ""

    def test_uses_provided_session(self):
        """Uses provided session instead of creating new one."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_iam_client.get_role.return_value = {"Role": {"RoleName": "Test"}}
        mock_session.client.return_value = mock_iam_client

        create_service_linked_role("Test", "test.amazonaws.com", session=mock_session)

        mock_session.client.assert_called_once()


class TestDeleteServiceLinkedRole:
    """Tests for delete_service_linked_role function."""

    def test_deletes_existing_role(self):
        """Deletes role and returns task ID."""
        with patch("sra.iam.boto3.Session") as mock_session_class:
            mock_iam_client = MagicMock()
            mock_iam_client.delete_service_linked_role.return_value = {
                "DeletionTaskId": "task-12345"
            }

            mock_session = MagicMock()
            mock_session.client.return_value = mock_iam_client
            mock_session_class.return_value = mock_session

            result = delete_service_linked_role("AWSServiceRoleForTest")

            assert result == "task-12345"
            mock_iam_client.delete_service_linked_role.assert_called_once_with(
                RoleName="AWSServiceRoleForTest"
            )

    def test_returns_none_when_role_not_exists(self):
        """Returns None when role doesn't exist."""
        with patch("sra.iam.boto3.Session") as mock_session_class:
            mock_iam_client = MagicMock()
            mock_iam_client.exceptions.NoSuchEntityException = MockNoSuchEntityException
            mock_iam_client.delete_service_linked_role.side_effect = MockNoSuchEntityException()

            mock_session = MagicMock()
            mock_session.client.return_value = mock_iam_client
            mock_session_class.return_value = mock_session

            result = delete_service_linked_role("NonExistentRole")

            assert result is None


class TestServiceLinkedRoleExists:
    """Tests for service_linked_role_exists function."""

    def test_returns_true_when_role_exists(self):
        """Returns True when role exists."""
        with patch("sra.iam.boto3.Session") as mock_session_class:
            mock_iam_client = MagicMock()
            mock_iam_client.get_role.return_value = {
                "Role": {"RoleName": "ExistingRole"}
            }

            mock_session = MagicMock()
            mock_session.client.return_value = mock_iam_client
            mock_session_class.return_value = mock_session

            result = service_linked_role_exists("ExistingRole")

            assert result is True

    def test_returns_false_when_role_not_exists(self):
        """Returns False when role doesn't exist."""
        with patch("sra.iam.boto3.Session") as mock_session_class:
            mock_iam_client = MagicMock()
            mock_iam_client.exceptions.NoSuchEntityException = MockNoSuchEntityException
            mock_iam_client.get_role.side_effect = MockNoSuchEntityException()

            mock_session = MagicMock()
            mock_session.client.return_value = mock_iam_client
            mock_session_class.return_value = mock_session

            result = service_linked_role_exists("NonExistentRole")

            assert result is False

    def test_uses_provided_session(self):
        """Uses provided session instead of creating new one."""
        mock_session = MagicMock()
        mock_iam_client = MagicMock()
        mock_iam_client.get_role.return_value = {"Role": {"RoleName": "Test"}}
        mock_session.client.return_value = mock_iam_client

        service_linked_role_exists("Test", session=mock_session)

        mock_session.client.assert_called_once()

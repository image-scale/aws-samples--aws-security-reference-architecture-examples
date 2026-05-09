"""Tests for the organizations module."""

from unittest.mock import MagicMock, patch

import pytest

from sra.organizations import (
    get_account_ids,
    get_management_account_id,
    get_organization_accounts,
    get_organization_id,
    get_root_organizational_unit_id,
)


class TestGetOrganizationAccounts:
    """Tests for get_organization_accounts function."""

    def test_returns_active_accounts(self):
        """Returns list of active accounts with AccountId and Email."""
        with patch("sra.organizations.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_paginator = MagicMock()
            mock_paginator.paginate.return_value = [
                {
                    "Accounts": [
                        {"Id": "111111111111", "Email": "account1@example.com", "Status": "ACTIVE"},
                        {"Id": "222222222222", "Email": "account2@example.com", "Status": "ACTIVE"},
                    ]
                }
            ]
            mock_org_client.get_paginator.return_value = mock_paginator

            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            result = get_organization_accounts()

            assert len(result) == 2
            assert result[0] == {"AccountId": "111111111111", "Email": "account1@example.com"}
            assert result[1] == {"AccountId": "222222222222", "Email": "account2@example.com"}

    def test_excludes_non_active_accounts(self):
        """Excludes accounts with status other than ACTIVE."""
        with patch("sra.organizations.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_paginator = MagicMock()
            mock_paginator.paginate.return_value = [
                {
                    "Accounts": [
                        {"Id": "111111111111", "Email": "active@example.com", "Status": "ACTIVE"},
                        {"Id": "222222222222", "Email": "suspended@example.com", "Status": "SUSPENDED"},
                        {"Id": "333333333333", "Email": "pending@example.com", "Status": "PENDING_CLOSURE"},
                    ]
                }
            ]
            mock_org_client.get_paginator.return_value = mock_paginator

            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            result = get_organization_accounts()

            assert len(result) == 1
            assert result[0]["AccountId"] == "111111111111"

    def test_excludes_specified_accounts(self):
        """Excludes accounts in the exclude_accounts list."""
        with patch("sra.organizations.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_paginator = MagicMock()
            mock_paginator.paginate.return_value = [
                {
                    "Accounts": [
                        {"Id": "111111111111", "Email": "account1@example.com", "Status": "ACTIVE"},
                        {"Id": "222222222222", "Email": "account2@example.com", "Status": "ACTIVE"},
                        {"Id": "333333333333", "Email": "account3@example.com", "Status": "ACTIVE"},
                    ]
                }
            ]
            mock_org_client.get_paginator.return_value = mock_paginator

            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            result = get_organization_accounts(exclude_accounts=["222222222222"])

            assert len(result) == 2
            account_ids = [a["AccountId"] for a in result]
            assert "222222222222" not in account_ids
            assert "111111111111" in account_ids
            assert "333333333333" in account_ids

    def test_handles_pagination(self):
        """Handles multiple pages of accounts."""
        with patch("sra.organizations.boto3.Session") as mock_session_class:
            with patch("sra.organizations.sleep"):
                mock_org_client = MagicMock()
                mock_paginator = MagicMock()
                mock_paginator.paginate.return_value = [
                    {
                        "Accounts": [
                            {"Id": "111111111111", "Email": "page1@example.com", "Status": "ACTIVE"},
                        ]
                    },
                    {
                        "Accounts": [
                            {"Id": "222222222222", "Email": "page2@example.com", "Status": "ACTIVE"},
                        ]
                    },
                    {
                        "Accounts": [
                            {"Id": "333333333333", "Email": "page3@example.com", "Status": "ACTIVE"},
                        ]
                    },
                ]
                mock_org_client.get_paginator.return_value = mock_paginator

                mock_session = MagicMock()
                mock_session.client.return_value = mock_org_client
                mock_session_class.return_value = mock_session

                result = get_organization_accounts()

                assert len(result) == 3

    def test_uses_provided_session(self):
        """Uses provided session instead of creating new one."""
        mock_session = MagicMock()
        mock_org_client = MagicMock()
        mock_paginator = MagicMock()
        mock_paginator.paginate.return_value = [{"Accounts": []}]
        mock_org_client.get_paginator.return_value = mock_paginator
        mock_session.client.return_value = mock_org_client

        get_organization_accounts(session=mock_session)

        mock_session.client.assert_called_once()


class TestGetAccountIds:
    """Tests for get_account_ids function."""

    def test_extracts_account_ids_from_list(self):
        """Extracts just the account IDs from account list."""
        accounts = [
            {"AccountId": "111111111111", "Email": "a@b.com"},
            {"AccountId": "222222222222", "Email": "c@d.com"},
        ]

        result = get_account_ids(accounts)

        assert result == ["111111111111", "222222222222"]

    def test_fetches_accounts_when_empty_list(self):
        """Fetches accounts when given empty list."""
        with patch("sra.organizations.get_organization_accounts") as mock_get_accounts:
            mock_get_accounts.return_value = [
                {"AccountId": "999999999999", "Email": "fetched@example.com"},
            ]

            result = get_account_ids([])

            mock_get_accounts.assert_called_once()
            assert result == ["999999999999"]

    def test_fetches_accounts_when_none(self):
        """Fetches accounts when given None."""
        with patch("sra.organizations.get_organization_accounts") as mock_get_accounts:
            mock_get_accounts.return_value = [
                {"AccountId": "888888888888", "Email": "fetched@example.com"},
            ]

            result = get_account_ids(None)

            mock_get_accounts.assert_called_once()
            assert result == ["888888888888"]

    def test_passes_exclude_accounts_when_fetching(self):
        """Passes exclude_accounts to get_organization_accounts."""
        with patch("sra.organizations.get_organization_accounts") as mock_get_accounts:
            mock_get_accounts.return_value = []

            get_account_ids(None, exclude_accounts=["123456789012"])

            mock_get_accounts.assert_called_once()
            call_args = mock_get_accounts.call_args
            assert call_args[0][0] == ["123456789012"]


class TestGetManagementAccountId:
    """Tests for get_management_account_id function."""

    def test_returns_management_account_id(self):
        """Returns the management account ID from describe_organization."""
        with patch("sra.organizations.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_org_client.describe_organization.return_value = {
                "Organization": {
                    "MasterAccountId": "123456789012",
                    "Id": "o-abc123",
                }
            }

            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            result = get_management_account_id()

            assert result == "123456789012"


class TestGetOrganizationId:
    """Tests for get_organization_id function."""

    def test_returns_organization_id(self):
        """Returns the organization ID from describe_organization."""
        with patch("sra.organizations.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_org_client.describe_organization.return_value = {
                "Organization": {
                    "MasterAccountId": "123456789012",
                    "Id": "o-exampleorgid",
                }
            }

            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            result = get_organization_id()

            assert result == "o-exampleorgid"


class TestGetRootOrganizationalUnitId:
    """Tests for get_root_organizational_unit_id function."""

    def test_returns_root_ou_id(self):
        """Returns the root OU ID from list_roots."""
        with patch("sra.organizations.boto3.Session") as mock_session_class:
            mock_org_client = MagicMock()
            mock_org_client.list_roots.return_value = {
                "Roots": [
                    {"Id": "r-abc1", "Arn": "arn:aws:organizations::123456789012:root/o-org/r-abc1"},
                ]
            }

            mock_session = MagicMock()
            mock_session.client.return_value = mock_org_client
            mock_session_class.return_value = mock_session

            result = get_root_organizational_unit_id()

            assert result == "r-abc1"

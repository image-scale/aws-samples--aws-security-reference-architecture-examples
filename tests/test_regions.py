"""Tests for the regions module."""

from unittest.mock import MagicMock, patch

import pytest
from botocore.exceptions import ClientError

from sra.regions import (
    DEFAULT_REGIONS,
    filter_regions_by_availability,
    get_available_regions_from_account,
    get_enabled_regions,
    parse_region_list,
)


class TestParseRegionList:
    """Tests for parse_region_list function."""

    def test_parses_comma_separated_regions(self):
        """Parses comma-separated region string."""
        result = parse_region_list("us-east-1, eu-west-1")
        assert result == ["us-east-1", "eu-west-1"]

    def test_handles_no_spaces(self):
        """Handles regions without spaces."""
        result = parse_region_list("us-east-1,eu-west-1,ap-south-1")
        assert result == ["us-east-1", "eu-west-1", "ap-south-1"]

    def test_strips_whitespace(self):
        """Strips whitespace from region names."""
        result = parse_region_list("  us-east-1  ,  eu-west-1  ")
        assert result == ["us-east-1", "eu-west-1"]

    def test_empty_string_returns_empty_list(self):
        """Empty string returns empty list."""
        result = parse_region_list("")
        assert result == []

    def test_whitespace_only_returns_empty_list(self):
        """Whitespace-only string returns empty list."""
        result = parse_region_list("   ")
        assert result == []

    def test_none_returns_empty_list(self):
        """None returns empty list."""
        result = parse_region_list(None)
        assert result == []

    def test_single_region(self):
        """Single region is parsed correctly."""
        result = parse_region_list("us-east-1")
        assert result == ["us-east-1"]

    def test_filters_empty_elements(self):
        """Filters out empty elements from trailing comma."""
        result = parse_region_list("us-east-1,eu-west-1,")
        assert result == ["us-east-1", "eu-west-1"]


class TestGetEnabledRegions:
    """Tests for get_enabled_regions function."""

    def test_returns_enabled_regions(self):
        """Returns regions where STS call succeeds."""
        with patch("sra.regions.boto3.Session") as mock_session_class:
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

            mock_session = MagicMock()
            mock_session.client.return_value = mock_sts_client
            mock_session_class.return_value = mock_session

            result = get_enabled_regions("us-east-1, eu-west-1")

            assert "us-east-1" in result
            assert "eu-west-1" in result

    def test_uses_customer_regions_when_provided(self):
        """Uses customer-provided regions instead of defaults."""
        with patch("sra.regions.boto3.Session") as mock_session_class:
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

            mock_session = MagicMock()
            mock_session.client.return_value = mock_sts_client
            mock_session_class.return_value = mock_session

            result = get_enabled_regions("ap-south-1")

            assert result == ["ap-south-1"]
            mock_session.client.assert_called()
            call_args = mock_session.client.call_args
            assert call_args.kwargs["region_name"] == "ap-south-1"

    def test_excludes_disabled_regions(self):
        """Excludes regions that return InvalidClientTokenId."""
        with patch("sra.regions.boto3.Session") as mock_session_class:
            def client_side_effect(service, **kwargs):
                mock_client = MagicMock()
                if kwargs.get("region_name") == "disabled-region":
                    error_response = {"Error": {"Code": "InvalidClientTokenId"}}
                    mock_client.get_caller_identity.side_effect = ClientError(
                        error_response, "GetCallerIdentity"
                    )
                else:
                    mock_client.get_caller_identity.return_value = {"Account": "123"}
                return mock_client

            mock_session = MagicMock()
            mock_session.client.side_effect = client_side_effect
            mock_session_class.return_value = mock_session

            result = get_enabled_regions("us-east-1, disabled-region, eu-west-1")

            assert "us-east-1" in result
            assert "eu-west-1" in result
            assert "disabled-region" not in result

    def test_excludes_invalid_regions(self):
        """Excludes regions with invalid endpoints."""
        with patch("sra.regions.boto3.Session") as mock_session_class:
            def client_side_effect(service, **kwargs):
                mock_client = MagicMock()
                if kwargs.get("region_name") == "invalid-region":
                    mock_client.get_caller_identity.side_effect = Exception(
                        "Could not connect to the endpoint URL"
                    )
                else:
                    mock_client.get_caller_identity.return_value = {"Account": "123"}
                return mock_client

            mock_session = MagicMock()
            mock_session.client.side_effect = client_side_effect
            mock_session_class.return_value = mock_session

            result = get_enabled_regions("us-east-1, invalid-region")

            assert "us-east-1" in result
            assert "invalid-region" not in result

    def test_uses_default_regions_when_not_provided(self):
        """Uses DEFAULT_REGIONS when no customer regions provided."""
        with patch("sra.regions.boto3.Session") as mock_session_class:
            mock_sts_client = MagicMock()
            mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}

            mock_session = MagicMock()
            mock_session.client.return_value = mock_sts_client
            mock_session_class.return_value = mock_session

            result = get_enabled_regions(None)

            assert len(result) == len(DEFAULT_REGIONS)

    def test_uses_provided_session(self):
        """Uses provided session instead of creating new one."""
        mock_session = MagicMock()
        mock_sts_client = MagicMock()
        mock_sts_client.get_caller_identity.return_value = {"Account": "123456789012"}
        mock_session.client.return_value = mock_sts_client

        get_enabled_regions("us-east-1", session=mock_session)

        mock_session.client.assert_called()


class TestGetAvailableRegionsFromAccount:
    """Tests for get_available_regions_from_account function."""

    def test_returns_enabled_regions_from_api(self):
        """Returns regions from account:ListRegions API."""
        with patch("sra.regions.boto3.Session") as mock_session_class:
            mock_account_client = MagicMock()
            mock_account_client.list_regions.return_value = {
                "Regions": [
                    {"RegionName": "us-east-1", "RegionOptStatus": "ENABLED_BY_DEFAULT"},
                    {"RegionName": "ap-south-1", "RegionOptStatus": "ENABLED"},
                    {"RegionName": "eu-west-1", "RegionOptStatus": "ENABLED_BY_DEFAULT"},
                ]
            }

            mock_session = MagicMock()
            mock_session.client.return_value = mock_account_client
            mock_session_class.return_value = mock_session

            result = get_available_regions_from_account()

            assert result == ["us-east-1", "ap-south-1", "eu-west-1"]

    def test_calls_list_regions_with_correct_status(self):
        """Calls list_regions with ENABLED and ENABLED_BY_DEFAULT status."""
        with patch("sra.regions.boto3.Session") as mock_session_class:
            mock_account_client = MagicMock()
            mock_account_client.list_regions.return_value = {"Regions": []}

            mock_session = MagicMock()
            mock_session.client.return_value = mock_account_client
            mock_session_class.return_value = mock_session

            get_available_regions_from_account()

            mock_account_client.list_regions.assert_called_once_with(
                RegionOptStatusContains=["ENABLED", "ENABLED_BY_DEFAULT"]
            )


class TestFilterRegionsByAvailability:
    """Tests for filter_regions_by_availability function."""

    def test_filters_to_enabled_regions(self):
        """Filters list to only enabled regions."""
        with patch("sra.regions.boto3.Session") as mock_session_class:
            def client_side_effect(service, **kwargs):
                mock_client = MagicMock()
                if kwargs.get("region_name") == "disabled-region":
                    mock_client.get_caller_identity.side_effect = Exception("Failed")
                else:
                    mock_client.get_caller_identity.return_value = {"Account": "123"}
                return mock_client

            mock_session = MagicMock()
            mock_session.client.side_effect = client_side_effect
            mock_session_class.return_value = mock_session

            result = filter_regions_by_availability(
                ["us-east-1", "disabled-region", "eu-west-1"]
            )

            assert "us-east-1" in result
            assert "eu-west-1" in result
            assert "disabled-region" not in result

    def test_empty_list_returns_empty(self):
        """Empty input returns empty output."""
        result = filter_regions_by_availability([])
        assert result == []

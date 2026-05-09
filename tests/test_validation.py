"""Tests for the validation module."""

import pytest

from sra.validation import (
    AWS_ACCOUNT_ID_PATTERN,
    BOOLEAN_PATTERN,
    BOOLEAN_PATTERN_CASE_INSENSITIVE,
    FINDING_PUBLISHING_FREQUENCY_PATTERN,
    KMS_KEY_ARN_PATTERN,
    MAX_PASSWORD_AGE_PATTERN,
    MINIMUM_PASSWORD_LENGTH_PATTERN,
    PASSWORD_REUSE_PREVENTION_PATTERN,
    REGIONS_PATTERN,
    ROLE_NAME_PATTERN,
    S3_BUCKET_ARN_PATTERN,
    S3_BUCKET_NAME_PATTERN,
    SNS_TOPIC_ARN_PATTERN,
    ValidationError,
    validate_parameter,
    validate_parameters,
)


class TestValidateParameter:
    """Tests for validate_parameter function."""

    def test_valid_aws_account_id(self):
        """Valid 12-digit account ID passes validation."""
        validate_parameter("AWS_ACCOUNT_ID", "123456789012", AWS_ACCOUNT_ID_PATTERN)

    def test_invalid_aws_account_id_too_short(self):
        """Too-short account ID raises ValidationError."""
        with pytest.raises(ValidationError) as exc_info:
            validate_parameter("AWS_ACCOUNT_ID", "12345", AWS_ACCOUNT_ID_PATTERN)
        assert "AWS_ACCOUNT_ID" in str(exc_info.value)
        assert "12345" in str(exc_info.value)
        assert AWS_ACCOUNT_ID_PATTERN in str(exc_info.value)

    def test_invalid_aws_account_id_non_numeric(self):
        """Non-numeric account ID raises ValidationError."""
        with pytest.raises(ValidationError):
            validate_parameter("AWS_ACCOUNT_ID", "12345678901a", AWS_ACCOUNT_ID_PATTERN)

    def test_valid_role_name(self):
        """Valid role name passes validation."""
        validate_parameter("ROLE_NAME", "MyRole-123", ROLE_NAME_PATTERN)

    def test_valid_role_name_with_special_chars(self):
        """Role name with allowed special characters passes."""
        validate_parameter("ROLE_NAME", "My_Role+=,.@-Name", ROLE_NAME_PATTERN)

    def test_empty_role_name_required(self):
        """Empty role name raises ValidationError when required."""
        with pytest.raises(ValidationError) as exc_info:
            validate_parameter("ROLE_NAME", "", ROLE_NAME_PATTERN)
        assert "missing or empty" in str(exc_info.value)

    def test_none_value_required(self):
        """None value raises ValidationError when required."""
        with pytest.raises(ValidationError) as exc_info:
            validate_parameter("ROLE_NAME", None, ROLE_NAME_PATTERN)
        assert "missing or empty" in str(exc_info.value)

    def test_boolean_true(self):
        """Lowercase 'true' passes boolean validation."""
        validate_parameter("ENABLED", "true", BOOLEAN_PATTERN)

    def test_boolean_false(self):
        """Lowercase 'false' passes boolean validation."""
        validate_parameter("ENABLED", "false", BOOLEAN_PATTERN)

    def test_boolean_uppercase_fails_case_sensitive(self):
        """Uppercase 'TRUE' fails case-sensitive boolean validation."""
        with pytest.raises(ValidationError):
            validate_parameter("ENABLED", "TRUE", BOOLEAN_PATTERN)

    def test_boolean_uppercase_passes_case_insensitive(self):
        """Uppercase 'TRUE' passes case-insensitive boolean validation."""
        validate_parameter("ENABLED", "TRUE", BOOLEAN_PATTERN_CASE_INSENSITIVE)
        validate_parameter("ENABLED", "False", BOOLEAN_PATTERN_CASE_INSENSITIVE)

    def test_invalid_boolean_value(self):
        """Invalid boolean value raises ValidationError."""
        with pytest.raises(ValidationError):
            validate_parameter("ENABLED", "yes", BOOLEAN_PATTERN)

    def test_optional_allows_empty(self):
        """Optional parameter allows empty string."""
        validate_parameter("OPTIONAL_PARAM", "", ROLE_NAME_PATTERN, optional=True)

    def test_optional_allows_none(self):
        """Optional parameter allows None value."""
        validate_parameter("OPTIONAL_PARAM", None, ROLE_NAME_PATTERN, optional=True)

    def test_optional_still_validates_non_empty(self):
        """Optional parameter still validates non-empty values."""
        with pytest.raises(ValidationError):
            validate_parameter("OPTIONAL_PARAM", "!!invalid!!", ROLE_NAME_PATTERN, optional=True)


class TestArnPatterns:
    """Tests for ARN pattern validations."""

    def test_valid_kms_key_arn(self):
        """Valid KMS key ARN passes validation."""
        arn = "arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        validate_parameter("KMS_KEY_ARN", arn, KMS_KEY_ARN_PATTERN)

    def test_valid_kms_key_arn_gov_cloud(self):
        """Valid KMS key ARN in GovCloud passes validation."""
        arn = "arn:aws-us-gov:kms:us-gov-west-1:123456789012:key/12345678-1234-1234-1234-123456789012"
        validate_parameter("KMS_KEY_ARN", arn, KMS_KEY_ARN_PATTERN)

    def test_invalid_kms_key_arn(self):
        """Invalid KMS key ARN raises ValidationError."""
        with pytest.raises(ValidationError):
            validate_parameter("KMS_KEY_ARN", "invalid-arn", KMS_KEY_ARN_PATTERN)

    def test_valid_sns_topic_arn(self):
        """Valid SNS topic ARN passes validation."""
        arn = "arn:aws:sns:us-east-1:123456789012:my-topic"
        validate_parameter("SNS_TOPIC_ARN", arn, SNS_TOPIC_ARN_PATTERN)

    def test_valid_sns_topic_arn_with_hyphen(self):
        """SNS topic ARN with hyphens passes validation."""
        arn = "arn:aws:sns:eu-west-1:123456789012:my-sns-topic-name"
        validate_parameter("SNS_TOPIC_ARN", arn, SNS_TOPIC_ARN_PATTERN)

    def test_invalid_sns_topic_arn(self):
        """Invalid SNS topic ARN raises ValidationError."""
        with pytest.raises(ValidationError):
            validate_parameter("SNS_TOPIC_ARN", "not-an-arn", SNS_TOPIC_ARN_PATTERN)

    def test_valid_s3_bucket_arn(self):
        """Valid S3 bucket ARN passes validation."""
        arn = "arn:aws:s3:::my-bucket-name"
        validate_parameter("S3_BUCKET_ARN", arn, S3_BUCKET_ARN_PATTERN)

    def test_valid_s3_bucket_arn_with_hyphens(self):
        """S3 bucket ARN with hyphens passes validation."""
        arn = "arn:aws:s3:::my-security-bucket-123"
        validate_parameter("S3_BUCKET_ARN", arn, S3_BUCKET_ARN_PATTERN)

    def test_invalid_s3_bucket_arn(self):
        """Invalid S3 bucket ARN raises ValidationError."""
        with pytest.raises(ValidationError):
            validate_parameter("S3_BUCKET_ARN", "s3://my-bucket", S3_BUCKET_ARN_PATTERN)


class TestOtherPatterns:
    """Tests for other pattern validations."""

    def test_valid_regions(self):
        """Valid regions string passes validation."""
        validate_parameter("REGIONS", "us-east-1, eu-west-1", REGIONS_PATTERN)

    def test_empty_regions_allowed(self):
        """Empty regions string passes validation (matches empty pattern)."""
        validate_parameter("REGIONS", "", REGIONS_PATTERN, optional=True)

    def test_valid_s3_bucket_name(self):
        """Valid S3 bucket name passes validation."""
        validate_parameter("BUCKET_NAME", "my-bucket-123", S3_BUCKET_NAME_PATTERN)

    def test_valid_finding_frequency_fifteen_minutes(self):
        """FIFTEEN_MINUTES passes finding frequency validation."""
        validate_parameter("FREQUENCY", "FIFTEEN_MINUTES", FINDING_PUBLISHING_FREQUENCY_PATTERN)

    def test_valid_finding_frequency_one_hour(self):
        """ONE_HOUR passes finding frequency validation."""
        validate_parameter("FREQUENCY", "ONE_HOUR", FINDING_PUBLISHING_FREQUENCY_PATTERN)

    def test_valid_finding_frequency_six_hours(self):
        """SIX_HOURS passes finding frequency validation."""
        validate_parameter("FREQUENCY", "SIX_HOURS", FINDING_PUBLISHING_FREQUENCY_PATTERN)

    def test_invalid_finding_frequency(self):
        """Invalid finding frequency raises ValidationError."""
        with pytest.raises(ValidationError):
            validate_parameter("FREQUENCY", "DAILY", FINDING_PUBLISHING_FREQUENCY_PATTERN)


class TestPasswordPatterns:
    """Tests for password policy pattern validations."""

    def test_valid_max_password_age(self):
        """Valid max password ages pass validation."""
        validate_parameter("MAX_AGE", "90", MAX_PASSWORD_AGE_PATTERN)
        validate_parameter("MAX_AGE", "1", MAX_PASSWORD_AGE_PATTERN)
        validate_parameter("MAX_AGE", "365", MAX_PASSWORD_AGE_PATTERN)

    def test_invalid_max_password_age_zero(self):
        """Zero max password age fails validation."""
        with pytest.raises(ValidationError):
            validate_parameter("MAX_AGE", "0", MAX_PASSWORD_AGE_PATTERN)

    def test_valid_minimum_password_length(self):
        """Valid minimum password lengths pass validation."""
        validate_parameter("MIN_LENGTH", "8", MINIMUM_PASSWORD_LENGTH_PATTERN)
        validate_parameter("MIN_LENGTH", "6", MINIMUM_PASSWORD_LENGTH_PATTERN)
        validate_parameter("MIN_LENGTH", "128", MINIMUM_PASSWORD_LENGTH_PATTERN)

    def test_invalid_minimum_password_length_too_short(self):
        """Too-short minimum password length fails validation."""
        with pytest.raises(ValidationError):
            validate_parameter("MIN_LENGTH", "5", MINIMUM_PASSWORD_LENGTH_PATTERN)

    def test_valid_password_reuse_prevention(self):
        """Valid password reuse prevention values pass validation."""
        validate_parameter("REUSE", "1", PASSWORD_REUSE_PREVENTION_PATTERN)
        validate_parameter("REUSE", "12", PASSWORD_REUSE_PREVENTION_PATTERN)
        validate_parameter("REUSE", "24", PASSWORD_REUSE_PREVENTION_PATTERN)

    def test_invalid_password_reuse_prevention_too_high(self):
        """Too-high password reuse prevention fails validation."""
        with pytest.raises(ValidationError):
            validate_parameter("REUSE", "25", PASSWORD_REUSE_PREVENTION_PATTERN)


class TestValidateParameters:
    """Tests for validate_parameters function."""

    def test_validate_multiple_params(self):
        """Multiple parameters validated successfully."""
        params = {
            "ACCOUNT_ID": "123456789012",
            "ROLE_NAME": "MyRole",
            "ENABLED": "true",
        }
        validations = [
            ("ACCOUNT_ID", AWS_ACCOUNT_ID_PATTERN),
            ("ROLE_NAME", ROLE_NAME_PATTERN),
            ("ENABLED", BOOLEAN_PATTERN),
        ]
        result = validate_parameters(params, validations)
        assert result == params

    def test_validate_with_optional_param(self):
        """Optional parameter validation works correctly."""
        params = {
            "ACCOUNT_ID": "123456789012",
            "REGIONS": "",
        }
        validations = [
            ("ACCOUNT_ID", AWS_ACCOUNT_ID_PATTERN),
            ("REGIONS", REGIONS_PATTERN, True),
        ]
        result = validate_parameters(params, validations)
        assert result == params

    def test_validate_fails_on_first_invalid(self):
        """Validation raises on first invalid parameter."""
        params = {
            "ACCOUNT_ID": "invalid",
            "ROLE_NAME": "MyRole",
        }
        validations = [
            ("ACCOUNT_ID", AWS_ACCOUNT_ID_PATTERN),
            ("ROLE_NAME", ROLE_NAME_PATTERN),
        ]
        with pytest.raises(ValidationError) as exc_info:
            validate_parameters(params, validations)
        assert "ACCOUNT_ID" in str(exc_info.value)

    def test_validate_missing_required_param(self):
        """Missing required parameter raises ValidationError."""
        params = {"ROLE_NAME": "MyRole"}
        validations = [
            ("ACCOUNT_ID", AWS_ACCOUNT_ID_PATTERN),
            ("ROLE_NAME", ROLE_NAME_PATTERN),
        ]
        with pytest.raises(ValidationError) as exc_info:
            validate_parameters(params, validations)
        assert "ACCOUNT_ID" in str(exc_info.value)

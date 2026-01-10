"""Unit tests for GDPR compliance checker."""

import unittest
from unittest.mock import Mock, patch, MagicMock
import boto3
from moto import mock_aws

from s3_security_scanner.checks.gdpr_compliance import GDPRComplianceChecker


class TestGDPRComplianceChecker(unittest.TestCase):
    """Test GDPR compliance checker functionality."""

    def setUp(self):
        """Set up test fixtures."""
        self.mock_session = Mock(spec=boto3.Session)
        self.checker = GDPRComplianceChecker(self.mock_session)
        self.test_bucket = "test-gdpr-bucket"
        self.test_region = "eu-west-1"

    def test_check_gdpr_compliance_features_returns_dict(self):
        """Test that GDPR compliance check returns a dictionary with expected keys."""
        # Create mock clients
        mock_s3_client = Mock()
        mock_kms_client = Mock()
        mock_cloudtrail_client = Mock()

        # Create a mock session that returns our mock clients
        mock_session = Mock(spec=boto3.Session)
        mock_session.client.side_effect = lambda service, **kwargs: {
            's3': mock_s3_client,
            'kms': mock_kms_client,
            'cloudtrail': mock_cloudtrail_client
        }[service]

        # Create checker with the mock session
        checker = GDPRComplianceChecker(mock_session)

        # Call the function - it should return defaults on any errors
        result = checker.check_gdpr_compliance_features(self.test_bucket, self.test_region)

        # Verify it returns a dict with expected structure (even if defaults)
        self.assertIsInstance(result, dict)
        self.assertIn('gdpr_data_residency', result)

    def test_check_data_residency_eu_region(self):
        """Test data residency check correctly identifies EU regions as compliant."""
        mock_s3_client = Mock()
        mock_s3_client.get_bucket_location.return_value = {
            'LocationConstraint': 'eu-west-1'
        }

        result = self.checker._check_data_residency(
            self.test_bucket, mock_s3_client, self.test_region
        )

        self.assertTrue(result['compliant_region'])
        self.assertEqual(result['bucket_region'], 'eu-west-1')

    def test_check_data_residency_non_eu_region(self):
        """Test data residency check correctly identifies non-EU regions as non-compliant."""
        mock_s3_client = Mock()
        mock_s3_client.get_bucket_location.return_value = {
            'LocationConstraint': 'us-east-1'
        }

        result = self.checker._check_data_residency(
            self.test_bucket, mock_s3_client, 'us-east-1'
        )

        self.assertFalse(result['compliant_region'])
        self.assertEqual(result['bucket_region'], 'us-east-1')

    def test_check_kms_key_management_aes256(self):
        """Test KMS key management check with AES256."""
        mock_s3_client = Mock()
        mock_kms_client = Mock()
        
        mock_s3_client.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }]
            }
        }
        
        result = self.checker._check_kms_key_management(
            self.test_bucket, mock_s3_client, mock_kms_client
        )
        
        self.assertFalse(result['kms_managed'])
        self.assertFalse(result['is_compliant'])

    def test_check_kms_key_management_kms_with_rotation(self):
        """Test KMS key management check with KMS and rotation."""
        mock_s3_client = Mock()
        mock_kms_client = Mock()
        
        mock_s3_client.get_bucket_encryption.return_value = {
            'ServerSideEncryptionConfiguration': {
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'aws:kms',
                        'KMSMasterKeyID': 'test-key-id'
                    }
                }]
            }
        }
        
        mock_kms_client.get_key_rotation_status.return_value = {
            'KeyRotationEnabled': True
        }
        
        result = self.checker._check_kms_key_management(
            self.test_bucket, mock_s3_client, mock_kms_client
        )
        
        self.assertTrue(result['kms_managed'])
        self.assertTrue(result['key_rotation_enabled'])
        self.assertTrue(result['is_compliant'])

    def test_check_cloudtrail_logging_enabled(self):
        """Test CloudTrail logging check when enabled."""
        mock_cloudtrail_client = Mock()
        
        mock_cloudtrail_client.describe_trails.return_value = {
            'trailList': [{'Name': 'test-trail'}]
        }
        
        mock_cloudtrail_client.get_event_selectors.return_value = {
            'EventSelectors': [{
                'DataResources': [{
                    'Type': 'AWS::S3::Object',
                    'Values': [f'arn:aws:s3:::{self.test_bucket}/*']
                }]
            }]
        }
        
        result = self.checker._check_cloudtrail_logging(
            self.test_bucket, mock_cloudtrail_client
        )
        
        self.assertTrue(result['is_enabled'])
        self.assertEqual(result['trails_count'], 1)

    def test_check_data_residency_compliant_region(self):
        """Test data residency check for compliant region."""
        mock_s3_client = Mock()
        mock_s3_client.get_bucket_location.return_value = {
            'LocationConstraint': 'eu-west-1'
        }
        
        result = self.checker._check_data_residency(
            self.test_bucket, mock_s3_client, 'eu-west-1'
        )
        
        self.assertTrue(result['compliant_region'])
        self.assertEqual(result['bucket_region'], 'eu-west-1')

    def test_check_data_residency_non_compliant_region(self):
        """Test data residency check for non-compliant region."""
        mock_s3_client = Mock()
        mock_s3_client.get_bucket_location.return_value = {
            'LocationConstraint': 'us-east-1'
        }
        
        result = self.checker._check_data_residency(
            self.test_bucket, mock_s3_client, 'us-east-1'
        )
        
        self.assertFalse(result['compliant_region'])
        self.assertEqual(result['bucket_region'], 'us-east-1')

    def test_check_international_transfers_no_replication(self):
        """Test international transfers check with no replication."""
        mock_s3_client = Mock()
        from botocore.exceptions import ClientError
        
        mock_s3_client.get_bucket_replication.side_effect = ClientError(
            {'Error': {'Code': 'ReplicationConfigurationNotFoundError'}}, 
            'GetBucketReplication'
        )
        
        result = self.checker._check_international_transfers(
            self.test_bucket, mock_s3_client
        )
        
        self.assertTrue(result['compliant_transfers'])
        self.assertEqual(result['replication_rules_count'], 0)

    def test_check_purpose_limitation_with_tags(self):
        """Test purpose limitation check with purpose tags."""
        mock_s3_client = Mock()
        mock_s3_client.get_bucket_tagging.return_value = {
            'TagSet': [
                {'Key': 'DataPurpose', 'Value': 'Marketing'},
                {'Key': 'Environment', 'Value': 'Production'}
            ]
        }
        
        result = self.checker._check_purpose_limitation(
            self.test_bucket, mock_s3_client
        )
        
        self.assertTrue(result['purpose_restricted'])
        self.assertEqual(len(result['purpose_tags']), 1)
        self.assertEqual(result['total_tags'], 2)

    def test_check_transfer_acceleration_enabled(self):
        """Test transfer acceleration check when enabled."""
        mock_s3_client = Mock()
        mock_s3_client.get_bucket_accelerate_configuration.return_value = {
            'Status': 'Enabled'
        }
        
        result = self.checker._check_transfer_acceleration(
            self.test_bucket, mock_s3_client
        )
        
        self.assertTrue(result['is_enabled'])
        self.assertTrue(result['is_properly_configured'])
        self.assertEqual(result['status'], 'Enabled')

    def test_check_website_hosting_enabled(self):
        """Test website hosting check when enabled."""
        mock_s3_client = Mock()
        mock_s3_client.get_bucket_website.return_value = {
            'IndexDocument': {'Suffix': 'index.html'}
        }
        
        result = self.checker._check_website_hosting(
            self.test_bucket, mock_s3_client
        )
        
        self.assertTrue(result['is_enabled'])
        self.assertFalse(result['is_secure'])  # Website hosting with personal data is risky

    def test_check_website_hosting_disabled(self):
        """Test website hosting check when disabled."""
        mock_s3_client = Mock()
        from botocore.exceptions import ClientError
        
        mock_s3_client.get_bucket_website.side_effect = ClientError(
            {'Error': {'Code': 'NoSuchWebsiteConfiguration'}}, 
            'GetBucketWebsite'
        )
        
        result = self.checker._check_website_hosting(
            self.test_bucket, mock_s3_client
        )
        
        self.assertFalse(result['is_enabled'])
        self.assertTrue(result['is_secure'])

    def test_check_inventory_config_with_configs(self):
        """Test inventory configuration check with configurations."""
        mock_s3_client = Mock()
        mock_s3_client.list_bucket_inventory_configurations.return_value = {
            'InventoryConfigurationList': [
                {'Id': 'test-inventory-1'},
                {'Id': 'test-inventory-2'}
            ]
        }
        
        result = self.checker._check_inventory_config(
            self.test_bucket, mock_s3_client
        )
        
        self.assertTrue(result['has_inventory'])
        self.assertEqual(result['config_count'], 2)

    def test_check_analytics_config_with_configs(self):
        """Test analytics configuration check with configurations."""
        mock_s3_client = Mock()
        mock_s3_client.list_bucket_analytics_configurations.return_value = {
            'AnalyticsConfigurationList': [
                {'Id': 'test-analytics-1'}
            ]
        }
        
        result = self.checker._check_analytics_config(
            self.test_bucket, mock_s3_client
        )
        
        self.assertTrue(result['has_analytics'])
        self.assertFalse(result['is_secure'])  # Analytics with personal data should be secured
        self.assertEqual(result['config_count'], 1)

    def test_get_default_gdpr_results(self):
        """Test default GDPR results structure."""
        result = self.checker._get_default_gdpr_results()
        
        expected_keys = [
            'kms_key_management',
            'cloudtrail_logging',
            'gdpr_data_residency',
            'gdpr_international_transfers',
            'gdpr_replication_compliance',
            'gdpr_purpose_limitation',
            'transfer_acceleration',
            'website_hosting',
            'inventory_config',
            'analytics_config'
        ]
        
        for key in expected_keys:
            self.assertIn(key, result)

    def test_error_handling(self):
        """Test error handling in GDPR compliance check."""
        # Mock session to raise exception
        self.mock_session.client.side_effect = Exception("Test error")
        
        result = self.checker.check_gdpr_compliance_features(self.test_bucket, self.test_region)
        
        # Should return default results when error occurs
        self.assertIsInstance(result, dict)
        
        # Verify default structure is returned
        self.assertIn('kms_key_management', result)
        self.assertFalse(result['kms_key_management']['kms_managed'])


if __name__ == '__main__':
    unittest.main()
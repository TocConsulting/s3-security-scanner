"""Tests for SOC 2 monitoring module."""

import unittest
from unittest.mock import Mock, patch
from datetime import datetime
from botocore.exceptions import ClientError

from s3_security_scanner.checks.soc2_monitoring import SOC2MonitoringChecker


class TestSOC2MonitoringChecker(unittest.TestCase):
    """Test cases for SOC2MonitoringChecker class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.mock_session = Mock()
        # Create a session factory that returns the mock session
        self.session_factory = lambda: self.mock_session
        self.checker = SOC2MonitoringChecker(self.session_factory, 'us-east-1')
    
    def test_init(self):
        """Test SOC2MonitoringChecker initialization."""
        self.assertEqual(self.checker.session_factory, self.session_factory)
        self.assertEqual(self.checker.region, 'us-east-1')
        # Clients should not be created in __init__ anymore
    
    def test_check_kms_key_management_no_encryption(self):
        """Test KMS key management check with no encryption."""
        mock_s3_client = Mock()
        mock_s3_client.get_bucket_encryption.side_effect = ClientError(
            {'Error': {'Code': 'ServerSideEncryptionConfigurationNotFoundError'}}, 
            'GetBucketEncryption'
        )
        
        result = self.checker.check_kms_key_management('test-bucket', mock_s3_client)
        
        self.assertFalse(result['kms_managed'])
        self.assertEqual(result['error'], 'No encryption configuration found')
    
    def test_check_kms_key_management_with_kms(self):
        """Test KMS key management check with KMS encryption."""
        mock_s3_client = Mock()
        mock_kms_client = Mock()
        mock_sts_client = Mock()
        
        # Mock encryption configuration
        encryption_config = {
            'Rules': [{
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'aws:kms',
                    'KMSMasterKeyID': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012'
                }
            }]
        }
        
        # Mock KMS describe key response
        mock_kms_client.describe_key.return_value = {
            'KeyMetadata': {
                'KeyId': '12345678-1234-1234-1234-123456789012',
                'Arn': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
                'KeyManager': 'CUSTOMER',
                'KeyUsage': 'ENCRYPT_DECRYPT',
                'KeySpec': 'SYMMETRIC_DEFAULT',
                'CreationDate': datetime.now(),
                'Enabled': True
            }
        }
        
        # Mock key rotation status
        mock_kms_client.get_key_rotation_status.return_value = {
            'KeyRotationEnabled': True
        }
        
        # Mock key policy
        mock_kms_client.get_key_policy.return_value = {
            'Policy': '{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*", "Resource": "*"}]}'
        }
        
        # Mock STS for account ID
        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        
        # Mock the session to return the appropriate clients
        def mock_client(service, **kwargs):
            if service == 'kms':
                return mock_kms_client
            elif service == 'sts':
                return mock_sts_client
            return Mock()
        
        self.mock_session.client = mock_client
        
        result = self.checker.check_kms_key_management('test-bucket', mock_s3_client, encryption_config)
        
        self.assertTrue(result['kms_managed'])
        self.assertEqual(result['total_keys'], 1)
        self.assertEqual(result['customer_managed_keys'], 1)
        self.assertEqual(result['keys_with_rotation'], 1)
        self.assertEqual(result['rotation_compliance_percent'], 100.0)
    
    def test_analyze_kms_key(self):
        """Test individual KMS key analysis."""
        mock_kms_client = Mock()
        mock_sts_client = Mock()
        
        # Mock key metadata
        mock_kms_client.describe_key.return_value = {
            'KeyMetadata': {
                'KeyId': '12345678-1234-1234-1234-123456789012',
                'Arn': 'arn:aws:kms:us-east-1:123456789012:key/12345678-1234-1234-1234-123456789012',
                'KeyManager': 'CUSTOMER',
                'KeyUsage': 'ENCRYPT_DECRYPT',
                'KeySpec': 'SYMMETRIC_DEFAULT',
                'CreationDate': datetime.now(),
                'Enabled': True
            }
        }
        
        # Mock rotation status
        mock_kms_client.get_key_rotation_status.return_value = {
            'KeyRotationEnabled': True
        }
        
        # Mock key policy
        mock_kms_client.get_key_policy.return_value = {
            'Policy': '{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:root"}, "Action": "kms:*", "Resource": "*"}]}'
        }
        
        # Mock STS for account ID
        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        
        # Mock the session to return the appropriate clients
        def mock_client(service, **kwargs):
            if service == 'kms':
                return mock_kms_client
            elif service == 'sts':
                return mock_sts_client
            return Mock()
        
        self.mock_session.client = mock_client
        
        result = self.checker._analyze_kms_key('test-key-id')
        
        self.assertEqual(result['key_manager'], 'CUSTOMER')
        self.assertTrue(result['rotation_enabled'])
        self.assertTrue(result['policy_compliant'])
        self.assertEqual(len(result['cross_account_access']), 0)
    
    def test_analyze_key_policy_wildcard_principal(self):
        """Test key policy analysis with wildcard principal."""
        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        
        # Mock the session to return the STS client
        self.mock_session.client = lambda service, **kwargs: mock_sts_client if service == 'sts' else Mock()
        
        # Policy with wildcard principal should be non-compliant
        policy = {
            'Statement': [{
                'Effect': 'Allow',
                'Principal': '*',
                'Action': 'kms:*'
            }]
        }
            
        result = self.checker._analyze_key_policy(policy)
        self.assertFalse(result)
    
    def test_check_cloudwatch_monitoring(self):
        """Test CloudWatch monitoring check."""
        mock_cw_client = Mock()
        
        # Mock S3 metrics
        mock_cw_client.list_metrics.return_value = {
            'Metrics': [
                {'MetricName': 'BucketSizeBytes', 'Namespace': 'AWS/S3'},
                {'MetricName': 'NumberOfObjects', 'Namespace': 'AWS/S3'}
            ]
        }
        
        # Mock CloudWatch alarms
        mock_paginator = Mock()
        mock_paginator.paginate.return_value = [
            {
                'MetricAlarms': [
                    {
                        'AlarmName': 'S3-BucketSize-Alarm',
                        'Namespace': 'AWS/S3',
                        'MetricName': 'BucketSizeBytes',
                        'Dimensions': [{'Name': 'BucketName', 'Value': 'test-bucket'}]
                    }
                ]
            }
        ]
        mock_cw_client.get_paginator.return_value = mock_paginator
        
        # Mock metric statistics
        mock_cw_client.get_metric_statistics.return_value = {
            'Datapoints': [
                {'Average': 1024000, 'Timestamp': datetime.now()}
            ]
        }
        
        # Mock the session to return the CloudWatch client
        self.mock_session.client = lambda service, **kwargs: mock_cw_client if service == 'cloudwatch' else Mock()
        
        result = self.checker.check_cloudwatch_monitoring('test-bucket', 'us-east-1')
        
        self.assertTrue(result['monitoring_enabled'])
        self.assertEqual(result['metric_count'], 2)
        self.assertEqual(result['alarm_count'], 1)
        self.assertTrue(result['recent_activity']['monitoring_active'])
        self.assertGreater(result['monitoring_compliance']['monitoring_score'], 0)
    
    def test_check_storage_lens_configuration(self):
        """Test Storage Lens configuration check."""
        mock_s3control_client = Mock()
        
        # Mock list configurations
        mock_s3control_client.list_storage_lens_configurations.return_value = {
            'StorageLensConfigurationList': [
                {'Id': 'default-account-dashboard', 'IsEnabled': True}
            ]
        }
        
        # Mock detailed configuration
        mock_s3control_client.get_storage_lens_configuration.return_value = {
            'StorageLensConfiguration': {
                'Id': 'default-account-dashboard',
                'IsEnabled': True,
                'DataExport': {
                    'S3BucketDestination': {'Bucket': 'storage-lens-exports'},
                    'CloudWatchMetrics': {'IsEnabled': True}
                },
                'AccountLevel': {
                    'AdvancedCostOptimizationMetrics': {'IsEnabled': True},
                    'AdvancedDataProtectionMetrics': {'IsEnabled': True}
                }
            }
        }
        
        # Mock the session to return the S3 Control client
        self.mock_session.client = lambda service, **kwargs: mock_s3control_client if service == 's3control' else Mock()
        
        result = self.checker.check_storage_lens_configuration('123456789012')
        
        self.assertTrue(result['storage_lens_enabled'])
        self.assertEqual(result['configuration_count'], 1)
        self.assertTrue(result['default_config_analysis']['IsEnabled'])
        self.assertEqual(result['governance_compliance']['governance_score'], 100)
    
    def test_check_storage_lens_access_denied(self):
        """Test Storage Lens check with access denied."""
        mock_s3control_client = Mock()
        mock_s3control_client.list_storage_lens_configurations.side_effect = ClientError(
            {'Error': {'Code': 'AccessDeniedException'}}, 
            'ListStorageLensConfigurations'
        )
        
        # Mock the session to return the S3 Control client
        self.mock_session.client = lambda service, **kwargs: mock_s3control_client if service == 's3control' else Mock()
        
        result = self.checker.check_storage_lens_configuration('123456789012')
        
        self.assertFalse(result['storage_lens_enabled'])
        self.assertIn('Access denied', result['error'])
    
    def test_calculate_monitoring_score(self):
        """Test monitoring score calculation."""
        # Test with comprehensive metrics and alarms
        metrics = [
            {'MetricName': 'BucketSizeBytes'},
            {'MetricName': 'NumberOfObjects'},
            {'MetricName': 'GetRequests'}
        ]
        alarms = [
            {'AlarmName': 'test-alarm'}
        ]
        
        score = self.checker._calculate_monitoring_score(metrics, alarms)
        self.assertEqual(score, 100)  # 30 + 20 + 10 + 20 + 20 = 100
        
        # Test with no metrics or alarms
        score = self.checker._calculate_monitoring_score([], [])
        self.assertEqual(score, 0)
    
    def test_check_cross_account_key_access(self):
        """Test cross-account key access detection."""
        mock_sts_client = Mock()
        mock_sts_client.get_caller_identity.return_value = {'Account': '123456789012'}
        
        # Mock the session to return the STS client
        self.mock_session.client = lambda service, **kwargs: mock_sts_client if service == 'sts' else Mock()
        
        # Policy with cross-account access
        policy = {
            'Statement': [{
                'Effect': 'Allow',
                'Principal': {
                    'AWS': [
                        'arn:aws:iam::123456789012:user/local-user',
                        'arn:aws:iam::999999999999:user/external-user'
                    ]
                },
                'Action': 'kms:*'
            }]
        }
        
        result = self.checker._check_cross_account_key_access(policy)
        self.assertEqual(len(result), 1)
        self.assertIn('arn:aws:iam::999999999999:user/external-user', result)


if __name__ == "__main__":
    unittest.main()
"""Tests for scanner module."""

import unittest
from unittest.mock import Mock, patch
from moto import mock_aws
import boto3
from s3_security_scanner.scanner import S3SecurityScanner
from s3_security_scanner.analyzers.pattern_analyzer import PatternAnalyzer


class TestS3SecurityScanner(unittest.TestCase):
    """Test cases for S3SecurityScanner class."""
    
    @mock_aws
    def test_get_all_buckets(self):
        """Test getting all S3 buckets."""
        # Create mock S3 client
        s3 = boto3.client('s3', region_name='us-east-1')
        
        # Create test buckets
        s3.create_bucket(Bucket='test-bucket-1')
        s3.create_bucket(Bucket='test-bucket-2')
        
        # Initialize scanner
        scanner = S3SecurityScanner(region='us-east-1')
        
        # Get buckets
        buckets = scanner.get_all_buckets()
        
        # Verify results
        self.assertEqual(len(buckets), 2)
        bucket_names = [b['Name'] for b in buckets]
        self.assertIn('test-bucket-1', bucket_names)
        self.assertIn('test-bucket-2', bucket_names)
    
    @mock_aws
    def test_check_bucket_versioning(self):
        """Test checking bucket versioning."""
        # Create mock S3 client
        s3 = boto3.client('s3', region_name='us-east-1')
        
        # Create test bucket
        bucket_name = 'test-versioning-bucket'
        s3.create_bucket(Bucket=bucket_name)
        
        # Enable versioning
        s3.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        
        # Initialize scanner
        scanner = S3SecurityScanner(region='us-east-1')
        
        # Check versioning
        result = scanner.check_versioning(bucket_name, s3)
        
        # Verify results
        self.assertTrue(result['is_enabled'])
        self.assertEqual(result['status'], 'Enabled')
    
    def test_extract_bucket_info_from_endpoint(self):
        """Test extracting bucket info from S3 endpoints."""
        scanner = S3SecurityScanner(region='us-east-1')
        
        # Test S3 website endpoint
        result = scanner.dns_security_checker.extract_bucket_info_from_endpoint('docs.example.com.s3-website-eu-west-1.amazonaws.com')
        self.assertEqual(result['bucket_name'], 'docs.example.com')
        self.assertEqual(result['region'], 'eu-west-1')
        
        # Test S3 direct endpoint
        result = scanner.dns_security_checker.extract_bucket_info_from_endpoint('my-bucket.s3.amazonaws.com')
        self.assertEqual(result['bucket_name'], 'my-bucket')
        self.assertEqual(result['region'], 'us-east-1')
        
        # Test invalid endpoint
        result = scanner.dns_security_checker.extract_bucket_info_from_endpoint('not-an-s3-endpoint.com')
        self.assertIsNone(result['bucket_name'])
        self.assertIsNone(result['region'])
    
    def test_is_s3_endpoint(self):
        """Test S3 endpoint detection."""
        scanner = S3SecurityScanner(region='us-east-1')
        
        # Valid S3 endpoints
        self.assertTrue(scanner.dns_security_checker._is_s3_endpoint('bucket.s3-website-us-east-1.amazonaws.com'))
        self.assertTrue(scanner.dns_security_checker._is_s3_endpoint('bucket.s3.amazonaws.com'))
        self.assertTrue(scanner.dns_security_checker._is_s3_endpoint('bucket.s3-us-west-2.amazonaws.com'))
        
        # Invalid endpoints
        self.assertFalse(scanner.dns_security_checker._is_s3_endpoint('example.com'))
        self.assertFalse(scanner.dns_security_checker._is_s3_endpoint('s3.amazonaws.com'))
        self.assertFalse(scanner.dns_security_checker._is_s3_endpoint('cloudfront.net'))
    
    @mock_aws
    def test_check_bucket_ownership_in_region_owned(self):
        """Test bucket ownership check for owned bucket."""
        # Create mock S3 client and bucket
        s3 = boto3.client('s3', region_name='us-east-1')
        bucket_name = 'test-owned-bucket'
        s3.create_bucket(Bucket=bucket_name)
        
        # Initialize scanner
        scanner = S3SecurityScanner(region='us-east-1')
        
        # Check ownership
        result = scanner.dns_security_checker.check_bucket_ownership_in_region(bucket_name, 'us-east-1')
        
        # Verify results
        self.assertTrue(result['exists'])
        self.assertTrue(result['owned_by_us'])
        self.assertIsNone(result['error'])
    
    @mock_aws 
    def test_check_bucket_ownership_in_region_not_found(self):
        """Test bucket ownership check for non-existent bucket."""
        scanner = S3SecurityScanner(region='us-east-1')
        
        # Check non-existent bucket
        result = scanner.dns_security_checker.check_bucket_ownership_in_region('non-existent-bucket', 'us-east-1')
        
        # Verify results
        self.assertFalse(result['exists'])
        self.assertFalse(result['owned_by_us'])
        self.assertEqual(result['error'], 'NoSuchBucket')
    
    @patch('s3_security_scanner.checks.dns_security.dns.resolver.Resolver')
    def test_check_cname_record(self, mock_resolver_class):
        """Test CNAME record checking."""
        # Mock DNS resolver
        mock_resolver = Mock()
        mock_resolver_class.return_value = mock_resolver
        
        # Mock CNAME response
        mock_answer = Mock()
        mock_answer.target = 'bucket.s3-website-us-east-1.amazonaws.com.'
        mock_resolver.resolve.return_value = [mock_answer]
        
        scanner = S3SecurityScanner(region='us-east-1')
        
        # Check CNAME
        result = scanner.dns_security_checker.check_cname_record('subdomain.example.com')
        
        # Verify results
        self.assertEqual(len(result), 1)
        self.assertEqual(result[0], 'bucket.s3-website-us-east-1.amazonaws.com')

    def test_extract_bucket_naming_patterns(self):
        """Test bucket naming pattern extraction."""
        
        # Test case 1: Complex bucket name with all patterns
        bucket_name = "myorg-prod-api-v2"
        pattern_analyzer = PatternAnalyzer()
        patterns = pattern_analyzer.extract_bucket_naming_patterns(bucket_name)
        
        self.assertEqual(patterns['components'], ['myorg', 'prod', 'api', 'v2'])
        self.assertEqual(patterns['separators'], ['-'])
        self.assertEqual(patterns['environments'], ['prod'])
        self.assertEqual(patterns['business_indicators'], ['api'])
        self.assertEqual(patterns['version_indicators'], ['v2'])
        self.assertTrue(patterns['has_org_prefix'])
        self.assertTrue(patterns['has_predictable_structure'])
        self.assertEqual(patterns['sensitive_keywords'], [])
        
        # Test case 2: Bucket with sensitive keywords
        bucket_name = "company-secret-key-backup"
        patterns = pattern_analyzer.extract_bucket_naming_patterns(bucket_name)
        
        self.assertEqual(patterns['sensitive_keywords'], ['secret', 'key'])
        self.assertEqual(patterns['business_indicators'], ['backup'])
        
        # Test case 3: Simple bucket name
        bucket_name = "simplebucket"
        patterns = pattern_analyzer.extract_bucket_naming_patterns(bucket_name)
        
        self.assertEqual(patterns['components'], ['simplebucket'])
        self.assertEqual(patterns['separators'], [])
        self.assertFalse(patterns['has_org_prefix'])
        self.assertFalse(patterns['has_predictable_structure'])

    def test_assess_information_disclosure_risk(self):
        """Test information disclosure risk assessment."""
        pattern_analyzer = PatternAnalyzer()
        
        # Test case 1: Critical risk - sensitive keywords + predictable structure
        patterns = {
            'components': ['myorg', 'prod', 'secrets', 'v1'],
            'separators': ['-'],
            'environments': ['prod'],
            'business_indicators': ['secrets'],
            'version_indicators': ['v1'],
            'has_org_prefix': True,
            'has_predictable_structure': True,
            'sensitive_keywords': ['secrets']
        }
        
        risk_assessment = pattern_analyzer.assess_information_disclosure_risk("myorg-prod-secrets-v1", patterns)
        
        self.assertEqual(risk_assessment['risk_level'], 'CRITICAL')
        self.assertEqual(risk_assessment['severity'], 'HIGH')
        self.assertIn('Contains sensitive keywords: secrets', risk_assessment['disclosed_info'])
        self.assertIn('Reveals environment: prod', risk_assessment['disclosed_info'])
        self.assertIn('Follows predictable naming pattern that enables enumeration', risk_assessment['disclosed_info'])
        
        # Test case 2: Critical risk - environment + business logic (4 risk factors)
        patterns = {
            'components': ['myorg', 'staging', 'api'],
            'separators': ['-'],
            'environments': ['staging'],
            'business_indicators': ['api'],
            'version_indicators': [],
            'has_org_prefix': True,
            'has_predictable_structure': True,
            'sensitive_keywords': []
        }
        
        risk_assessment = pattern_analyzer.assess_information_disclosure_risk("myorg-staging-api", patterns)
        
        # The logic sets it to CRITICAL if >= 3 risk factors + predictable structure
        # We have: environment, business, org prefix, predictable structure
        # So it will be CRITICAL, not MODERATE
        self.assertEqual(risk_assessment['risk_level'], 'CRITICAL')
        self.assertEqual(risk_assessment['severity'], 'HIGH')
        
        # Test case 3: No risk - simple bucket
        patterns = {
            'components': ['simplebucket'],
            'separators': [],
            'environments': [],
            'business_indicators': [],
            'version_indicators': [],
            'has_org_prefix': False,
            'has_predictable_structure': False,
            'sensitive_keywords': []
        }
        
        risk_assessment = pattern_analyzer.assess_information_disclosure_risk("simplebucket", patterns)
        
        self.assertEqual(risk_assessment['risk_level'], 'NONE')
        self.assertEqual(risk_assessment['severity'], 'INFO')

    def test_check_bucket_enumeration_risk(self):
        """Test bucket enumeration risk assessment."""
        pattern_analyzer = PatternAnalyzer()
        
        # Test case 1: Predictable structure enables enumeration
        patterns = {
            'components': ['myorg', 'prod', 'api', 'v2'],
            'separators': ['-'],
            'environments': ['prod'],
            'business_indicators': ['api'],
            'version_indicators': ['v2'],
            'has_org_prefix': True,
            'has_predictable_structure': True,
            'sensitive_keywords': []
        }
        
        enumeration_risks = pattern_analyzer.check_bucket_enumeration_risk("myorg-prod-api-v2", patterns)
        
        # Should generate alternative buckets
        self.assertGreater(len(enumeration_risks), 0)
        self.assertIn('myorg-dev-api-v2', enumeration_risks)
        self.assertIn('myorg-prod-web-v2', enumeration_risks)
        # Check that the enumeration generates alternatives and is limited to 10
        self.assertLessEqual(len(enumeration_risks), 10)  # Should be limited to 10
        
        # Test case 2: No predictable structure - no enumeration risk
        patterns = {
            'components': ['randomname'],
            'separators': [],
            'environments': [],
            'business_indicators': [],
            'version_indicators': [],
            'has_org_prefix': False,
            'has_predictable_structure': False,
            'sensitive_keywords': []
        }
        
        enumeration_risks = pattern_analyzer.check_bucket_enumeration_risk("randomname", patterns)
        
        # Should not generate any enumeration risks
        self.assertEqual(len(enumeration_risks), 0)

    def test_analyze_cname_information_disclosure(self):
        """Test CNAME information disclosure analysis."""
        scanner = S3SecurityScanner(region='us-east-1')
        
        # Mock route53 records
        route53_records = [
            {
                'zone_name': 'example.com',
                'record_name': 'api.example.com',
                'record_type': 'CNAME',
                's3_endpoint': 'myorg-prod-api-v2.s3-website-us-east-1.amazonaws.com',
                'ttl': 300
            },
            {
                'zone_name': 'example.com',
                'record_name': 'assets.example.com',
                'record_type': 'A',  # Not CNAME, should be skipped
                's3_endpoint': 'assets-bucket.s3.amazonaws.com',
                'ttl': 300
            },
            {
                'zone_name': 'example.com',
                'record_name': 'docs.example.com',
                'record_type': 'CNAME',
                's3_endpoint': 'simple-bucket.s3.amazonaws.com',
                'ttl': 300
            }
        ]
        
        # Mock extract_bucket_info_from_endpoint
        def mock_extract_bucket_info(endpoint):
            if 'myorg-prod-api-v2' in endpoint:
                return {'bucket_name': 'myorg-prod-api-v2', 'region': 'us-east-1'}
            elif 'simple-bucket' in endpoint:
                return {'bucket_name': 'simple-bucket', 'region': 'us-east-1'}
            return {'bucket_name': None, 'region': None}
        
        # Use DNS analyzer directly for CNAME analysis
        from s3_security_scanner.analyzers.dns_analyzer import DNSAnalyzer
        dns_analyzer = DNSAnalyzer(scanner.logger)
        dns_analyzer._extract_bucket_info_from_endpoint = mock_extract_bucket_info
        
        # Analyze CNAME vulnerabilities
        vulnerabilities = dns_analyzer.analyze_cname_information_disclosure(route53_records)
        
        # Should find vulnerability for the predictable bucket name (simple-bucket has no risk)
        self.assertGreaterEqual(len(vulnerabilities), 1)
        
        vuln = vulnerabilities[0]
        self.assertEqual(vuln['source'], 'cname_analysis')
        self.assertEqual(vuln['domain'], 'api.example.com')
        self.assertEqual(vuln['bucket_name'], 'myorg-prod-api-v2')
        self.assertEqual(vuln['vulnerability'], 'information_disclosure')
        self.assertIn('severity', vuln)
        self.assertIn('disclosed_information', vuln)
        self.assertIn('enumeration_risks', vuln)

    def test_cname_vulnerability_integration(self):
        """Test full integration of CNAME vulnerability detection in scan_subdomain_takeover."""
        scanner = S3SecurityScanner(region='us-east-1')
        
        # Mock the discover_route53_records method
        def mock_discover_route53_records():
            return [
                {
                    'zone_name': 'example.com',
                    'record_name': 'api.example.com',
                    'record_type': 'CNAME',
                    's3_endpoint': 'myorg-prod-api-secrets.s3-website-us-east-1.amazonaws.com',
                    'ttl': 300
                }
            ]
        
        # Mock the analyze_route53_takeover_risks method
        def mock_analyze_route53_takeover_risks():
            return []
        
        # Mock extract_bucket_info_from_endpoint
        def mock_extract_bucket_info(endpoint):
            return {'bucket_name': 'myorg-prod-api-secrets', 'region': 'us-east-1'}
        
        scanner.dns_security_checker.discover_route53_records = mock_discover_route53_records
        scanner.dns_security_checker.analyze_route53_takeover_risks = mock_analyze_route53_takeover_risks
        scanner.dns_security_checker.extract_bucket_info_from_endpoint = mock_extract_bucket_info
        
        # Run the scan
        results = scanner.scan_subdomain_takeover()
        
        # Should detect CNAME vulnerability
        self.assertGreater(results['cname_vulnerabilities_found'], 0)
        self.assertGreater(results['total_vulnerabilities_found'], 0)
        
        # Find the CNAME vulnerability
        cname_vuln = None
        for vuln in results['vulnerabilities']:
            if vuln.get('source') == 'cname_analysis':
                cname_vuln = vuln
                break
        
        self.assertIsNotNone(cname_vuln)
        self.assertEqual(cname_vuln['vulnerability'], 'information_disclosure')
        self.assertEqual(cname_vuln['bucket_name'], 'myorg-prod-api-secrets')
        self.assertEqual(cname_vuln['severity'], 'HIGH')  # Should be HIGH due to 'secrets' keyword

    def test_check_wildcard_principal(self):
        """Test checking for wildcard principal in bucket policy."""
        scanner = S3SecurityScanner(region='us-east-1')
        mock_client = Mock()
        
        # Test bucket with wildcard principal policy
        mock_client.get_bucket_policy.return_value = {
            'Policy': '{"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject"}]}'
        }
        
        result = scanner.check_wildcard_principal('test-bucket', mock_client)
        self.assertTrue(result['has_wildcard_principal'])
        self.assertEqual(len(result['wildcard_statements']), 1)
        
        # Test bucket with specific principal policy
        mock_client.get_bucket_policy.return_value = {
            'Policy': '{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789:user/test"}, "Action": "s3:GetObject"}]}'
        }
        
        result = scanner.check_wildcard_principal('test-bucket', mock_client)
        self.assertFalse(result['has_wildcard_principal'])
        self.assertEqual(len(result['wildcard_statements']), 0)

    def test_check_event_notifications(self):
        """Test checking bucket event notifications."""
        scanner = S3SecurityScanner(region='us-east-1')
        mock_client = Mock()
        
        # Test bucket with notifications
        mock_client.get_bucket_notification_configuration.return_value = {
            'TopicConfigurations': [{'Id': 'test-sns', 'TopicArn': 'arn:aws:sns:us-east-1:123456789:test'}],
            'QueueConfigurations': [],
            'LambdaConfigurations': []
        }
        
        result = scanner.check_event_notifications('test-bucket', mock_client)
        self.assertTrue(result['has_notifications'])
        self.assertEqual(result['notification_count'], 1)
        self.assertEqual(result['sns_topics'], 1)
        
        # Test bucket without notifications
        mock_client.get_bucket_notification_configuration.return_value = {
            'TopicConfigurations': [],
            'QueueConfigurations': [],
            'LambdaConfigurations': []
        }
        
        result = scanner.check_event_notifications('test-bucket', mock_client)
        self.assertFalse(result['has_notifications'])
        self.assertEqual(result['notification_count'], 0)

    def test_check_replication(self):
        """Test checking bucket replication configuration."""
        scanner = S3SecurityScanner(region='us-east-1')
        mock_client = Mock()
        
        # Test bucket with replication
        mock_client.get_bucket_replication.return_value = {
            'ReplicationConfiguration': {
                'Role': 'arn:aws:iam::123456789:role/replication-role',
                'Rules': [
                    {'Status': 'Enabled', 'Id': 'test-replication'},
                    {'Status': 'Disabled', 'Id': 'test-replication-2'}
                ]
            }
        }
        
        result = scanner.check_replication('test-bucket', mock_client)
        self.assertTrue(result['has_replication'])
        self.assertEqual(result['replication_rule_count'], 2)
        self.assertEqual(result['enabled_rule_count'], 1)
        
        # Test bucket without replication
        from botocore.exceptions import ClientError
        mock_client.get_bucket_replication.side_effect = ClientError(
            {'Error': {'Code': 'ReplicationConfigurationNotFoundError'}}, 'GetBucketReplication'
        )
        
        result = scanner.check_replication('test-bucket', mock_client)
        self.assertFalse(result['has_replication'])
        self.assertEqual(result['replication_rule_count'], 0)

    def test_check_transfer_acceleration(self):
        """Test checking S3 transfer acceleration."""
        scanner = S3SecurityScanner(region='us-east-1')
        mock_client = Mock()
        
        # Test bucket with transfer acceleration enabled
        mock_client.get_bucket_accelerate_configuration.return_value = {
            'Status': 'Enabled'
        }
        
        result = scanner.check_transfer_acceleration('test-bucket', mock_client)
        self.assertTrue(result['is_enabled'])
        self.assertEqual(result['status'], 'Enabled')
        
        # Test bucket without transfer acceleration
        mock_client.get_bucket_accelerate_configuration.return_value = {}
        
        result = scanner.check_transfer_acceleration('test-bucket', mock_client)
        self.assertFalse(result['is_enabled'])
        self.assertEqual(result['status'], 'Suspended')

    def test_check_cross_account_access(self):
        """Test checking cross-account access in bucket policy."""
        scanner = S3SecurityScanner(region='us-east-1')
        mock_client = Mock()
        
        # Mock STS client via session factory
        mock_session = Mock()
        mock_sts = Mock()
        mock_sts.get_caller_identity.return_value = {'Account': '123456789012'}
        
        # Mock the session client method to return appropriate client based on service
        def mock_client_factory(service, **kwargs):
            if service == 'sts':
                return mock_sts
            return Mock()
        
        mock_session.client = mock_client_factory
        
        # Mock the access control checker's session factory
        scanner.access_control_checker.session_factory = lambda: mock_session
        
        # Test bucket with cross-account access
        mock_client.get_bucket_policy.return_value = {
            'Policy': '{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::999999999999:user/external"}, "Action": "s3:GetObject"}]}'
        }
        
        result = scanner.check_cross_account_access('test-bucket', mock_client)
        self.assertTrue(result['has_cross_account_access'])
        self.assertEqual(len(result['cross_account_principals']), 1)
        self.assertEqual(result['cross_account_principals'][0]['account_id'], '999999999999')
        
        # Test bucket without cross-account access
        mock_client.get_bucket_policy.return_value = {
            'Policy': '{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789012:user/internal"}, "Action": "s3:GetObject"}]}'
        }
        
        result = scanner.check_cross_account_access('test-bucket', mock_client)
        self.assertFalse(result['has_cross_account_access'])
        self.assertEqual(len(result['cross_account_principals']), 0)

    def test_check_mfa_requirement(self):
        """Test checking MFA requirement in bucket policy."""
        scanner = S3SecurityScanner(region='us-east-1')
        mock_client = Mock()
        
        # Test bucket with MFA requirement
        mock_client.get_bucket_policy.return_value = {
            'Policy': '{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789:user/test"}, "Action": "s3:*", "Condition": {"Bool": {"aws:MultiFactorAuthPresent": "true"}}}]}'
        }
        
        result = scanner.check_mfa_requirement('test-bucket', mock_client)
        self.assertTrue(result['mfa_required'])
        self.assertEqual(len(result['mfa_statements']), 1)
        
        # Test bucket without MFA requirement
        mock_client.get_bucket_policy.return_value = {
            'Policy': '{"Statement": [{"Effect": "Allow", "Principal": {"AWS": "arn:aws:iam::123456789:user/test"}, "Action": "s3:GetObject"}]}'
        }
        
        result = scanner.check_mfa_requirement('test-bucket', mock_client)
        self.assertFalse(result['mfa_required'])
        self.assertEqual(len(result['mfa_statements']), 0)

    def test_check_data_classification_tagging(self):
        """Test data classification tagging check."""
        scanner = S3SecurityScanner(region='us-east-1')
        mock_client = Mock()
        
        # Mock bucket tagging
        mock_client.get_bucket_tagging.return_value = {
            'TagSet': [
                {'Key': 'DataClassification', 'Value': 'Confidential'},
                {'Key': 'Environment', 'Value': 'Production'}
            ]
        }
        
        # Mock object listing and tagging
        mock_client.get_paginator.return_value.paginate.return_value = [
            {
                'Contents': [
                    {'Key': 'confidential-data.txt', 'Size': 1024},
                    {'Key': 'public-info.txt', 'Size': 512}
                ]
            }
        ]
        
        # Mock object tagging responses
        def mock_get_object_tagging(Bucket, Key):
            if 'confidential' in Key:
                return {'TagSet': [{'Key': 'DataClassification', 'Value': 'confidential'}]}
            else:
                return {'TagSet': []}
        
        mock_client.get_object_tagging.side_effect = mock_get_object_tagging
        
        result = scanner.check_data_classification_tagging('test-bucket', mock_client, sample_size=10)
        
        self.assertIn('bucket_classification', result)
        self.assertIn('total_objects_analyzed', result)
        self.assertIn('classification_coverage_percent', result)
        self.assertEqual(result['total_objects_analyzed'], 2)


if __name__ == "__main__":
    unittest.main()
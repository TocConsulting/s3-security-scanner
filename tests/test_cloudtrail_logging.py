"""Tests for CloudTrail Data Events Logging Checker."""

import unittest
from unittest.mock import Mock, patch, MagicMock
import boto3

from s3_security_scanner.checks.cloudtrail_logging import CloudTrailDataEventsChecker


class TestCloudTrailDataEventsChecker(unittest.TestCase):
    """Test cases for CloudTrail data events checker."""

    def setUp(self):
        """Set up test fixtures."""
        self.session = Mock()
        # Create a session factory that returns the mock session
        self.session_factory = lambda: self.session
        self.checker = CloudTrailDataEventsChecker(self.session_factory)

    def test_get_all_trails_success(self):
        """Test successful retrieval of all trails."""
        # Mock the CloudTrail client response
        mock_client = Mock()
        mock_client.list_trails.return_value = {
            'Trails': [
                {
                    'TrailName': 'test-trail-1',
                    'S3BucketName': 'test-bucket',
                    'IsMultiRegionTrail': True,
                    'HomeRegion': 'us-east-1'
                },
                {
                    'TrailName': 'test-trail-2',
                    'S3BucketName': 'test-bucket',
                    'IsMultiRegionTrail': False,
                    'HomeRegion': 'us-west-2'
                }
            ]
        }
        self.session.client.return_value = mock_client
        
        # Test method
        trails = self.checker.get_all_trails()
        
        # Verify results
        self.assertEqual(len(trails), 2)
        trail_names = [trail['TrailName'] for trail in trails]
        self.assertIn('test-trail-1', trail_names)
        self.assertIn('test-trail-2', trail_names)

    def test_get_all_trails_no_credentials(self):
        """Test handling of no credentials error."""
        # Reset the checker to clear any cache
        self.checker._trails_cache = None
        
        mock_client = Mock()
        mock_client.list_trails.side_effect = Exception("No credentials")
        self.session.client.return_value = mock_client
        
        trails = self.checker.get_all_trails()
        
        self.assertEqual(trails, [])

    def test_get_trail_event_selectors_success(self):
        """Test successful retrieval of event selectors."""
        # Mock the CloudTrail client response
        mock_client = Mock()
        mock_client.get_event_selectors.return_value = {
            'EventSelectors': [
                {
                    'ReadWriteType': 'WriteOnly',
                    'DataResources': [
                        {
                            'Type': 'AWS::S3::Object',
                            'Values': ['arn:aws:s3:::*/*']
                        }
                    ]
                }
            ]
        }
        self.session.client.return_value = mock_client
        
        # Test method
        selectors = self.checker.get_trail_event_selectors('test-trail')
        
        # Verify results - the method now returns a dict with legacy_selectors and advanced_selectors
        self.assertIsInstance(selectors, dict)
        self.assertIn('legacy_selectors', selectors)
        self.assertIn('advanced_selectors', selectors)
        self.assertEqual(len(selectors['legacy_selectors']), 1)
        self.assertEqual(selectors['legacy_selectors'][0]['ReadWriteType'], 'WriteOnly')
        self.assertEqual(selectors['legacy_selectors'][0]['DataResources'][0]['Type'], 'AWS::S3::Object')

    def test_parse_s3_data_events_wildcard_write_only(self):
        """Test parsing S3 data events with wildcard write-only configuration."""
        event_selectors = [
            {
                'ReadWriteType': 'WriteOnly',
                'DataResources': [
                    {
                        'Type': 'AWS::S3::Object',
                        'Values': ['arn:aws:s3:::*/*']
                    }
                ]
            }
        ]
        
        result = self.checker.parse_s3_data_events(event_selectors)
        
        self.assertTrue(result['has_s3_data_events'])
        self.assertTrue(result['write_events_enabled'])
        self.assertFalse(result['read_events_enabled'])
        self.assertTrue(result['all_buckets_covered'])
        self.assertEqual(result['read_write_type'], 'WriteOnly')
        self.assertEqual(result['specific_buckets'], [])

    def test_parse_s3_data_events_specific_buckets_all_events(self):
        """Test parsing S3 data events with specific buckets and all events."""
        event_selectors = [
            {
                'ReadWriteType': 'All',
                'DataResources': [
                    {
                        'Type': 'AWS::S3::Object',
                        'Values': [
                            'arn:aws:s3:::bucket1/*',
                            'arn:aws:s3:::bucket2/*'
                        ]
                    }
                ]
            }
        ]
        
        result = self.checker.parse_s3_data_events(event_selectors)
        
        self.assertTrue(result['has_s3_data_events'])
        self.assertTrue(result['write_events_enabled'])
        self.assertTrue(result['read_events_enabled'])
        self.assertFalse(result['all_buckets_covered'])
        self.assertEqual(result['read_write_type'], 'All')
        self.assertEqual(set(result['specific_buckets']), {'bucket1', 'bucket2'})

    def test_parse_s3_data_events_no_s3_events(self):
        """Test parsing event selectors with no S3 data events."""
        event_selectors = [
            {
                'ReadWriteType': 'All',
                'DataResources': [
                    {
                        'Type': 'AWS::DynamoDB::Table',
                        'Values': ['arn:aws:dynamodb:*:*:table/*']
                    }
                ]
            }
        ]
        
        result = self.checker.parse_s3_data_events(event_selectors)
        
        self.assertFalse(result['has_s3_data_events'])
        self.assertFalse(result['write_events_enabled'])
        self.assertFalse(result['read_events_enabled'])
        self.assertFalse(result['all_buckets_covered'])
        self.assertEqual(result['specific_buckets'], [])

    def test_check_bucket_cloudtrail_coverage_multi_region_trail(self):
        """Test bucket coverage check with multi-region trail."""
        # Mock get_all_trails
        self.checker.get_all_trails = Mock(return_value=[
            {
                'TrailName': 'multi-region-trail',
                'HomeRegion': 'us-east-1',
                'IsMultiRegionTrail': True
            }
        ])
        
        # Mock get_trail_event_selectors
        self.checker.get_trail_event_selectors = Mock(return_value=[
            {
                'ReadWriteType': 'WriteOnly',
                'DataResources': [
                    {
                        'Type': 'AWS::S3::Object',
                        'Values': ['arn:aws:s3:::*/*']
                    }
                ]
            }
        ])
        
        # Test method
        result = self.checker.check_bucket_cloudtrail_coverage('test-bucket', 'us-west-2')
        
        # Verify results
        self.assertTrue(result['is_covered_write_events'])
        self.assertFalse(result['is_covered_read_events'])
        self.assertEqual(len(result['covering_trails']), 1)
        self.assertEqual(result['covering_trails'][0]['trail_name'], 'multi-region-trail')
        self.assertTrue(result['covering_trails'][0]['is_multi_region'])

    def test_check_bucket_cloudtrail_coverage_regional_trail_different_region(self):
        """Test bucket coverage check with regional trail in different region."""
        # Mock get_all_trails
        self.checker.get_all_trails = Mock(return_value=[
            {
                'TrailName': 'regional-trail',
                'HomeRegion': 'us-east-1',
                'IsMultiRegionTrail': False
            }
        ])
        
        # Mock get_trail_event_selectors
        self.checker.get_trail_event_selectors = Mock(return_value=[
            {
                'ReadWriteType': 'All',
                'DataResources': [
                    {
                        'Type': 'AWS::S3::Object',
                        'Values': ['arn:aws:s3:::test-bucket/*']
                    }
                ]
            }
        ])
        
        # Test method - bucket in different region
        result = self.checker.check_bucket_cloudtrail_coverage('test-bucket', 'us-west-2')
        
        # Verify results - should not be covered due to region mismatch
        self.assertFalse(result['is_covered_write_events'])
        self.assertFalse(result['is_covered_read_events'])
        self.assertEqual(len(result['covering_trails']), 0)

    def test_check_bucket_cloudtrail_coverage_specific_bucket_match(self):
        """Test bucket coverage check with specific bucket matching."""
        # Mock get_all_trails
        self.checker.get_all_trails = Mock(return_value=[
            {
                'TrailName': 'specific-trail',
                'HomeRegion': 'us-east-1',
                'IsMultiRegionTrail': False
            }
        ])
        
        # Mock get_trail_event_selectors
        self.checker.get_trail_event_selectors = Mock(return_value=[
            {
                'ReadWriteType': 'All',
                'DataResources': [
                    {
                        'Type': 'AWS::S3::Object',
                        'Values': ['arn:aws:s3:::target-bucket/*']
                    }
                ]
            }
        ])
        
        # Test method - bucket matches specific configuration
        result = self.checker.check_bucket_cloudtrail_coverage('target-bucket', 'us-east-1')
        
        # Verify results
        self.assertTrue(result['is_covered_write_events'])
        self.assertTrue(result['is_covered_read_events'])
        self.assertEqual(len(result['covering_trails']), 1)
        self.assertEqual(result['covering_trails'][0]['read_write_type'], 'All')

    def test_check_cis_s3_22_compliance_compliant(self):
        """Test CIS S3.22 compliance check - compliant case."""
        # Mock bucket coverage check
        self.checker.check_bucket_cloudtrail_coverage = Mock(return_value={
            'is_covered_write_events': True,
            'is_covered_read_events': False,
            'covering_trails': [
                {
                    'trail_name': 'write-trail',
                    'trail_region': 'us-east-1',
                    'is_multi_region': True,
                    'read_write_type': 'WriteOnly'
                }
            ],
            'cloudtrail_available': True
        })
        
        # Test method
        result = self.checker.check_cis_s3_22_compliance('test-bucket', 'us-east-1')
        
        # Verify results
        self.assertTrue(result['is_compliant'])
        self.assertEqual(result['control_id'], 'CIS S3.22')
        self.assertTrue(result['write_events_covered'])
        self.assertEqual(result['covering_trails_count'], 1)
        self.assertIn('Compliant', result['recommendation'])

    def test_check_cis_s3_22_compliance_non_compliant(self):
        """Test CIS S3.22 compliance check - non-compliant case."""
        # Mock bucket coverage check
        self.checker.check_bucket_cloudtrail_coverage = Mock(return_value={
            'is_covered_write_events': False,
            'is_covered_read_events': False,
            'covering_trails': [],
            'cloudtrail_available': True
        })
        
        # Test method
        result = self.checker.check_cis_s3_22_compliance('test-bucket', 'us-east-1')
        
        # Verify results
        self.assertFalse(result['is_compliant'])
        self.assertEqual(result['control_id'], 'CIS S3.22')
        self.assertFalse(result['write_events_covered'])
        self.assertEqual(result['covering_trails_count'], 0)
        self.assertIn('Non-compliant', result['recommendation'])

    def test_check_cis_s3_23_compliance_compliant(self):
        """Test CIS S3.23 compliance check - compliant case."""
        # Mock bucket coverage check
        self.checker.check_bucket_cloudtrail_coverage = Mock(return_value={
            'is_covered_write_events': True,
            'is_covered_read_events': True,
            'covering_trails': [
                {
                    'trail_name': 'all-events-trail',
                    'trail_region': 'us-east-1',
                    'is_multi_region': True,
                    'read_write_type': 'All'
                }
            ],
            'cloudtrail_available': True
        })
        
        # Test method
        result = self.checker.check_cis_s3_23_compliance('test-bucket', 'us-east-1')
        
        # Verify results
        self.assertTrue(result['is_compliant'])
        self.assertEqual(result['control_id'], 'CIS S3.23')
        self.assertTrue(result['read_events_covered'])
        self.assertEqual(result['covering_trails_count'], 1)
        self.assertIn('Compliant', result['recommendation'])

    def test_calculate_bucket_coverage_percentage(self):
        """Test calculation of bucket coverage percentage."""
        # Mock individual bucket coverage checks
        coverage_responses = [
            {'is_covered_write_events': True, 'is_covered_read_events': True},
            {'is_covered_write_events': True, 'is_covered_read_events': False},
            {'is_covered_write_events': False, 'is_covered_read_events': False},
            {'is_covered_write_events': False, 'is_covered_read_events': True}
        ]
        
        def mock_coverage_check(bucket_name, bucket_region):
            return coverage_responses.pop(0)
        
        self.checker.check_bucket_cloudtrail_coverage = Mock(side_effect=mock_coverage_check)
        
        # Test data
        buckets = [
            {'name': 'bucket1', 'region': 'us-east-1'},
            {'name': 'bucket2', 'region': 'us-west-2'},
            {'name': 'bucket3', 'region': 'eu-west-1'},
            {'name': 'bucket4', 'region': 'ap-southeast-1'}
        ]
        
        # Test method
        result = self.checker.calculate_bucket_coverage_percentage(buckets)
        
        # Verify results
        self.assertEqual(result['total_buckets'], 4)
        self.assertEqual(result['covered_buckets_write'], 2)  # bucket1, bucket2
        self.assertEqual(result['covered_buckets_read'], 2)   # bucket1, bucket4
        self.assertEqual(result['coverage_percentage_write'], 50.0)
        self.assertEqual(result['coverage_percentage_read'], 50.0)
        self.assertEqual(len(result['uncovered_buckets']), 2)  # bucket3, bucket4 (for write)

    def test_check_account_cloudtrail_coverage(self):
        """Test account-wide CloudTrail coverage analysis."""
        # Mock get_all_trails
        self.checker.get_all_trails = Mock(return_value=[
            {
                'TrailName': 'global-trail',
                'HomeRegion': 'us-east-1',
                'IsMultiRegionTrail': True
            },
            {
                'TrailName': 'regional-trail',
                'HomeRegion': 'us-west-2',
                'IsMultiRegionTrail': False
            }
        ])
        
        # Mock get_trail_event_selectors
        def mock_event_selectors(trail_name):
            if trail_name == 'global-trail':
                return [
                    {
                        'ReadWriteType': 'WriteOnly',
                        'DataResources': [
                            {
                                'Type': 'AWS::S3::Object',
                                'Values': ['arn:aws:s3:::*/*']
                            }
                        ]
                    }
                ]
            else:
                return [
                    {
                        'ReadWriteType': 'All',
                        'DataResources': [
                            {
                                'Type': 'AWS::S3::Object',
                                'Values': ['arn:aws:s3:::specific-bucket/*']
                            }
                        ]
                    }
                ]
        
        self.checker.get_trail_event_selectors = Mock(side_effect=mock_event_selectors)
        
        # Test method
        result = self.checker.check_account_cloudtrail_coverage(['us-east-1', 'us-west-2'])
        
        # Verify results
        self.assertEqual(result['total_trails'], 2)
        self.assertEqual(result['trails_with_s3_data_events'], 2)
        self.assertEqual(result['multi_region_trails'], 1)
        self.assertEqual(result['regional_trails'], 1)
        self.assertEqual(result['trails_covering_all_buckets'], 1)
        self.assertEqual(result['trails_write_only'], 1)
        self.assertEqual(result['trails_all_events'], 1)
        self.assertTrue(result['has_global_coverage'])
        self.assertEqual(len(result['trails_details']), 2)


if __name__ == '__main__':
    unittest.main()
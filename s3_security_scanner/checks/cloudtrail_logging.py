"""CloudTrail Data Events Logging Checker for S3 Buckets."""

from typing import Dict, Any, List
from botocore.exceptions import ClientError, NoCredentialsError


class CloudTrailDataEventsChecker:
    """Checks CloudTrail data events configuration for S3 buckets."""

    def __init__(self, session_factory=None):
        """Initialize the CloudTrail data events checker.

        Args:
            session_factory: Callable that returns a boto3 session (for thread safety)
        """
        self.session_factory = session_factory
        self._cloudtrail_client = None
        self._trails_cache = None
        self._event_selectors_cache = {}

    @property
    def cloudtrail_client(self):
        """Lazy initialization of CloudTrail client."""
        if self._cloudtrail_client is None:
            session = self.session_factory() if callable(self.session_factory) else self.session_factory
            self._cloudtrail_client = session.client('cloudtrail')
        return self._cloudtrail_client

    def get_all_trails(self) -> List[Dict[str, Any]]:
        """Get all CloudTrail trails (multi-region and regional).

        Returns:
            List of trail dictionaries with trail metadata
        """
        if self._trails_cache is not None:
            return self._trails_cache

        try:
            response = self.cloudtrail_client.list_trails()
            self._trails_cache = response.get('Trails', [])
            return self._trails_cache
        except (ClientError, NoCredentialsError, Exception):
            # Return empty list if CloudTrail access is not available
            return []

    def get_trail_event_selectors(self, trail_name: str) -> List[Dict[str, Any]]:
        """Get event selectors for a specific trail.

        Args:
            trail_name: Name or ARN of the CloudTrail trail

        Returns:
            List of event selectors for the trail
        """
        if trail_name in self._event_selectors_cache:
            return self._event_selectors_cache[trail_name]

        try:
            response = self.cloudtrail_client.get_event_selectors(TrailName=trail_name)

            # Handle both legacy EventSelectors and new AdvancedEventSelectors
            selectors = response.get('EventSelectors', [])
            advanced_selectors = response.get('AdvancedEventSelectors', [])

            # Store both formats for comprehensive parsing
            combined_selectors = {
                'legacy_selectors': selectors,
                'advanced_selectors': advanced_selectors
            }

            self._event_selectors_cache[trail_name] = combined_selectors
            return combined_selectors
        except (ClientError, NoCredentialsError, Exception):
            # Return empty dict if trail is not accessible
            return {'legacy_selectors': [], 'advanced_selectors': []}

    def parse_s3_data_events(self, event_selectors) -> Dict[str, Any]:
        """Parse S3 data events configuration from both legacy and advanced event selectors.

        Args:
            event_selectors: Dictionary containing both legacy and advanced selectors, or legacy list format

        Returns:
            Dictionary containing S3 data events configuration
        """
        s3_data_events = {
            'has_s3_data_events': False,
            'write_events_enabled': False,
            'read_events_enabled': False,
            'all_buckets_covered': False,
            'specific_buckets': set(),
            'read_write_type': None
        }

        # Handle backward compatibility - if we receive a list, treat it as legacy format
        if isinstance(event_selectors, list):
            s3_data_events = self._parse_legacy_event_selectors(event_selectors, s3_data_events)
        elif isinstance(event_selectors, dict):
            # Handle new format with both legacy and advanced selectors
            legacy_selectors = event_selectors.get('legacy_selectors', [])
            if legacy_selectors:
                s3_data_events = self._parse_legacy_event_selectors(legacy_selectors, s3_data_events)

            # Handle advanced EventSelectors format
            advanced_selectors = event_selectors.get('advanced_selectors', [])
            if advanced_selectors:
                s3_data_events = self._parse_advanced_event_selectors(advanced_selectors, s3_data_events)

        # Convert set to list for JSON serialization
        s3_data_events['specific_buckets'] = list(s3_data_events['specific_buckets'])

        return s3_data_events

    def _parse_legacy_event_selectors(self, legacy_selectors: List[Dict[str, Any]], s3_data_events: Dict[str, Any]) -> Dict[str, Any]:
        """Parse legacy EventSelectors format."""
        for selector in legacy_selectors:
            read_write_type = selector.get('ReadWriteType', 'All')
            data_resources = selector.get('DataResources', [])

            for resource in data_resources:
                resource_type = resource.get('Type', '')
                values = resource.get('Values', [])

                # Check for S3 object-level events
                if resource_type == 'AWS::S3::Object':
                    s3_data_events['has_s3_data_events'] = True
                    s3_data_events['read_write_type'] = read_write_type

                    # Check read/write permissions
                    if read_write_type in ['WriteOnly', 'All']:
                        s3_data_events['write_events_enabled'] = True
                    if read_write_type in ['ReadOnly', 'All']:
                        s3_data_events['read_events_enabled'] = True

                    # Parse bucket coverage
                    for value in values:
                        if value in ['arn:aws:s3:::*/*', 'arn:aws:s3:::*']:
                            # All buckets covered (both formats supported)
                            s3_data_events['all_buckets_covered'] = True
                        elif value.startswith('arn:aws:s3:::') and ('/*' in value or value.endswith('*')):
                            # Specific bucket covered
                            bucket_name = value.split(':::')[1].split('/')[0]
                            s3_data_events['specific_buckets'].add(bucket_name)

        return s3_data_events

    def _parse_advanced_event_selectors(self, advanced_selectors: List[Dict[str, Any]], s3_data_events: Dict[str, Any]) -> Dict[str, Any]:
        """Parse advanced EventSelectors format."""
        for selector in advanced_selectors:
            field_selectors = selector.get('FieldSelectors', [])

            # Check if this selector is for S3 data events
            is_s3_data_event = False
            is_s3_object_type = False
            read_write_type = 'All'  # Default for advanced selectors
            resource_arns = []

            for field_selector in field_selectors:
                field = field_selector.get('Field', '')
                equals = field_selector.get('Equals', [])

                # Check for data events
                if field == 'eventCategory' and 'Data' in equals:
                    is_s3_data_event = True

                # Check for S3 object resource type
                if field == 'resources.type' and 'AWS::S3::Object' in equals:
                    is_s3_object_type = True

                # Check for read/write type
                if field == 'readOnly':
                    if 'true' in [str(v).lower() for v in equals]:
                        read_write_type = 'ReadOnly'
                    elif 'false' in [str(v).lower() for v in equals]:
                        read_write_type = 'WriteOnly'

                # Check for resource ARNs
                if field == 'resources.ARN':
                    resource_arns = equals

            # If this is an S3 data event selector
            if is_s3_data_event and is_s3_object_type:
                s3_data_events['has_s3_data_events'] = True
                s3_data_events['read_write_type'] = read_write_type

                # Check read/write permissions
                if read_write_type in ['WriteOnly', 'All']:
                    s3_data_events['write_events_enabled'] = True
                if read_write_type in ['ReadOnly', 'All']:
                    s3_data_events['read_events_enabled'] = True

                # Parse bucket coverage
                if resource_arns:
                    for arn in resource_arns:
                        if arn in ['arn:aws:s3:::*/*', 'arn:aws:s3:::*']:
                            # All buckets covered
                            s3_data_events['all_buckets_covered'] = True
                        elif arn.startswith('arn:aws:s3:::') and ('/*' in arn or arn.endswith('*')):
                            # Specific bucket covered
                            bucket_name = arn.split(':::')[1].split('/')[0]
                            s3_data_events['specific_buckets'].add(bucket_name)
                else:
                    # No resource ARNs specified in advanced selectors means all resources (wildcard)
                    # This is the default behavior for advanced selectors
                    s3_data_events['all_buckets_covered'] = True

        return s3_data_events

    def check_bucket_cloudtrail_coverage(self, bucket_name: str, bucket_region: str) -> Dict[str, Any]:
        """Check if a specific bucket is covered by CloudTrail data events.

        Args:
            bucket_name: Name of the S3 bucket
            bucket_region: AWS region where the bucket is located

        Returns:
            Dictionary containing bucket's CloudTrail coverage status
        """
        trails = self.get_all_trails()

        coverage_result = {
            'bucket_name': bucket_name,
            'bucket_region': bucket_region,
            'is_covered_write_events': False,
            'is_covered_read_events': False,
            'covering_trails': [],
            'total_trails_checked': len(trails),
            'cloudtrail_available': len(trails) > 0
        }

        for trail in trails:
            trail_name = trail.get('TrailName', trail.get('Name', ''))
            trail_region = trail.get('HomeRegion', '')
            is_multi_region = trail.get('IsMultiRegionTrail', False)

            # Skip regional trails that don't match bucket region
            if not is_multi_region and trail_region != bucket_region:
                continue

            event_selectors = self.get_trail_event_selectors(trail_name)
            s3_events = self.parse_s3_data_events(event_selectors)

            # Check if this trail covers our bucket
            bucket_covered = (
                s3_events['all_buckets_covered'] or
                bucket_name in s3_events['specific_buckets']
            )

            if bucket_covered and s3_events['has_s3_data_events']:
                trail_info = {
                    'trail_name': trail_name,
                    'trail_region': trail_region,
                    'is_multi_region': is_multi_region,
                    'read_write_type': s3_events['read_write_type'],
                    'covers_write_events': s3_events['write_events_enabled'],
                    'covers_read_events': s3_events['read_events_enabled']
                }
                coverage_result['covering_trails'].append(trail_info)

                # Update overall coverage status
                if s3_events['write_events_enabled']:
                    coverage_result['is_covered_write_events'] = True
                if s3_events['read_events_enabled']:
                    coverage_result['is_covered_read_events'] = True

        return coverage_result

    def check_account_cloudtrail_coverage(self, bucket_regions: List[str]) -> Dict[str, Any]:
        """Check overall CloudTrail S3 data events coverage for the account.

        Args:
            bucket_regions: List of regions where buckets are located

        Returns:
            Dictionary containing account-wide CloudTrail coverage analysis
        """
        trails = self.get_all_trails()

        account_coverage = {
            'total_trails': len(trails),
            'trails_with_s3_data_events': 0,
            'multi_region_trails': 0,
            'regional_trails': 0,
            'trails_covering_all_buckets': 0,
            'trails_write_only': 0,
            'trails_read_only': 0,
            'trails_all_events': 0,
            'regions_with_trail_coverage': set(),
            'has_global_coverage': False,
            'trails_details': []
        }

        for trail in trails:
            trail_name = trail.get('TrailName', trail.get('Name', ''))
            trail_region = trail.get('HomeRegion', '')
            is_multi_region = trail.get('IsMultiRegionTrail', False)

            if is_multi_region:
                account_coverage['multi_region_trails'] += 1
            else:
                account_coverage['regional_trails'] += 1
                account_coverage['regions_with_trail_coverage'].add(trail_region)

            event_selectors = self.get_trail_event_selectors(trail_name)
            s3_events = self.parse_s3_data_events(event_selectors)

            if s3_events['has_s3_data_events']:
                account_coverage['trails_with_s3_data_events'] += 1

                if s3_events['all_buckets_covered']:
                    account_coverage['trails_covering_all_buckets'] += 1

                    # If multi-region trail covers all buckets, we have global coverage
                    if is_multi_region:
                        account_coverage['has_global_coverage'] = True

                # Track read/write event types
                if s3_events['read_write_type'] == 'WriteOnly':
                    account_coverage['trails_write_only'] += 1
                elif s3_events['read_write_type'] == 'ReadOnly':
                    account_coverage['trails_read_only'] += 1
                elif s3_events['read_write_type'] == 'All':
                    account_coverage['trails_all_events'] += 1

                trail_detail = {
                    'trail_name': trail_name,
                    'trail_region': trail_region,
                    'is_multi_region': is_multi_region,
                    'read_write_type': s3_events['read_write_type'],
                    'covers_all_buckets': s3_events['all_buckets_covered'],
                    'specific_buckets_count': len(s3_events['specific_buckets']),
                    'write_events_enabled': s3_events['write_events_enabled'],
                    'read_events_enabled': s3_events['read_events_enabled']
                }
                account_coverage['trails_details'].append(trail_detail)

        # Convert set to list for JSON serialization
        account_coverage['regions_with_trail_coverage'] = list(account_coverage['regions_with_trail_coverage'])

        return account_coverage

    def calculate_bucket_coverage_percentage(self, buckets: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Calculate what percentage of buckets are covered by CloudTrail data events.

        Args:
            buckets: List of bucket dictionaries with name and region

        Returns:
            Dictionary with coverage statistics
        """
        if not buckets:
            return {
                'total_buckets': 0,
                'covered_buckets_write': 0,
                'covered_buckets_read': 0,
                'coverage_percentage_write': 0,
                'coverage_percentage_read': 0,
                'uncovered_buckets': []
            }

        covered_write = 0
        covered_read = 0
        uncovered_buckets = []

        for bucket in buckets:
            bucket_name = bucket.get('name', bucket.get('Name', ''))
            bucket_region = bucket.get('region', 'us-east-1')

            coverage = self.check_bucket_cloudtrail_coverage(bucket_name, bucket_region)

            if coverage['is_covered_write_events']:
                covered_write += 1
            if coverage['is_covered_read_events']:
                covered_read += 1

            if not coverage['is_covered_write_events']:
                uncovered_buckets.append({
                    'bucket_name': bucket_name,
                    'bucket_region': bucket_region,
                    'missing_write_events': True,
                    'missing_read_events': not coverage['is_covered_read_events']
                })

        total_buckets = len(buckets)

        return {
            'total_buckets': total_buckets,
            'covered_buckets_write': covered_write,
            'covered_buckets_read': covered_read,
            'coverage_percentage_write': round((covered_write / total_buckets) * 100, 1) if total_buckets > 0 else 0,
            'coverage_percentage_read': round((covered_read / total_buckets) * 100, 1) if total_buckets > 0 else 0,
            'uncovered_buckets': uncovered_buckets
        }

    def check_cis_s3_22_compliance(self, bucket_name: str, bucket_region: str) -> Dict[str, Any]:
        """Check CIS S3.22 compliance: S3 buckets should have object-level logging for write events.

        Args:
            bucket_name: Name of the S3 bucket
            bucket_region: AWS region where the bucket is located

        Returns:
            Dictionary containing CIS S3.22 compliance status
        """
        coverage = self.check_bucket_cloudtrail_coverage(bucket_name, bucket_region)

        is_compliant = coverage['is_covered_write_events']

        return {
            'is_compliant': is_compliant,
            'control_id': 'CIS S3.22',
            'description': 'S3 buckets should have object-level logging for write events',
            'bucket_name': bucket_name,
            'bucket_region': bucket_region,
            'write_events_covered': coverage['is_covered_write_events'],
            'covering_trails_count': len(coverage['covering_trails']),
            'covering_trails': coverage['covering_trails'],
            'cloudtrail_available': coverage['cloudtrail_available'],
            'recommendation': (
                'Compliant: Write events are logged via CloudTrail' if is_compliant else
                'Non-compliant: Enable CloudTrail data events for S3 write operations'
            )
        }

    def check_cis_s3_23_compliance(self, bucket_name: str, bucket_region: str) -> Dict[str, Any]:
        """Check CIS S3.23 compliance: S3 buckets should have object-level logging for read events.

        Args:
            bucket_name: Name of the S3 bucket
            bucket_region: AWS region where the bucket is located

        Returns:
            Dictionary containing CIS S3.23 compliance status
        """
        coverage = self.check_bucket_cloudtrail_coverage(bucket_name, bucket_region)

        is_compliant = coverage['is_covered_read_events']

        return {
            'is_compliant': is_compliant,
            'control_id': 'CIS S3.23',
            'description': 'S3 buckets should have object-level logging for read events',
            'bucket_name': bucket_name,
            'bucket_region': bucket_region,
            'read_events_covered': coverage['is_covered_read_events'],
            'covering_trails_count': len(coverage['covering_trails']),
            'covering_trails': coverage['covering_trails'],
            'cloudtrail_available': coverage['cloudtrail_available'],
            'recommendation': (
                'Compliant: Read events are logged via CloudTrail' if is_compliant else
                'Non-compliant: Enable CloudTrail data events for S3 read operations'
            )
        }

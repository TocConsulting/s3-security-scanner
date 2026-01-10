"""Threat detection service integration checks."""

from botocore.exceptions import ClientError
from typing import Dict, Any
from .base import BaseChecker


class ThreatDetectionChecker(BaseChecker):
    """Checks for threat detection services configuration."""

    def __init__(self, session=None):
        """Initialize with optional session."""
        super().__init__(session)
        self._guardduty_client = None
        self._macie_client = None

    @property
    def guardduty_client(self):
        """Lazy-load GuardDuty client."""
        if self._guardduty_client is None:
            self._guardduty_client = self.get_client('guardduty')
        return self._guardduty_client

    @property
    def macie_client(self):
        """Lazy-load Macie client."""
        if self._macie_client is None:
            self._macie_client = self.get_client('macie2')
        return self._macie_client

    def check_guardduty_s3_protection(self) -> Dict[str, Any]:
        """Check if GuardDuty S3 protection is enabled.

        GuardDuty S3 protection monitors S3 data events for malicious
        and suspicious activity.

        Returns:
            Dict with GuardDuty S3 protection status
        """
        try:
            # List all GuardDuty detectors
            detectors = self.guardduty_client.list_detectors()

            if not detectors.get('DetectorIds'):
                return {
                    'is_enabled': False,
                    'has_s3_protection': False,
                    'error': 'No GuardDuty detectors found',
                    'recommendation': 'Enable GuardDuty to monitor for threats'
                }

            findings = []
            for detector_id in detectors['DetectorIds']:
                try:
                    # Get detector details
                    detector = self.guardduty_client.get_detector(
                        DetectorId=detector_id
                    )

                    # Check if detector is enabled
                    is_enabled = detector.get('Status') == 'ENABLED'

                    # Check S3 data sources configuration
                    data_sources = detector.get('DataSources', {})
                    s3_logs = data_sources.get('S3Logs', {})
                    s3_protection_enabled = s3_logs.get('Status') == 'ENABLED'

                    # Check for additional features (if available)
                    features = detector.get('Features', [])
                    s3_features = [
                        f for f in features
                        if 'S3' in f.get('Name', '')
                    ]

                    findings.append({
                        'detector_id': detector_id,
                        'is_enabled': is_enabled,
                        's3_protection': s3_protection_enabled,
                        's3_features': s3_features,
                        'created_at': detector.get('CreatedAt'),
                        'updated_at': detector.get('UpdatedAt')
                    })

                except ClientError as e:
                    findings.append({
                        'detector_id': detector_id,
                        'error': str(e)
                    })

            # Aggregate findings
            any_enabled = any(f.get('is_enabled', False) for f in findings)
            any_s3_protection = any(f.get('s3_protection', False) for f in findings)

            return {
                'is_enabled': any_enabled,
                'has_s3_protection': any_s3_protection,
                'detectors': findings,
                'recommendation': self._get_guardduty_recommendation(
                    any_enabled, any_s3_protection
                )
            }

        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                return {
                    'is_enabled': False,
                    'has_s3_protection': False,
                    'error': 'Access denied to GuardDuty API',
                    'recommendation': 'Grant guardduty:ListDetectors and guardduty:GetDetector permissions'
                }
            else:
                return {
                    'is_enabled': False,
                    'has_s3_protection': False,
                    'error': str(e)
                }

    def _get_guardduty_recommendation(
        self, is_enabled: bool, has_s3: bool
    ) -> str:
        """Generate GuardDuty recommendation."""
        if not is_enabled:
            return (
                "Enable GuardDuty to detect threats and unauthorized use. "
                "GuardDuty provides intelligent threat detection for S3."
            )
        elif not has_s3:
            return (
                "Enable S3 protection in GuardDuty to monitor S3 data events "
                "for malicious activity and anomalous behavior patterns."
            )
        else:
            return "GuardDuty S3 protection is properly configured."

    def check_macie_s3_discovery(self) -> Dict[str, Any]:
        """Check if Amazon Macie is enabled for S3 data discovery.

        Macie uses machine learning to discover, classify, and protect
        sensitive data in S3.

        Returns:
            Dict with Macie configuration status
        """
        try:
            # Check if Macie is enabled
            macie_session = self.macie_client.get_macie_session()

            is_enabled = macie_session.get('status') == 'ENABLED'

            if not is_enabled:
                return {
                    'is_enabled': False,
                    'has_s3_discovery': False,
                    'error': 'Macie is not enabled',
                    'recommendation': 'Enable Macie to discover and protect sensitive data in S3'
                }

            # Get S3 bucket inventory if Macie is enabled
            try:
                # Get classification jobs
                jobs = self.macie_client.list_classification_jobs()
                active_jobs = [
                    j for j in jobs.get('items', [])
                    if j.get('jobStatus') in ['RUNNING', 'IDLE']
                ]

                # Get S3 resources being monitored
                bucket_stats = self.macie_client.get_bucket_statistics()

                return {
                    'is_enabled': True,
                    'has_s3_discovery': True,
                    'finding_publishing': macie_session.get('findingPublishingFrequency'),
                    'service_role': macie_session.get('serviceRole'),
                    'active_classification_jobs': len(active_jobs),
                    'total_buckets_monitored': bucket_stats.get('bucketCount', 0),
                    'total_objects_monitored': bucket_stats.get('objectCount', 0),
                    'total_size_monitored_gb': bucket_stats.get('sizeInBytes', 0) / (1024**3),
                    'recommendation': self._get_macie_recommendation(
                        True, active_jobs, bucket_stats
                    )
                }

            except ClientError:
                # Macie is enabled but might not have full permissions
                return {
                    'is_enabled': True,
                    'has_s3_discovery': False,
                    'warning': 'Macie enabled but cannot retrieve S3 discovery details',
                    'recommendation': 'Grant additional Macie permissions to view discovery status'
                }

        except ClientError as e:
            if e.response['Error']['Code'] == 'AccessDeniedException':
                return {
                    'is_enabled': False,
                    'has_s3_discovery': False,
                    'error': 'Access denied to Macie API',
                    'recommendation': 'Grant macie2:GetMacieSession permission to check Macie status'
                }
            elif e.response['Error']['Code'] == 'ResourceNotFoundException':
                return {
                    'is_enabled': False,
                    'has_s3_discovery': False,
                    'error': 'Macie not enabled in this region',
                    'recommendation': 'Enable Macie for automated sensitive data discovery in S3'
                }
            else:
                return {
                    'is_enabled': False,
                    'has_s3_discovery': False,
                    'error': str(e)
                }

    def _get_macie_recommendation(
        self, is_enabled: bool, jobs: list, stats: dict
    ) -> str:
        """Generate Macie recommendation."""
        if not is_enabled:
            return (
                "Enable Amazon Macie to automatically discover, classify, and protect "
                "sensitive data stored in S3 buckets."
            )
        elif not jobs:
            return (
                "Macie is enabled but no classification jobs are running. "
                "Create classification jobs to scan S3 buckets for sensitive data."
            )
        elif stats.get('bucketCount', 0) == 0:
            return (
                "Macie is enabled but not monitoring any S3 buckets. "
                "Configure Macie to monitor your S3 buckets."
            )
        else:
            return f"Macie is monitoring {stats.get('bucketCount', 0)} buckets successfully."

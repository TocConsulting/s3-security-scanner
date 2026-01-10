"""Account-level S3 security checks."""

from botocore.exceptions import ClientError
from typing import Dict, Any
from .base import BaseChecker


class AccountSecurityChecker(BaseChecker):
    """Checks for account-level S3 security configurations."""

    def __init__(self, session=None):
        """Initialize with optional session for consistent authentication."""
        super().__init__(session)
        self._s3control_client = None
        self._account_id = None

    @property
    def s3control_client(self):
        """Lazy-load S3Control client."""
        if self._s3control_client is None:
            self._s3control_client = self.get_client('s3control')
        return self._s3control_client

    @property
    def account_id(self):
        """Lazy-load account ID."""
        if self._account_id is None:
            self._account_id = self.get_current_account_id()
        return self._account_id

    def check_account_public_access_block(self) -> Dict[str, Any]:
        """Check account-level S3 public access block settings.

        This is different from bucket-level settings and applies to ALL buckets
        in the account as a default baseline.

        Returns:
            Dict with account-level public access block status
        """
        try:
            response = self.s3control_client.get_public_access_block(
                AccountId=self.account_id
            )

            config = response.get('PublicAccessBlockConfiguration', {})

            # Check if all four settings are properly configured
            all_enabled = all([
                config.get('BlockPublicAcls', False),
                config.get('IgnorePublicAcls', False),
                config.get('BlockPublicPolicy', False),
                config.get('RestrictPublicBuckets', False)
            ])

            return {
                'is_properly_configured': all_enabled,
                'details': config,
                'account_id': self.account_id,
                'missing_settings': [
                    setting for setting in
                    ['BlockPublicAcls', 'IgnorePublicAcls',
                     'BlockPublicPolicy', 'RestrictPublicBuckets']
                    if not config.get(setting, False)
                ]
            }

        except ClientError as e:
            if e.response['Error']['Code'] == 'NoSuchPublicAccessBlockConfiguration':
                # No account-level configuration exists
                return {
                    'is_properly_configured': False,
                    'details': {},
                    'account_id': self.account_id,
                    'error': 'No account-level public access block configuration',
                    'missing_settings': [
                        'BlockPublicAcls', 'IgnorePublicAcls',
                        'BlockPublicPolicy', 'RestrictPublicBuckets'
                    ]
                }
            else:
                return {
                    'is_properly_configured': False,
                    'details': {},
                    'account_id': self.account_id,
                    'error': str(e)
                }

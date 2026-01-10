"""Base class for all security checkers."""

import boto3
from botocore.exceptions import ClientError
from typing import Dict, Any


class BaseChecker:
    """Base class for all security checkers."""

    def __init__(self, session_factory=None):
        """Initialize the checker with optional session factory.

        Args:
            session_factory: Callable that returns a boto3 session (for thread safety)
                           or a boto3 session object (for backward compatibility)
        """
        self.session_factory = session_factory

    def get_client(self, service_name: str, region_name: str = None):
        """Get AWS client for the specified service.

        Args:
            service_name: AWS service name (e.g., 's3', 'sts')
            region_name: AWS region name (optional)

        Returns:
            boto3 client for the service
        """
        if self.session_factory:
            # Get session - handle both callable factory and direct session object
            session = self.session_factory() if callable(self.session_factory) else self.session_factory
            return session.client(service_name, region_name=region_name)
        else:
            return boto3.client(service_name, region_name=region_name)

    def get_current_account_id(self) -> str:
        """Get current AWS account ID.

        Returns:
            Current AWS account ID
        """
        sts_client = self.get_client("sts")
        return sts_client.get_caller_identity()["Account"]

    def handle_client_error(
        self, e: ClientError, default_response: Dict[str, Any] = None
    ) -> Dict[str, Any]:
        """Handle ClientError exceptions consistently.

        Args:
            e: ClientError exception
            default_response: Default response dict to return

        Returns:
            Error response dict
        """
        if default_response is None:
            default_response = {
                "is_enabled": False,
                "details": f"Error: {str(e)}",
            }

        return default_response

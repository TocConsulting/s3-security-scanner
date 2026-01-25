"""S3 Security Scanner - A comprehensive AWS S3 bucket security scanner
with compliance mapping."""

__version__ = "1.0.1"
__author__ = "Toc Consulting"
__email__ = "tarek@tocconsulting.fr"

from .scanner import S3SecurityScanner
from .compliance import ComplianceChecker

__all__ = ["S3SecurityScanner", "ComplianceChecker"]

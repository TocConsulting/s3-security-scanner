"""Tests for CLI module."""

import unittest
from click.testing import CliRunner
from s3_security_scanner.cli import main
from s3_security_scanner import __version__


class TestCLI(unittest.TestCase):
    """Test cases for CLI."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.runner = CliRunner()
    
    def test_help_option(self):
        """Test help option works."""
        result = self.runner.invoke(main, ['--help'])
        self.assertEqual(result.exit_code, 0)
        # Check for key elements in the new CLI format
        self.assertIn('security', result.output)
        self.assertIn('discover', result.output)
        self.assertIn('dns', result.output)

    def test_help_short_option(self):
        """Test short help option works."""
        result = self.runner.invoke(main, ['-h'])
        self.assertEqual(result.exit_code, 0)
        # Check for key elements in the new CLI format
        self.assertIn('security', result.output)
        self.assertIn('Scanner', result.output)
    
    def test_version_option(self):
        """Test version option works."""
        result = self.runner.invoke(main, ['--version'])
        self.assertEqual(result.exit_code, 0)
        self.assertIn(__version__, result.output)


if __name__ == "__main__":
    unittest.main()
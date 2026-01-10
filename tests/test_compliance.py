"""Tests for compliance module."""

import unittest
from s3_security_scanner.compliance import ComplianceChecker


class TestComplianceChecker(unittest.TestCase):
    """Test cases for ComplianceChecker class."""
    
    def setUp(self):
        """Set up test fixtures."""
        self.checker = ComplianceChecker()
    
    def test_frameworks_defined(self):
        """Test that all compliance frameworks are defined."""
        frameworks = self.checker.frameworks
        self.assertIn("CIS", frameworks)
        self.assertIn("AWS-FSBP", frameworks)
        self.assertIn("PCI-DSS", frameworks)
        self.assertIn("HIPAA", frameworks)
        self.assertIn("SOC2", frameworks)
        self.assertIn("ISO27001", frameworks)
        self.assertIn("ISO27017", frameworks)
        self.assertIn("ISO27018", frameworks)
        self.assertIn("GDPR", frameworks)
    
    def test_cis_controls_count(self):
        """Test CIS framework has expected controls."""
        cis_controls = self.checker.frameworks["CIS"]["controls"]
        self.assertEqual(len(cis_controls), 6)
        self.assertIn("S3.1", cis_controls)
        self.assertIn("S3.5", cis_controls)
        self.assertIn("S3.8", cis_controls)
        self.assertIn("S3.20", cis_controls)
        self.assertIn("S3.22", cis_controls)
        self.assertIn("S3.23", cis_controls)
    
    def test_aws_fsbp_controls_count(self):
        """Test AWS FSBP framework has expected controls."""
        fsbp_controls = self.checker.frameworks["AWS-FSBP"]["controls"]
        self.assertEqual(len(fsbp_controls), 11)
        self.assertIn("S3.1", fsbp_controls)
        self.assertIn("S3.2", fsbp_controls)
        self.assertIn("S3.3", fsbp_controls)
        self.assertIn("S3.5", fsbp_controls)
        self.assertIn("S3.6", fsbp_controls)
        self.assertIn("S3.8", fsbp_controls)
        self.assertIn("S3.9", fsbp_controls)
        self.assertIn("S3.12", fsbp_controls)
        self.assertIn("S3.13", fsbp_controls)
        self.assertIn("S3.19", fsbp_controls)
        self.assertIn("S3.24", fsbp_controls)
    
    def test_soc2_controls_count(self):
        """Test SOC 2 framework has expected controls."""
        soc2_controls = self.checker.frameworks["SOC2"]["controls"]
        self.assertEqual(len(soc2_controls), 12)  # 12 SOC 2 controls implemented
        # Security (CC) - Mandatory
        self.assertIn("SOC2-CC-ENCRYPTION-REST", soc2_controls)
        self.assertIn("SOC2-CC-ENCRYPTION-TRANSIT", soc2_controls)
        self.assertIn("SOC2-CC-ACCESS-CONTROL", soc2_controls)
        self.assertIn("SOC2-CC-MFA-REQUIREMENTS", soc2_controls)
        self.assertIn("SOC2-CC-AUDIT-LOGGING", soc2_controls)
        self.assertIn("SOC2-CC-KEY-MANAGEMENT", soc2_controls)
        # Availability (A) - Optional
        self.assertIn("SOC2-A-BACKUP-RECOVERY", soc2_controls)
        self.assertIn("SOC2-A-REPLICATION", soc2_controls)
        self.assertIn("SOC2-A-MONITORING", soc2_controls)
        # Confidentiality (C) - Optional
        self.assertIn("SOC2-C-DATA-PROTECTION", soc2_controls)
        # Processing Integrity (PI) - Optional
        self.assertIn("SOC2-PI-DATA-INTEGRITY", soc2_controls)
        # Privacy (P) - Optional
        self.assertIn("SOC2-P-DATA-GOVERNANCE", soc2_controls)
    
    def test_soc2_control_descriptions(self):
        """Test SOC 2 controls have proper descriptions."""
        soc2_controls = self.checker.frameworks["SOC2"]["controls"]
        
        # Test that each control has required fields
        for control_id, control in soc2_controls.items():
            self.assertIn("description", control)
            self.assertIn("severity", control)
            self.assertIn("check", control)
            self.assertIsInstance(control["description"], str)
            self.assertIn(control["severity"], ["HIGH", "MEDIUM", "LOW"])
    
    def test_soc2_remediation_steps(self):
        """Test SOC 2 remediation steps are available."""
        soc2_controls = [
            "SOC2-CC-ENCRYPTION-REST", "SOC2-CC-ENCRYPTION-TRANSIT", "SOC2-CC-ACCESS-CONTROL",
            "SOC2-CC-MFA-REQUIREMENTS", "SOC2-CC-AUDIT-LOGGING", "SOC2-CC-KEY-MANAGEMENT",
            "SOC2-A-BACKUP-RECOVERY", "SOC2-A-REPLICATION", "SOC2-A-MONITORING",
            "SOC2-C-DATA-PROTECTION", "SOC2-PI-DATA-INTEGRITY", "SOC2-P-DATA-GOVERNANCE"
        ]
        
        for control_id in soc2_controls:
            steps = self.checker.get_remediation_steps("SOC2", control_id)
            self.assertIsInstance(steps, list)
            self.assertGreater(len(steps), 0)
    
    def test_soc2_compliance_check_encryption_rest(self):
        """Test SOC 2 SOC2-CC-ENCRYPTION-REST - Server-side encryption check."""
        # Mock bucket checks with encryption enabled
        bucket_checks = {
            "encryption": {"is_enabled": True}
        }
        
        # Get the check function for SOC2-CC-ENCRYPTION-REST
        check_func = self.checker.frameworks["SOC2"]["controls"]["SOC2-CC-ENCRYPTION-REST"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test with encryption disabled
        bucket_checks["encryption"]["is_enabled"] = False
        result = check_func(bucket_checks)
        self.assertFalse(result)
    
    def test_soc2_compliance_check_encryption_transit(self):
        """Test SOC 2 SOC2-CC-ENCRYPTION-TRANSIT - SSL enforcement check."""
        # Mock bucket checks with SSL enforced
        bucket_checks = {
            "bucket_policy": {"ssl_enforced": True}
        }
        
        check_func = self.checker.frameworks["SOC2"]["controls"]["SOC2-CC-ENCRYPTION-TRANSIT"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test with SSL not enforced
        bucket_checks["bucket_policy"]["ssl_enforced"] = False
        result = check_func(bucket_checks)
        self.assertFalse(result)
    
    def test_soc2_compliance_check_access_control(self):
        """Test SOC 2 SOC2-CC-ACCESS-CONTROL - Access control check."""
        # Mock bucket checks with proper access controls
        bucket_checks = {
            "public_access_block": {"is_properly_configured": True},
            "is_public": False
        }
        
        check_func = self.checker.frameworks["SOC2"]["controls"]["SOC2-CC-ACCESS-CONTROL"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test with public bucket
        bucket_checks["is_public"] = True
        result = check_func(bucket_checks)
        self.assertFalse(result)
    
    def test_soc2_compliance_check_mfa_requirements(self):
        """Test SOC 2 SOC2-CC-MFA-REQUIREMENTS - MFA requirement check."""
        # Mock bucket checks with MFA required
        bucket_checks = {
            "mfa_requirement": {"mfa_required": True}
        }
        
        check_func = self.checker.frameworks["SOC2"]["controls"]["SOC2-CC-MFA-REQUIREMENTS"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test without MFA requirement
        bucket_checks["mfa_requirement"]["mfa_required"] = False
        result = check_func(bucket_checks)
        self.assertFalse(result)
    
    def test_soc2_compliance_check_audit_logging(self):
        """Test SOC 2 SOC2-CC-AUDIT-LOGGING - Audit logging check."""
        # Mock bucket checks with logging enabled
        bucket_checks = {
            "logging": {"is_enabled": True}
        }
        
        check_func = self.checker.frameworks["SOC2"]["controls"]["SOC2-CC-AUDIT-LOGGING"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test without logging
        bucket_checks["logging"]["is_enabled"] = False
        result = check_func(bucket_checks)
        self.assertFalse(result)
        
    def test_soc2_compliance_check_key_management(self):
        """Test SOC 2 SOC2-CC-KEY-MANAGEMENT - KMS key management check."""
        # Mock bucket checks with KMS managed
        bucket_checks = {
            "kms_key_management": {"kms_managed": True}
        }
        
        check_func = self.checker.frameworks["SOC2"]["controls"]["SOC2-CC-KEY-MANAGEMENT"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test without KMS management
        bucket_checks["kms_key_management"]["kms_managed"] = False
        result = check_func(bucket_checks)
        self.assertFalse(result)
    
    def test_soc2_compliance_check_backup_recovery(self):
        """Test SOC 2 SOC2-A-BACKUP-RECOVERY - Backup and recovery check."""
        # Mock bucket checks with versioning enabled
        bucket_checks = {
            "versioning": {"is_enabled": True}
        }
        
        check_func = self.checker.frameworks["SOC2"]["controls"]["SOC2-A-BACKUP-RECOVERY"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test without versioning
        bucket_checks["versioning"]["is_enabled"] = False
        result = check_func(bucket_checks)
        self.assertFalse(result)
        
    def test_soc2_compliance_check_replication(self):
        """Test SOC 2 SOC2-A-REPLICATION - Replication check."""
        # Mock bucket checks with replication enabled
        bucket_checks = {
            "replication": {"has_replication": True}
        }
        
        check_func = self.checker.frameworks["SOC2"]["controls"]["SOC2-A-REPLICATION"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test without replication
        bucket_checks["replication"]["has_replication"] = False
        result = check_func(bucket_checks)
        self.assertFalse(result)
        
    def test_soc2_compliance_check_monitoring(self):
        """Test SOC 2 SOC2-A-MONITORING - CloudWatch monitoring check."""
        # Mock bucket checks with monitoring enabled
        bucket_checks = {
            "cloudwatch_monitoring": {"monitoring_enabled": True}
        }
        
        check_func = self.checker.frameworks["SOC2"]["controls"]["SOC2-A-MONITORING"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test without monitoring
        bucket_checks["cloudwatch_monitoring"]["monitoring_enabled"] = False
        result = check_func(bucket_checks)
        self.assertFalse(result)
    
    def test_soc2_compliance_check_data_protection(self):
        """Test SOC 2 SOC2-C-DATA-PROTECTION - Data protection check."""
        # Mock bucket checks with no cross-account access and encryption enabled
        bucket_checks = {
            "cross_account_access": {"has_cross_account_access": False},
            "encryption": {"is_enabled": True}
        }
        
        check_func = self.checker.frameworks["SOC2"]["controls"]["SOC2-C-DATA-PROTECTION"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test with cross-account access
        bucket_checks["cross_account_access"]["has_cross_account_access"] = True
        result = check_func(bucket_checks)
        self.assertFalse(result)
        
    def test_soc2_compliance_check_data_integrity(self):
        """Test SOC 2 SOC2-PI-DATA-INTEGRITY - Data integrity check."""
        # Mock bucket checks with object lock enabled
        bucket_checks = {
            "object_lock": {"is_enabled": True}
        }
        
        check_func = self.checker.frameworks["SOC2"]["controls"]["SOC2-PI-DATA-INTEGRITY"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test without object lock
        bucket_checks["object_lock"]["is_enabled"] = False
        result = check_func(bucket_checks)
        self.assertFalse(result)
        
    def test_soc2_compliance_check_data_governance(self):
        """Test SOC 2 SOC2-P-DATA-GOVERNANCE - Data governance check."""
        # Mock bucket checks with Storage Lens enabled
        bucket_checks = {
            "storage_lens_config": {"storage_lens_enabled": True}
        }
        
        check_func = self.checker.frameworks["SOC2"]["controls"]["SOC2-P-DATA-GOVERNANCE"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test without Storage Lens
        bucket_checks["storage_lens_config"]["storage_lens_enabled"] = False
        result = check_func(bucket_checks)
        self.assertFalse(result)
    
    def test_aws_fsbp_compliance_check_public_read_access(self):
        """Test AWS FSBP S3.2 - Block public read access."""
        # Mock bucket checks with no public access (good)
        bucket_checks = {
            "is_public": False,
            "bucket_acl": {"has_public_access": False}
        }
        
        check_func = self.checker.frameworks["AWS-FSBP"]["controls"]["S3.2"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test with public access (bad)
        bucket_checks["is_public"] = True
        result = check_func(bucket_checks)
        self.assertFalse(result)
    
    def test_aws_fsbp_compliance_check_public_write_access(self):
        """Test AWS FSBP S3.3 - Block public write access."""
        # Mock bucket checks with no public write (good)
        bucket_checks = {
            "bucket_acl": {"has_public_write": False}
        }
        
        check_func = self.checker.frameworks["AWS-FSBP"]["controls"]["S3.3"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test with public write access (bad)
        bucket_checks["bucket_acl"]["has_public_write"] = True
        result = check_func(bucket_checks)
        self.assertFalse(result)
    
    def test_aws_fsbp_compliance_check_acl_grants(self):
        """Test AWS FSBP S3.12 - ACLs should not be used for access management."""
        # Mock bucket checks with minimal ACL usage (good)
        bucket_checks = {
            "bucket_acl": {"has_acl_grants": False}
        }
        
        check_func = self.checker.frameworks["AWS-FSBP"]["controls"]["S3.12"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test with ACL grants (bad)
        bucket_checks["bucket_acl"]["has_acl_grants"] = True
        result = check_func(bucket_checks)
        self.assertFalse(result)
    
    def test_aws_fsbp_compliance_check_access_points(self):
        """Test AWS FSBP S3.19 - Access points should have public access blocked."""
        # Mock bucket checks with properly blocked access points (good)
        bucket_checks = {
            "access_points": {"all_have_public_access_blocked": True}
        }
        
        check_func = self.checker.frameworks["AWS-FSBP"]["controls"]["S3.19"]["check"]
        result = check_func(bucket_checks)
        self.assertTrue(result)
        
        # Test with unblocked access points (bad)
        bucket_checks["access_points"]["all_have_public_access_blocked"] = False
        result = check_func(bucket_checks)
        self.assertFalse(result)
    
    def test_aws_fsbp_remediation_steps(self):
        """Test AWS FSBP remediation steps are available."""
        for control_id in ["S3.1", "S3.2", "S3.3", "S3.12", "S3.19", "S3.24"]:
            steps = self.checker.get_remediation_steps("AWS-FSBP", control_id)
            self.assertIsInstance(steps, list)
            self.assertGreater(len(steps), 0)
    
    def test_pci_dss_controls_count(self):
        """Test PCI DSS framework has expected controls."""
        pci_controls = self.checker.frameworks["PCI-DSS"]["controls"]
        self.assertEqual(len(pci_controls), 10)
    
    def test_pci_dss_control_ids(self):
        """Test PCI DSS uses S3.x control ID format."""
        pci_controls = self.checker.frameworks["PCI-DSS"]["controls"]
        for control_id in pci_controls.keys():
            self.assertTrue(control_id.startswith("S3."), 
                          f"Control {control_id} should use S3.x format")
    
    def test_pci_dss_all_controls(self):
        """Test PCI DSS has all expected AWS Config rule controls."""
        pci_controls = self.checker.frameworks["PCI-DSS"]["controls"]
        expected_controls = ["S3.1", "S3.5", "S3.8", "S3.9", "S3.15", 
                           "S3.17", "S3.19", "S3.22", "S3.23", "S3.24"]
        for control in expected_controls:
            self.assertIn(control, pci_controls)
    
    def test_pci_dss_remediation_steps(self):
        """Test PCI DSS remediation steps are available for all controls."""
        pci_controls = self.checker.frameworks["PCI-DSS"]["controls"]
        for control_id in pci_controls.keys():
            steps = self.checker.get_remediation_steps("PCI-DSS", control_id)
            self.assertIsInstance(steps, list)
            self.assertGreater(len(steps), 0, 
                             f"Control {control_id} should have remediation steps")
    
    def test_pci_dss_control_descriptions(self):
        """Test PCI DSS controls have proper descriptions."""
        pci_controls = self.checker.frameworks["PCI-DSS"]["controls"]
        
        # Test that each control has required fields
        for control_id, control in pci_controls.items():
            self.assertIn("description", control)
            self.assertIn("severity", control)
            self.assertIn("check", control)
            self.assertIsInstance(control["description"], str)
            self.assertIn(control["severity"], ["HIGH", "MEDIUM", "LOW"])
            self.assertTrue(callable(control["check"]), 
                          f"Control {control_id} check should be callable")
    
    def test_pci_dss_framework_name(self):
        """Test PCI DSS framework has correct name."""
        framework_name = self.checker.frameworks["PCI-DSS"]["name"]
        self.assertEqual(framework_name, "PCI DSS v4.0 (AWS Config Rules)")
    
    def test_pci_dss_compliance_checks(self):
        """Test PCI DSS specific compliance checks with mock data."""
        # Mock bucket data for testing
        bucket_checks = {
            "is_public": False,
            "bucket_policy": {"ssl_enforced": True},
            "public_access_block": {"is_properly_configured": True},
            "logging": {"is_enabled": True},
            "object_lock": {"is_enabled": True},
            "encryption": {"is_enabled": True},
            "bucket_acl": {"has_public_write": False},
            "versioning": {"is_enabled": True},
            "replication": {"has_replication": True}
        }
        
        # Test each PCI DSS control passes with proper configuration
        pci_controls = self.checker.frameworks["PCI-DSS"]["controls"]
        
        # S3.1 - Public access prohibited
        result = pci_controls["S3.1"]["check"](bucket_checks)
        self.assertTrue(result, "S3.1 should pass with non-public bucket")
        
        # S3.5 - SSL required
        result = pci_controls["S3.5"]["check"](bucket_checks)
        self.assertTrue(result, "S3.5 should pass with SSL enforced")
        
        # S3.17 - Encryption enabled
        result = pci_controls["S3.17"]["check"](bucket_checks)
        self.assertTrue(result, "S3.17 should pass with encryption enabled")
        
        # S3.23 - Versioning enabled
        result = pci_controls["S3.23"]["check"](bucket_checks)
        self.assertTrue(result, "S3.23 should pass with versioning enabled")
        
        # Test failures
        bucket_checks["is_public"] = True
        result = pci_controls["S3.1"]["check"](bucket_checks)
        self.assertFalse(result, "S3.1 should fail with public bucket")
    
    def test_hipaa_controls_count(self):
        """Test HIPAA framework has expected controls."""
        hipaa_controls = self.checker.frameworks["HIPAA"]["controls"]
        self.assertEqual(len(hipaa_controls), 7)
    
    def test_hipaa_control_ids(self):
        """Test HIPAA uses AWS Config rule format."""
        hipaa_controls = self.checker.frameworks["HIPAA"]["controls"]
        expected_controls = [
            "s3-bucket-server-side-encryption-enabled",
            "s3-bucket-ssl-requests-only", 
            "s3-bucket-logging-enabled",
            "s3-bucket-public-read-prohibited",
            "s3-bucket-public-write-prohibited",
            "s3-bucket-versioning-enabled",
            "s3-bucket-default-lock-enabled"
        ]
        for control_id in expected_controls:
            self.assertIn(control_id, hipaa_controls, 
                         f"Expected HIPAA control {control_id} not found")
    
    def test_hipaa_control_descriptions(self):
        """Test HIPAA controls have proper descriptions with HIPAA sections."""
        hipaa_controls = self.checker.frameworks["HIPAA"]["controls"]
        
        # Test that each control has required fields
        for control_id, control in hipaa_controls.items():
            self.assertIn("description", control)
            self.assertIn("severity", control) 
            self.assertIn("check", control)
            self.assertIsInstance(control["description"], str)
            self.assertIn(control["severity"], ["HIGH", "MEDIUM", "LOW"])
            
            # Test that description contains HIPAA section reference
            self.assertIn("HIPAA §", control["description"],
                         f"Control {control_id} description should reference HIPAA section")
    
    def test_hipaa_framework_name(self):
        """Test HIPAA framework has correct name."""
        framework_name = self.checker.frameworks["HIPAA"]["name"]
        self.assertEqual(framework_name, "HIPAA Security Rule (AWS Config Rules)")
    
    def test_hipaa_remediation_steps(self):
        """Test HIPAA remediation steps are available for all controls."""
        hipaa_controls = self.checker.frameworks["HIPAA"]["controls"]
        for control_id in hipaa_controls.keys():
            steps = self.checker.get_remediation_steps("HIPAA", control_id)
            self.assertIsInstance(steps, list)
            self.assertGreater(len(steps), 0, 
                             f"Control {control_id} should have remediation steps")
    
    def test_hipaa_compliance_checks(self):
        """Test HIPAA specific compliance checks with mock data."""
        # Mock bucket data for testing
        bucket_checks = {
            "is_public": False,
            "bucket_policy": {"ssl_enforced": True},
            "public_access_block": {"is_properly_configured": True},
            "logging": {"is_enabled": True},
            "object_lock": {"is_enabled": True},
            "encryption": {"is_enabled": True},
            "bucket_acl": {"has_public_write": False},
            "versioning": {"is_enabled": True, "mfa_delete_enabled": True},
            "replication": {"has_replication": True}
        }
        
        hipaa_controls = self.checker.frameworks["HIPAA"]["controls"]
        
        # Test successful checks
        # s3-bucket-server-side-encryption-enabled
        result = hipaa_controls["s3-bucket-server-side-encryption-enabled"]["check"](bucket_checks)
        self.assertTrue(result, "s3-bucket-server-side-encryption-enabled should pass with encryption enabled")
        
        # s3-bucket-ssl-requests-only
        result = hipaa_controls["s3-bucket-ssl-requests-only"]["check"](bucket_checks)
        self.assertTrue(result, "s3-bucket-ssl-requests-only should pass with SSL enforced")
        
        # s3-bucket-logging-enabled
        result = hipaa_controls["s3-bucket-logging-enabled"]["check"](bucket_checks)
        self.assertTrue(result, "s3-bucket-logging-enabled should pass with logging enabled")
        
        # s3-bucket-public-read-prohibited
        result = hipaa_controls["s3-bucket-public-read-prohibited"]["check"](bucket_checks)
        self.assertTrue(result, "s3-bucket-public-read-prohibited should pass with private bucket")
        
        # s3-bucket-public-write-prohibited
        result = hipaa_controls["s3-bucket-public-write-prohibited"]["check"](bucket_checks)
        self.assertTrue(result, "s3-bucket-public-write-prohibited should pass without public write")
        
        # s3-bucket-versioning-enabled
        result = hipaa_controls["s3-bucket-versioning-enabled"]["check"](bucket_checks)
        self.assertTrue(result, "s3-bucket-versioning-enabled should pass with versioning enabled")
        
        # s3-bucket-default-lock-enabled
        result = hipaa_controls["s3-bucket-default-lock-enabled"]["check"](bucket_checks)
        self.assertTrue(result, "s3-bucket-default-lock-enabled should pass with object lock enabled")
        
        # Test failures
        bucket_checks["is_public"] = True
        result = hipaa_controls["s3-bucket-public-read-prohibited"]["check"](bucket_checks)
        self.assertFalse(result, "s3-bucket-public-read-prohibited should fail with public bucket")
        
        bucket_checks["encryption"]["is_enabled"] = False
        result = hipaa_controls["s3-bucket-server-side-encryption-enabled"]["check"](bucket_checks)
        self.assertFalse(result, "s3-bucket-server-side-encryption-enabled should fail without encryption")
        
        bucket_checks["bucket_policy"]["ssl_enforced"] = False
        result = hipaa_controls["s3-bucket-ssl-requests-only"]["check"](bucket_checks)
        self.assertFalse(result, "s3-bucket-ssl-requests-only should fail without SSL enforcement")
    
    def test_hipaa_specific_mappings(self):
        """Test HIPAA control mappings to specific HIPAA sections."""
        hipaa_controls = self.checker.frameworks["HIPAA"]["controls"]
        
        # Test specific control mappings based on HIPAA Security Rule
        encryption_control = hipaa_controls["s3-bucket-server-side-encryption-enabled"]
        self.assertIn("§164.312(a)(2)(iv)", encryption_control["description"])
        
        ssl_control = hipaa_controls["s3-bucket-ssl-requests-only"] 
        self.assertIn("§164.312(e)(1)", ssl_control["description"])
        
        logging_control = hipaa_controls["s3-bucket-logging-enabled"]
        self.assertIn("§164.312(b)", logging_control["description"])
        
        read_control = hipaa_controls["s3-bucket-public-read-prohibited"]
        self.assertIn("§164.312(a)(1)", read_control["description"])
        
        write_control = hipaa_controls["s3-bucket-public-write-prohibited"]
        self.assertIn("§164.312(a)(1)", write_control["description"])
        
        versioning_control = hipaa_controls["s3-bucket-versioning-enabled"]
        self.assertIn("§164.308(a)(7)(ii)(A)", versioning_control["description"])
        
        lock_control = hipaa_controls["s3-bucket-default-lock-enabled"]
        self.assertIn("§164.308(a)(1)(ii)(D)", lock_control["description"])
    
    def test_remediation_steps_exist(self):
        """Test remediation steps are available."""
        steps = self.checker.get_remediation_steps("CIS", "S3.1")
        self.assertIsInstance(steps, list)
        self.assertGreater(len(steps), 0)

    # ISO 27001 Tests
    def test_iso27001_controls_count(self):
        """Test ISO 27001 framework has expected controls."""
        iso27001_controls = self.checker.frameworks["ISO27001"]["controls"]
        self.assertEqual(len(iso27001_controls), 7)
        
        # Check for real control IDs
        expected_controls = ["5.15", "5.18", "5.23", "8.24", "12.3", "12.4", "13.2"]
        for control in expected_controls:
            self.assertIn(control, iso27001_controls)
    
    def test_iso27001_control_descriptions(self):
        """Test ISO 27001 controls have proper descriptions."""
        iso27001_controls = self.checker.frameworks["ISO27001"]["controls"]
        
        # Test specific control descriptions
        self.assertIn("Access control management", iso27001_controls["5.15"]["description"])
        self.assertIn("Access rights management", iso27001_controls["5.18"]["description"])
        self.assertIn("Information security for use of cloud services", iso27001_controls["5.23"]["description"])
        self.assertIn("Use of cryptography", iso27001_controls["8.24"]["description"])
        self.assertIn("Information backup", iso27001_controls["12.3"]["description"])
        self.assertIn("Logging and monitoring", iso27001_controls["12.4"]["description"])
        self.assertIn("Information transfer", iso27001_controls["13.2"]["description"])
        
        # Test that each control has required fields
        for control_id, control in iso27001_controls.items():
            self.assertIn("description", control)
            self.assertIn("severity", control)
            self.assertIn("check", control)
            self.assertIsInstance(control["description"], str)
            self.assertIn(control["severity"], ["HIGH", "MEDIUM", "LOW"])
            self.assertTrue(callable(control["check"]))
    
    def test_iso27001_framework_name(self):
        """Test ISO 27001 framework has correct name."""
        framework_name = self.checker.frameworks["ISO27001"]["name"]
        self.assertEqual(framework_name, "ISO 27001:2022 - Information Security Management Systems")
    
    def test_iso27001_compliance_checks(self):
        """Test ISO 27001 compliance checks with mock data."""
        # Mock bucket data for testing
        bucket_checks = {
            "public_access_block": {"is_properly_configured": True},
            "bucket_policy": {"is_public": False, "ssl_enforced": True},
            "bucket_acl": {"has_public_access": False},
            "versioning": {"is_enabled": True},
            "replication": {"has_replication": True},
            "logging": {"is_enabled": True},
            "encryption": {"is_enabled": True},
            "iso27001_access_control": {"is_compliant": True},
            "iso27001_access_rights": {"is_compliant": True},
            "iso27001_cloud_service_security": {"is_compliant": True},
            "iso27001_cryptography": {"is_compliant": True},
            "iso27001_backup": {"is_compliant": True},
            "iso27001_logging": {"is_compliant": True},
            "iso27001_info_transfer": {"is_compliant": True}
        }
        
        iso27001_controls = self.checker.frameworks["ISO27001"]["controls"]
        
        # Test each control passes with proper configuration
        for control_id, control in iso27001_controls.items():
            result = control["check"](bucket_checks)
            self.assertTrue(result, f"ISO 27001 control {control_id} should pass with proper configuration")
    
    # ISO 27017 Tests
    def test_iso27017_controls_count(self):
        """Test ISO 27017 framework has expected controls."""
        iso27017_controls = self.checker.frameworks["ISO27017"]["controls"]
        self.assertEqual(len(iso27017_controls), 7)
        
        # Check for real control IDs
        expected_controls = ["CLD.6.3.1", "CLD.7.1.1", "CLD.8.1.4", "CLD.12.1.5", "CLD.12.4.1", "CLD.13.1.1", "CLD.13.1.2"]
        for control in expected_controls:
            self.assertIn(control, iso27017_controls)
    
    def test_iso27017_control_descriptions(self):
        """Test ISO 27017 controls have proper descriptions."""
        iso27017_controls = self.checker.frameworks["ISO27017"]["controls"]
        
        # Test specific control descriptions
        self.assertIn("Restriction of access rights", iso27017_controls["CLD.6.3.1"]["description"])
        self.assertIn("Cloud service responsibilities", iso27017_controls["CLD.7.1.1"]["description"])
        self.assertIn("Data and information location", iso27017_controls["CLD.8.1.4"]["description"])
        self.assertIn("Monitoring activities", iso27017_controls["CLD.12.1.5"]["description"])
        self.assertIn("Logging cloud services", iso27017_controls["CLD.12.4.1"]["description"])
        self.assertIn("Information deletion", iso27017_controls["CLD.13.1.1"]["description"])
        self.assertIn("Information isolation", iso27017_controls["CLD.13.1.2"]["description"])
        
        # Test that each control has required fields
        for control_id, control in iso27017_controls.items():
            self.assertIn("description", control)
            self.assertIn("severity", control)
            self.assertIn("check", control)
            self.assertIsInstance(control["description"], str)
            self.assertIn(control["severity"], ["HIGH", "MEDIUM", "LOW"])
            self.assertTrue(callable(control["check"]))
    
    def test_iso27017_framework_name(self):
        """Test ISO 27017 framework has correct name."""
        framework_name = self.checker.frameworks["ISO27017"]["name"]
        self.assertEqual(framework_name, "ISO 27017:2015 - Cloud Security Guidelines")
    
    def test_iso27017_compliance_checks(self):
        """Test ISO 27017 compliance checks with mock data."""
        # Mock bucket data for testing
        bucket_checks = {
            "public_access_block": {"is_properly_configured": True},
            "bucket_policy": {"is_public": False},
            "bucket_acl": {"has_public_access": False},
            "encryption": {"is_enabled": True},
            "versioning": {"is_enabled": True},
            "logging": {"is_enabled": True},
            "replication": {"has_replication": True},
            "event_notifications": {"has_notifications": True},
            "lifecycle": {"has_lifecycle_rules": True},
            "cross_account_access": {"has_cross_account_access": False},
            "iso27017_access_restriction": {"is_compliant": True},
            "iso27017_shared_responsibility": {"is_compliant": True},
            "iso27017_data_location": {"is_compliant": True},
            "iso27017_monitoring": {"is_compliant": True},
            "iso27017_cloud_logging": {"is_compliant": True},
            "iso27017_data_deletion": {"is_compliant": True},
            "iso27017_data_isolation": {"is_compliant": True}
        }
        
        iso27017_controls = self.checker.frameworks["ISO27017"]["controls"]
        
        # Test each control passes with proper configuration
        for control_id, control in iso27017_controls.items():
            result = control["check"](bucket_checks)
            self.assertTrue(result, f"ISO 27017 control {control_id} should pass with proper configuration")
    
    # ISO 27018 Tests
    def test_iso27018_controls_count(self):
        """Test ISO 27018 framework has expected controls."""
        iso27018_controls = self.checker.frameworks["ISO27018"]["controls"]
        self.assertEqual(len(iso27018_controls), 4)
        
        # Check for real control IDs
        expected_controls = ["6.2.1", "6.4.1", "6.5.1", "8.2.1"]
        for control in expected_controls:
            self.assertIn(control, iso27018_controls)
    
    def test_iso27018_control_descriptions(self):
        """Test ISO 27018 controls have proper descriptions."""
        iso27018_controls = self.checker.frameworks["ISO27018"]["controls"]
        
        # Test specific control descriptions
        self.assertIn("Purpose limitation and use limitation", iso27018_controls["6.2.1"]["description"])
        self.assertIn("Data minimization", iso27018_controls["6.4.1"]["description"])
        self.assertIn("Use, retention and deletion", iso27018_controls["6.5.1"]["description"])
        self.assertIn("Accountability policy", iso27018_controls["8.2.1"]["description"])
        
        # Test that each control has required fields
        for control_id, control in iso27018_controls.items():
            self.assertIn("description", control)
            self.assertIn("severity", control)
            self.assertIn("check", control)
            self.assertIsInstance(control["description"], str)
            self.assertIn(control["severity"], ["HIGH", "MEDIUM", "LOW"])
            self.assertTrue(callable(control["check"]))
    
    def test_iso27018_framework_name(self):
        """Test ISO 27018 framework has correct name."""
        framework_name = self.checker.frameworks["ISO27018"]["name"]
        self.assertEqual(framework_name, "ISO 27018:2019 - PII Protection in Public Clouds")
    
    def test_iso27018_compliance_checks(self):
        """Test ISO 27018 compliance checks with mock data."""
        # Mock bucket data for testing
        bucket_checks = {
            "lifecycle": {"has_lifecycle_rules": True},
            "versioning": {"is_enabled": True},
            "logging": {"is_enabled": True},
            "iso27018_purpose_limitation": {"is_compliant": True},
            "iso27018_data_minimization": {"is_compliant": True},
            "iso27018_retention_deletion": {"is_compliant": True},
            "iso27018_accountability": {"is_compliant": True}
        }
        
        iso27018_controls = self.checker.frameworks["ISO27018"]["controls"]
        
        # Test each control passes with proper configuration
        for control_id, control in iso27018_controls.items():
            result = control["check"](bucket_checks)
            self.assertTrue(result, f"ISO 27018 control {control_id} should pass with proper configuration")
    
    def test_iso_remediation_steps(self):
        """Test ISO remediation steps are available for all controls."""
        iso_frameworks = ["ISO27001", "ISO27017", "ISO27018"]
        
        for framework in iso_frameworks:
            controls = self.checker.frameworks[framework]["controls"]
            for control_id in controls.keys():
                steps = self.checker.get_remediation_steps(framework, control_id)
                self.assertIsInstance(steps, list)
                self.assertGreater(len(steps), 0, 
                                 f"Control {framework}-{control_id} should have remediation steps")
    
    def test_iso_no_fake_controls(self):
        """Test that no fake control IDs exist in ISO frameworks."""
        # ISO 27001 should not have fake controls
        iso27001_controls = self.checker.frameworks["ISO27001"]["controls"]
        fake_iso27001_controls = ["5.15.1", "5.99", "FAKE.1"]
        for fake_control in fake_iso27001_controls:
            self.assertNotIn(fake_control, iso27001_controls)
        
        # ISO 27017 should not have fake controls
        iso27017_controls = self.checker.frameworks["ISO27017"]["controls"]
        fake_iso27017_controls = ["CLD.9.1.2", "CLD.99.1", "FAKE.CLD.1"]
        for fake_control in fake_iso27017_controls:
            self.assertNotIn(fake_control, iso27017_controls)
        
        # ISO 27018 should not have fake controls
        iso27018_controls = self.checker.frameworks["ISO27018"]["controls"]
        fake_iso27018_controls = ["PII.1.1", "PII.1.2", "FAKE.PII.1"]
        for fake_control in fake_iso27018_controls:
            self.assertNotIn(fake_control, iso27018_controls)

    # GDPR Tests
    def test_gdpr_controls_count(self):
        """Test GDPR framework has expected controls."""
        gdpr_controls = self.checker.frameworks["GDPR"]["controls"]
        self.assertEqual(len(gdpr_controls), 21)
        
        # Check for some expected control IDs
        expected_controls = ["G1", "G2", "G3", "G4", "G5", "G6", "G7", "G9", "G10", "G11", "G12", "G13", "G15", "G16", "G18", "G19", "G21", "G22", "G23", "G24", "G25"]
        for control in expected_controls:
            self.assertIn(control, gdpr_controls)
    
    def test_gdpr_control_descriptions(self):
        """Test GDPR controls have proper descriptions."""
        gdpr_controls = self.checker.frameworks["GDPR"]["controls"]
        
        # Test specific control descriptions contain Article references
        self.assertIn("Article 32", gdpr_controls["G1"]["description"])
        self.assertIn("Article 32", gdpr_controls["G2"]["description"])
        self.assertIn("Article 25", gdpr_controls["G9"]["description"])
        self.assertIn("Article 30", gdpr_controls["G11"]["description"])
        self.assertIn("Article 33", gdpr_controls["G13"]["description"])
        self.assertIn("Article 17", gdpr_controls["G15"]["description"])
        self.assertIn("Article 44", gdpr_controls["G18"]["description"])
        self.assertIn("Article 45", gdpr_controls["G19"]["description"])
        
        # Test that each control has required fields
        for control_id, control in gdpr_controls.items():
            self.assertIn("description", control)
            self.assertIn("severity", control)
            self.assertIn("check", control)
            self.assertIsInstance(control["description"], str)
            self.assertIn(control["severity"], ["HIGH", "MEDIUM", "LOW"])
            self.assertTrue(callable(control["check"]))
    
    def test_gdpr_framework_name(self):
        """Test GDPR framework has correct name."""
        framework_name = self.checker.frameworks["GDPR"]["name"]
        self.assertEqual(framework_name, "General Data Protection Regulation (EU) 2016/679")
    
    def test_gdpr_compliance_checks(self):
        """Test GDPR compliance checks with mock data."""
        # Mock bucket data for testing
        bucket_checks = {
            "encryption": {"is_enabled": True},
            "bucket_policy": {"ssl_enforced": True},
            "kms_key_management": {"kms_managed": True},
            "public_access_block": {"is_properly_configured": True},
            "is_public": False,
            "versioning": {"is_enabled": True, "mfa_delete_enabled": True},
            "lifecycle_rules": {"has_lifecycle_rules": True},
            "logging": {"is_enabled": True},
            "event_notifications": {"has_notifications": True},
            "object_lock": {"is_enabled": True},
            "cloudtrail_logging": {"is_enabled": True},
            "gdpr_purpose_limitation": {"purpose_restricted": True},
            "gdpr_replication_compliance": {"all_regions_compliant": True},
            "gdpr_data_residency": {"compliant_region": True},
            "gdpr_international_transfers": {"compliant_transfers": True},
            "transfer_acceleration": {"is_properly_configured": True},
            "cors": {"is_risky": False},
            "website_hosting": {"is_secure": True},
            "inventory_config": {"has_inventory": True},
            "analytics_config": {"is_secure": True}
        }
        
        gdpr_controls = self.checker.frameworks["GDPR"]["controls"]
        
        # Test some specific controls
        # G1 - Encryption at rest
        result = gdpr_controls["G1"]["check"](bucket_checks)
        self.assertTrue(result, "G1 should pass with encryption enabled")
        
        # G2 - SSL/TLS enforcement
        result = gdpr_controls["G2"]["check"](bucket_checks)
        self.assertTrue(result, "G2 should pass with SSL enforced")
        
        # G4 - Access controls
        result = gdpr_controls["G4"]["check"](bucket_checks)
        self.assertTrue(result, "G4 should pass with proper access controls")
        
        # G5 - Block public access
        result = gdpr_controls["G5"]["check"](bucket_checks)
        self.assertTrue(result, "G5 should pass with public access blocked")
        
        # G6 - Versioning
        result = gdpr_controls["G6"]["check"](bucket_checks)
        self.assertTrue(result, "G6 should pass with versioning enabled")
        
        # G11 - Audit logging
        result = gdpr_controls["G11"]["check"](bucket_checks)
        self.assertTrue(result, "G11 should pass with logging enabled")
        
        # Test failures
        bucket_checks["encryption"]["is_enabled"] = False
        result = gdpr_controls["G1"]["check"](bucket_checks)
        self.assertFalse(result, "G1 should fail without encryption")
        
        bucket_checks["bucket_policy"]["ssl_enforced"] = False
        result = gdpr_controls["G2"]["check"](bucket_checks)
        self.assertFalse(result, "G2 should fail without SSL enforcement")
    
    def test_gdpr_remediation_steps(self):
        """Test GDPR remediation steps are available for all controls."""
        gdpr_controls = self.checker.frameworks["GDPR"]["controls"]
        for control_id in gdpr_controls.keys():
            steps = self.checker.get_remediation_steps("GDPR", control_id)
            self.assertIsInstance(steps, list)
            self.assertGreater(len(steps), 0, 
                             f"Control {control_id} should have remediation steps")
    
    def test_gdpr_severity_levels(self):
        """Test GDPR controls have appropriate severity levels."""
        gdpr_controls = self.checker.frameworks["GDPR"]["controls"]
        
        # Test that core security controls are HIGH severity
        high_severity_controls = ["G1", "G2", "G3", "G4", "G5", "G11", "G12", "G18", "G19"]
        for control_id in high_severity_controls:
            if control_id in gdpr_controls:
                self.assertEqual(gdpr_controls[control_id]["severity"], "HIGH", 
                               f"Control {control_id} should be HIGH severity")
        
        # Test that some controls are MEDIUM severity
        medium_severity_controls = ["G6", "G7", "G9", "G10", "G13", "G15", "G16", "G22", "G23"]
        for control_id in medium_severity_controls:
            if control_id in gdpr_controls:
                self.assertEqual(gdpr_controls[control_id]["severity"], "MEDIUM", 
                               f"Control {control_id} should be MEDIUM severity")
        
        # Test that some controls are LOW severity
        low_severity_controls = ["G21", "G24", "G25"]
        for control_id in low_severity_controls:
            if control_id in gdpr_controls:
                self.assertEqual(gdpr_controls[control_id]["severity"], "LOW", 
                               f"Control {control_id} should be LOW severity")


if __name__ == "__main__":
    unittest.main()
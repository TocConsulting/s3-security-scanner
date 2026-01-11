# S3 Security Scanner

[![PyPI version](https://img.shields.io/pypi/v/s3-security-scanner.svg)](https://pypi.org/project/s3-security-scanner/)
[![License: MIT](https://img.shields.io/badge/License-MIT-brightgreen.svg)](https://opensource.org/licenses/MIT)
[![Python](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![AWS](https://img.shields.io/badge/AWS-S3-orange.svg)](https://aws.amazon.com/s3/)

A comprehensive, production-ready AWS S3 bucket security scanner with compliance mapping for CIS, AWS FSBP, PCI-DSS, HIPAA, SOC 2, ISO frameworks, and GDPR. Features multi-threaded scanning, object-level security analysis, and detailed remediation guidance.

## Key Features

### **Comprehensive Security Analysis**
- **Public Access Detection**: Multi-layered detection via ACLs, policies, and public access settings
- **Encryption Assessment**: Server-side encryption configuration analysis
- **Access Controls**: Versioning, MFA delete, and object lock evaluation
- **Object-Level Security**: Sample-based scanning for public objects and sensitive data patterns
- **CORS Analysis**: Detection of overly permissive cross-origin configurations
- **DNS Takeover Prevention**: Route53 and manual domain analysis for subdomain takeover risks
- **CNAME Information Disclosure**: Detection of sensitive information in DNS records

### **Compliance Frameworks**
- **CIS AWS Foundations Benchmark v3.0.0**: 6 S3-specific controls (100% coverage)
- **AWS Foundational Security Best Practices (FSBP)**: 11 S3-specific controls (100% coverage)
- **PCI DSS v4.0**: 10 AWS Config rules for PCI DSS compliance (100% coverage)  
- **HIPAA Security Rule**: 7 AWS Config rules for healthcare data protection (100% coverage)
- **SOC 2 Type II**: 12 controls supporting Trust Service Criteria (Variable compliance based on selected criteria)
- **ISO 27001:2022**: 7 information security controls (Access Control, Cloud Security, Cryptography, Backup, Logging, Info Transfer)
- **ISO 27017:2015**: 7 cloud security controls (Access Restriction, Shared Responsibility, Data Location, Monitoring, Logging, Data Deletion, Data Isolation)
- **ISO 27018:2019**: 4 PII protection controls (Purpose Limitation, Data Minimization, Retention/Deletion, Accountability)
- **GDPR (EU) 2016/679**: 21 implementable controls covering Articles 17, 25, 30, 32, 33, 44-49 (Data Protection, Security, International Transfers)
- **Real-time Compliance Scoring**: Automated compliance percentage calculation

**Note:** PCI DSS controls are implemented using AWS-recommended Config rules, as PCI DSS v4.0 itself does not define specific S3 requirements.

### **Performance & Usability**
- **Multi-threaded Scanning**: Parallel bucket analysis for faster results
- **Rich Console Output**: Progress bars, colored output, and formatted tables
- **Multiple Report Formats**: JSON, CSV, HTML, and compliance-specific reports
- **Beautiful HTML Reports**: Interactive dashboards with charts and visualizations
- **Flexible Targeting**: Scan all buckets or specific subsets

### **Production Ready**
- **Modular Architecture**: Clean separation of concerns with dedicated security check modules
- **Modern Python Packaging**: Uses pyproject.toml and follows best practices
- **Comprehensive CLI**: Rich command-line interface with extensive options
- **Error Handling**: Robust error recovery and partial scan results
- **Detailed Logging**: File and console logging with configurable levels

## Quick Start

### Installation

```bash
# Install from PyPI
pip install s3-security-scanner

# Or install from source
git clone https://github.com/TocConsulting/s3-security-scanner.git
cd s3-security-scanner
pip install .
```

### Basic Usage

The scanner has three main commands: `security`, `discover`, and `dns`.

```bash
# Scan all your S3 buckets for security issues
s3-security-scanner security

# Scan with specific AWS profile
s3-security-scanner security --profile production

# Scan specific buckets only
s3-security-scanner security --bucket my-bucket-1 --bucket my-bucket-2

# Discover S3 buckets for a target organization (no AWS credentials needed)
s3-security-scanner discover --target "company-name"

# Check domains for DNS takeover vulnerabilities
s3-security-scanner dns --domain example.com
```

## Commands

### Security Command

Scan your S3 buckets for security vulnerabilities and compliance issues.

```bash
s3-security-scanner security [OPTIONS]

Options:
  --bucket TEXT              Specific bucket(s) to scan (can be used multiple times)
  --exclude-bucket TEXT      Bucket(s) to exclude from scanning
  --compliance-only          Generate compliance report only
  --no-object-scan           Skip object analysis for faster results
  -d, --debug                Enable debug logging
  -q, --quiet                Suppress console output except errors
  -w, --max-workers INTEGER  Worker threads (default: 5)
  -f, --output-format        Report format: json, csv, html, all (default: all)
  -o, --output-dir TEXT      Output directory (default: ./output)
  -p, --profile TEXT         AWS profile name
  -r, --region TEXT          AWS region (default: us-east-1)
```

**Examples:**
```bash
# Scan all buckets with default settings
s3-security-scanner security

# Scan all buckets except specific ones
s3-security-scanner security --exclude-bucket temp-bucket --exclude-bucket dev-sandbox

# Fast compliance-only scan
s3-security-scanner security --compliance-only --no-object-scan -p production

# HTML report only
s3-security-scanner security -f html -o ./reports
```

### Discover Command

Find unknown S3 buckets for a target organization (no AWS credentials required for basic discovery).

```bash
s3-security-scanner discover [OPTIONS]

Options:
  --target TEXT           Target organization name (REQUIRED)
  --level TEXT            Permutation level: basic, medium, advanced (default: basic)
  --methods TEXT          Discovery methods: dns, http, permutations (default: dns,permutations)
  --only                  Only discover buckets, don't scan them for security issues
  --wordlist TEXT         Custom wordlist file for additional bucket names
  --stealth/--no-stealth  Enable stealth mode (default: enabled)
  -w, --max-workers       Worker threads (default: 5)
  -f, --output-format     Report format: json, csv, html, all (default: all)
  -o, --output-dir TEXT   Output directory (default: ./output)
  -p, --profile TEXT      AWS profile name
  -r, --region TEXT       AWS region (default: us-east-1)
  -d, --debug             Enable debug logging
  -q, --quiet             Suppress console output except errors
```

**Examples:**
```bash
# Discover buckets for a company (basic level, ~200 candidates, ~5 seconds)
s3-security-scanner discover --target "acme-corp"

# Medium discovery (~1,000 candidates, ~40 seconds)
s3-security-scanner discover --target "company" --level medium

# Advanced discovery (~9,000 candidates, ~9 minutes)
s3-security-scanner discover --target "company" --level advanced

# Discovery only - don't perform security scan even with AWS credentials
s3-security-scanner discover --target "company" --only
```

**Note:** If no AWS credentials are detected, discovery-only mode is automatically enabled.

### DNS Command

Check domains for DNS subdomain takeover vulnerabilities.

```bash
s3-security-scanner dns [OPTIONS]

Options:
  --domain TEXT              Domain(s) to scan (REQUIRED, can be used multiple times)
  --skip-subdomain-enum      Skip subdomain enumeration
  -p, --profile TEXT         AWS profile for Route53 scanning
  -r, --region TEXT          AWS region (default: us-east-1)
  -f, --output-format        Report format: json, csv, html, all (default: all)
  -o, --output-dir TEXT      Output directory (default: ./output)
  -w, --max-workers INTEGER  Worker threads (default: 5)
  -d, --debug                Enable debug logging
  -q, --quiet                Suppress console output except errors
```

**Examples:**
```bash
# Scan domains for takeover vulnerabilities
s3-security-scanner dns --domain example.com --domain test.com

# Use AWS profile for Route53 scanning
s3-security-scanner dns --domain example.com --profile production
```

## Prerequisites

### Python Requirements
- Python 3.8 or higher
- Required packages (installed automatically):
  - `boto3>=1.26.0`
  - `rich>=13.0.0`
  - `click>=8.1.0`
  - `jinja2>=3.1.0`
  - `dnspython>=2.4.0`

### AWS Requirements
- AWS credentials configured (via AWS CLI, environment variables, or IAM roles)
- Required permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:ListAllMyBuckets",
                "s3:GetBucketLocation",
                "s3:GetBucketAcl",
                "s3:GetBucketPolicy",
                "s3:GetBucketPublicAccessBlock",
                "s3:GetBucketEncryption",
                "s3:GetBucketVersioning",
                "s3:GetBucketLogging",
                "s3:GetBucketLifecycleConfiguration",
                "s3:GetBucketNotificationConfiguration",
                "s3:GetBucketReplication",
                "s3:GetBucketCors",
                "s3:GetObjectLockConfiguration",
                "s3:ListBucket",
                "s3:GetObjectAcl",
                "sts:GetCallerIdentity",
                "route53:ListHostedZones",
                "route53:ListResourceRecordSets",
                "cloudtrail:ListTrails",
                "cloudtrail:GetEventSelectors"
            ],
            "Resource": "*"
        }
    ]
}
```

## Security Checks

### Core Security Analysis

| Check | Description | Severity |
|-------|-------------|----------|
| **Public Access Block** | Verifies all four public access block settings | HIGH |
| **Bucket Policy** | Analyzes policies for public access and SSL enforcement | HIGH/MEDIUM |
| **Wildcard Principal** | Detects wildcard (*) principals in bucket policies | HIGH |
| **Bucket ACL** | Checks for public grants to AllUsers/AuthenticatedUsers | HIGH |
| **Default Encryption** | Validates server-side encryption configuration | MEDIUM |
| **Versioning** | Checks versioning and MFA delete status | LOW/MEDIUM |
| **Access Logging** | Verifies server access logging configuration | LOW |
| **Object Lock** | Assesses object lock and retention policies | INFO |
| **CORS Configuration** | Identifies overly permissive CORS rules | MEDIUM |
| **Lifecycle Rules** | Evaluates lifecycle management policies | INFO |
| **Event Notifications** | Checks for SNS/SQS/Lambda notification configuration | LOW |
| **Cross-Region Replication** | Validates replication configuration for disaster recovery | MEDIUM |
| **Transfer Acceleration** | Checks S3 Transfer Acceleration configuration | LOW |
| **Cross-Account Access** | Identifies cross-account principals in bucket policies | MEDIUM |
| **MFA Requirements** | Validates MFA conditions in bucket policies | HIGH |
| **Data Classification** | Analyzes bucket and object tagging for data governance | MEDIUM |
| **KMS Key Management** | Evaluates KMS key policies and rotation status | HIGH |
| **CloudWatch Monitoring** | Validates S3 metrics and alarm configuration | MEDIUM |
| **Storage Lens** | Checks Storage Lens configuration for governance | LOW |
| **DNS Takeover Prevention** | Scans Route53 and manual domains for takeover risks | CRITICAL |

### Object-Level Security (Sample-Based)

- **Public Object Detection**: Identifies objects with public ACLs
- **Sensitive Data Patterns**: Scans for potentially sensitive filenames:
  - SSN patterns: `\d{3}-\d{2}-\d{4}`
  - Credit card patterns: `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`
  - AWS access keys: `AKIA[0-9A-Z]{16}`
  - Private keys: `*.pem`, `*.key`, `*.pfx`
  - Password files: `*password*`, `*secret*`, `*credential*`
  - Database backups: `*.sql`, `*.dump`, `*.bak`

### Detailed Security Analysis

For comprehensive documentation of all security checks, attack vectors, and exploitation scenarios, see our detailed [Security Checks Documentation](security-checks.md). This document provides:

- **Detailed check explanations** with technical implementation details
- **Step-by-step attack scenarios** showing real-world exploitation methods
- **Compliance framework mappings** for CIS, PCI-DSS, HIPAA, and SOC 2
- **Real-world examples** of security breaches and their prevention
- **Defense-in-depth strategies** for comprehensive S3 security

### Security Remediation Guide

For step-by-step instructions on fixing all security vulnerabilities detected by the scanner, see our comprehensive [Remediation Guide](remediation-guide.md). This guide provides:

- **AWS Console instructions** with step-by-step procedures
- **AWS CLI commands** for automation and scripting
- **Python boto3 code** for programmatic remediation
- **Bulk remediation scripts** for hardening multiple buckets
- **Compliance-specific configurations** for GDPR, SOC 2, and other frameworks
- **Emergency response procedures** for security incidents

## Modular Architecture

The S3 Security Scanner is built with a clean, modular architecture that separates security checks into specialized modules:

### Core Structure
```
s3_security_scanner/
├── scanner.py                  # Main scanner orchestration
├── cli.py                      # Command-line interface
├── compliance.py               # Compliance framework mapping
├── html_reporter.py            # HTML report generation
├── utils.py                    # Shared utilities
├── bucket_utils.py             # Bucket utility functions
├── checks/                     # Security check modules
│   ├── base.py                 # Base check class
│   ├── access_control.py       # Public access & ACL checks
│   ├── encryption.py           # Encryption configuration
│   ├── logging_monitoring.py   # Logging & monitoring
│   ├── versioning_lifecycle.py # Versioning & lifecycle
│   ├── object_security.py      # Object-level security
│   ├── dns_security.py         # DNS takeover detection
│   ├── soc2_monitoring.py      # SOC 2 monitoring & governance
│   ├── cloudtrail_logging.py   # CloudTrail data events
│   ├── gdpr_compliance.py      # GDPR-specific checks
│   └── iso_compliance.py       # ISO compliance checks
├── discovery/                  # Bucket discovery modules
│   ├── bucket_discovery.py     # Discovery engine
│   ├── permutation_generator.py # Bucket name permutations
│   ├── dns_validator.py        # DNS validation
│   ├── http_validator.py       # HTTP validation
│   ├── wordlist_manager.py     # Wordlist management
│   ├── s3_bucket_wordlist.txt  # Bucket discovery wordlist
│   └── subdomain_wordlist.txt  # Subdomain wordlist
├── analyzers/                  # Data analysis modules
│   ├── pattern_analyzer.py     # Pattern extraction
│   └── dns_analyzer.py         # DNS/CNAME analysis
└── templates/                  # Report templates
    └── report.html             # HTML report template
```

### Key Benefits
- **Maintainability**: Each security domain has its own dedicated module
- **Testability**: Isolated components enable comprehensive unit testing
- **Scalability**: Easy to add new security checks without affecting existing code
- **Single Responsibility**: Each module focuses on one specific security area
- **Reusability**: Analyzers and checkers can be used independently

##  Security Scoring

### Individual Bucket Scoring

Each bucket receives a security score (0-100) starting with **100 points** and losing points for security issues:

| **Security Issue** | **Points Deducted** | **Severity** | **Description** |
|-------------------|-------------------|-------------|----------------|
| **Public Access Block Disabled** | **-20** | CRITICAL | Missing public access block settings |
| **Public Bucket Policy** | **-20** | CRITICAL | Bucket policy allows public access |
| **Public ACL Access** | **-20** | CRITICAL | ACL grants public permissions |
| **No SSL/TLS Enforcement** | **-15** | HIGH | Missing SSL/TLS enforcement |
| **No Encryption** | **-20** | HIGH | Default encryption not enabled |
| **Public Objects Found** | **-15** | HIGH | Objects with public ACLs detected |
| **No Versioning** | **-10** | MEDIUM | Versioning disabled |
| **Sensitive Objects Found** | **-10** | MEDIUM | Potentially sensitive files detected |
| **No MFA Delete** | **-5** | LOW | MFA delete not enabled |
| **No Logging** | **-5** | LOW | Server access logging disabled |
| **Risky CORS** | **-5** | LOW | Overly permissive CORS configuration |
| **No Object Lock** | **-3** | INFO | Object lock not configured |
| **No Lifecycle Rules** | **-2** | INFO | Lifecycle management not configured |

**Formula**: `Individual Score = max(0, 100 - total_deductions)`

### Average Security Score Calculation

The **"Avg Security Score"** displayed in reports is calculated as follows:

```python
# Step 1: Filter out buckets that failed to scan
valid_results = [bucket for bucket in results if not bucket.get("scan_error", False)]

# Step 2: Calculate average of all valid bucket scores
if valid_results:
    avg_security_score = sum(bucket.get("security_score", 0) for bucket in valid_results) / len(valid_results)
else:
    avg_security_score = 0

# Step 3: Round to appropriate precision
average_security_score = round(avg_security_score, 2)  # Stored with 2 decimals
display_score = "%.1f" % avg_security_score            # Displayed with 1 decimal
```

### Example Calculation

For an account with **3 buckets**:
- **Bucket A**: 85/100 (good security, minor logging issues)
- **Bucket B**: 45/100 (multiple public access vulnerabilities)  
- **Bucket C**: 92/100 (excellent security posture)

**Average Security Score = (85 + 45 + 92) ÷ 3 = 74.0**

### Score Interpretation

| **Score Range** | **Security Level** | **Recommendation** |
|-----------------|-------------------|-------------------|
| **90-100** | **Excellent** | Maintain current security posture |
| **70-89** |  **Good** | Address minor security gaps |
| **50-69** |  **Needs Improvement** | Fix medium-priority vulnerabilities |
| **0-49** |   **Poor** | Immediate action required - critical issues present |

### Key Features

- **Error-Safe**: Buckets that failed to scan are excluded from calculations
- **Weighted Fairly**: Each valid bucket contributes equally regardless of size
- **Priority-Based**: Critical security issues (public access) penalized more heavily than convenience features
- **Actionable**: Score directly correlates with security risk level

## Compliance Frameworks

### CIS AWS Foundations Benchmark v3.0.0

> [Official Documentation](https://www.cisecurity.org/benchmark/amazon_web_services) | [AWS Security Hub](https://docs.aws.amazon.com/securityhub/latest/userguide/cis-aws-foundations-benchmark.html)

| Control | Description | Check |
|---------|-------------|-------|
| **S3.1** | S3 buckets should have block public access settings enabled | Public access block configuration |
| **S3.5** | S3 buckets should require requests to use SSL | SSL enforcement in bucket policy |
| **S3.8** | S3 buckets should block public access | Overall public access assessment |
| **S3.9** | S3 buckets should have server access logging enabled | Access logging configuration |
| **S3.17** | S3 buckets should be encrypted at rest | Default encryption settings |
| **S3.20** | S3 buckets should have MFA delete enabled | MFA delete configuration |
| **S3.22** | S3 buckets should log object-level write events | CloudTrail data events |
| **S3.23** | S3 buckets should log object-level read events | CloudTrail data events |

### PCI DSS v4.0 (AWS Config Rules)

> [AWS PCI DSS Whitepaper](https://d1.awsstatic.com/whitepapers/compliance/pci-dss-compliance-on-aws-v4-102023.pdf) | [AWS Config Rules](https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-pci-dss-v4-including-global-resource-types.html)

| Control ID | AWS Config Rule | Focus Area |
|------------|-----------------|------------|
| **S3.1** | s3-bucket-public-access-prohibited | Public access prevention |
| **S3.5** | s3-bucket-ssl-requests-only | SSL/TLS enforcement |
| **S3.8** | s3-bucket-public-read-prohibited | Public read access prevention |
| **S3.9** | s3-bucket-logging-enabled | Access logging |
| **S3.15** | s3-bucket-default-lock-enabled | Audit trail protection |
| **S3.17** | s3-bucket-server-side-encryption-enabled | At-rest encryption |
| **S3.19** | s3-bucket-public-write-prohibited | Public write access prevention |
| **S3.22** | s3-bucket-level-public-access-prohibited | Bucket-level public access prevention |
| **S3.23** | s3-bucket-versioning-enabled | Data integrity and recovery |
| **S3.24** | s3-bucket-replication-enabled | Backup and disaster recovery |

### HIPAA Security Rule (AWS Config Rules)

> [AWS HIPAA Conformance Pack](https://docs.aws.amazon.com/config/latest/developerguide/operational-best-practices-for-hipaa_security.html) | [45 CFR Part 164](https://www.ecfr.gov/current/title-45/subtitle-A/subchapter-C/part-164)

| AWS Config Rule | HIPAA Section | Description |
|-----------------|---------------|-------------|
| **s3-bucket-server-side-encryption-enabled** | §164.312(a)(2)(iv) | Server-side encryption for PHI |
| **s3-bucket-ssl-requests-only** | §164.312(e)(1) | SSL/TLS transmission security |
| **s3-bucket-logging-enabled** | §164.312(b) | Access logging and audit controls |
| **s3-bucket-public-read-prohibited** | §164.312(a)(1) | Prohibit public read access |
| **s3-bucket-public-write-prohibited** | §164.312(a)(1) | Prohibit public write access |
| **s3-bucket-versioning-enabled** | §164.308(a)(7)(ii)(A) | Data backup and recovery |
| **s3-bucket-default-lock-enabled** | §164.308(a)(1)(ii)(D) | Object lock for assigned security responsibility |

### SOC 2 Type II - AWS S3 Controls Supporting Trust Service Criteria

> [AICPA SOC 2](https://www.aicpa-cima.com/topic/audit-assurance/audit-and-assurance-greater-than-soc-2) | [Trust Services Criteria](https://www.aicpa-cima.com/resources/download/get-description-criteria-for-your-organizations-soc-2-r-report)

| Control | Description | Trust Service Criteria |
|---------|-------------|------------------------|
| **SOC2-CC-ENCRYPTION-REST** | Server-side encryption enabled | Common Criteria - Security (CC6.6) |
| **SOC2-CC-ENCRYPTION-TRANSIT** | SSL/TLS enforcement for data in transit | Common Criteria - Security (CC6.6) |
| **SOC2-CC-ACCESS-CONTROL** | Proper access controls and public access blocking | Common Criteria - Security (CC6.1) |
| **SOC2-CC-MFA-REQUIREMENTS** | MFA requirements for sensitive operations | Common Criteria - Security (CC6.2) |
| **SOC2-CC-AUDIT-LOGGING** | Access logging for security monitoring | Common Criteria - Security (CC7.2) |
| **SOC2-CC-KEY-MANAGEMENT** | Encryption key management practices | Common Criteria - Security (CC6.8) |
| **SOC2-A-BACKUP-RECOVERY** | Versioning for data recovery | Availability (A1.2) |
| **SOC2-A-REPLICATION** | Cross-region replication for disaster recovery | Availability (A1.2) |
| **SOC2-A-MONITORING** | CloudWatch monitoring configuration | Availability (A1.3) |
| **SOC2-C-DATA-PROTECTION** | Confidential data access protection | Confidentiality (CC6.7) |
| **SOC2-PI-DATA-INTEGRITY** | Object lock for data integrity protection | Processing Integrity (CC8.1) |
| **SOC2-P-DATA-GOVERNANCE** | Storage Lens for data governance | Privacy (P2.1) |

**Note:** SOC 2 is a flexible framework where organizations choose which Trust Service Criteria to implement. Security (CC) is mandatory, while Availability (A), Confidentiality (C), Processing Integrity (PI), and Privacy (P) are optional based on business needs.

## Sample Output

### Console Summary
```
                   S3 Security Scan Summary - us-east-1                    
┌─────────────────────────────┬─────────────────┐
│ Metric                      │ Value           │
├─────────────────────────────┼─────────────────┤
│ Account ID                  │ 123456789012    │
│ Total Buckets               │ 25              │
│ Average Security Score      │ 78.5/100        │
│ Public Buckets              │ 3               │
│ High Severity Issues        │ 3               │
│ Medium Severity Issues      │ 8               │
│ Public Objects Found        │ 12              │
│ Sensitive Objects Found     │ 5               │
└─────────────────────────────┴─────────────────┘
```

### Compliance Summary
```
                     Compliance Framework Summary                      
┌───────────┬──────────────────┬──────────────┬──────────────┬─────────────────┐
│ Framework │ Compliant Buckets│ Total Buckets│ Compliance % │     Status      │
├───────────┼──────────────────┼──────────────┼──────────────┼─────────────────┤
│ CIS       │        18        │      25      │    72.0%     │    Good         │
│ PCI-DSS   │        15        │      25      │    60.0%     │    Needs Work   │
│ HIPAA     │        25        │      25      │   100.0%     │    Excellent    │
│ SOC 2     │        22        │      25      │    88.0%     │    Excellent    │
│ ISO 27001 │        17        │      25      │    68.0%     │    Good         │
│ ISO 27017 │        19        │      25      │    76.0%     │    Good         │
│ ISO 27018 │        12        │      25      │    48.0%     │    Needs Work   │
└───────────┴──────────────────┴──────────────┴──────────────┴─────────────────┘
```

## Advanced Usage

### High-Performance Scanning

```bash
# Increase worker threads for faster scanning
s3-security-scanner security -w 20

# Fast scan without object-level analysis
s3-security-scanner security --no-object-scan

# Compliance-only mode (fastest)
s3-security-scanner security --compliance-only --no-object-scan
```

### Integration with Other Tools

```bash
# Export results for further analysis with jq
s3-security-scanner security -q -f json && \
  cat output/s3_scan_*.json | jq '.results[] | select(.is_public == true)'

# Find all public buckets and fix them
s3-security-scanner security -q -f json && \
  cat output/s3_scan_*.json | jq -r '.results[] | select(.is_public == true) | .bucket_name' | \
  xargs -I {} aws s3api put-public-access-block --bucket {} \
    --public-access-block-configuration "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"
```

## Output Files

The scanner generates multiple report formats in the specified output directory:

### JSON Report (`s3_scan_region_timestamp.json`)
```json
{
  "summary": {
    "scan_time": "2025-01-15T10:30:45.123456",
    "region": "us-east-1",
    "account_id": "123456789012",
    "total_buckets": 25,
    "public_buckets": 3,
    "high_severity_buckets": 3,
    "average_security_score": 78.5
  },
  "results": [...]
}
```

### CSV Report (`s3_scan_region_timestamp.csv`)
Spreadsheet-friendly format with all key metrics and compliance status.

### HTML Report (`s3_scan_region_timestamp.html`)
Beautiful, interactive dashboard with:
- **Executive Summary**: Key metrics and risk indicators
- **Interactive Charts**: Security score distribution, compliance status, issues by severity
- **Detailed Tables**: Sortable and filterable bucket analysis
- **Compliance Matrix**: Framework-specific compliance status
- **Responsive Design**: Works on desktop and mobile devices

### Compliance Report (`s3_compliance_region_timestamp.json`)
Detailed compliance analysis with framework-specific results and remediation guidance.

### Log File (`s3_scan_timestamp.log`)
Comprehensive execution log with debug information and error details.

## Development

### Setting Up Development Environment

```bash
# Clone the repository
git clone https://github.com/TocConsulting/s3-security-scanner.git
cd s3-security-scanner

# Create virtual environment
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate

# Install in development mode
pip install -e ".[dev]"

# Install pre-commit hooks
pre-commit install
```


## Security Remediation Guide

For comprehensive step-by-step remediation instructions for all security vulnerabilities detected by the S3 Security Scanner, see our detailed **[Remediation Guide](remediation-guide.md)**.

The remediation guide provides:
- **AWS Console instructions** with step-by-step procedures
- **AWS CLI commands** for automation and scripting  
- **Python boto3 code** for programmatic remediation
- **Bulk remediation scripts** for hardening multiple buckets
- **Compliance-specific configurations** for GDPR, SOC 2, and other frameworks
- **Emergency response procedures** for security incidents

## Testing

### Running Tests

The project includes comprehensive unit tests using Python's unittest framework and moto for AWS service mocking.

```bash
# Install development dependencies including moto[s3]
pip install -e ".[dev]"

# Or install test dependencies manually
pip install pytest pytest-cov "moto[s3]"

# Run all tests
python -m pytest tests/ -v

# Run specific test file
python -m pytest tests/test_compliance.py -v

# Run with coverage
python -m pytest tests/ --cov=s3_security_scanner --cov-report=html
```

### Test Structure

```
tests/
├── __init__.py
├── test_cli.py                 # CLI option tests
├── test_compliance.py          # Compliance framework tests
├── test_scanner.py             # Scanner functionality tests
├── test_cloudtrail_logging.py  # CloudTrail logging tests
├── test_gdpr_compliance.py     # GDPR compliance tests
└── test_soc2_monitoring.py     # SOC 2 monitoring tests
```

The tests use `moto[s3]` to mock AWS S3 services specifically, allowing comprehensive testing without requiring actual AWS resources or incurring costs.

## Support & Contributing

### Getting Help
- **Documentation**: Check this README and inline help (`--help`)
- **Issues**: Report bugs via [GitHub Issues](https://github.com/TocConsulting/s3-security-scanner/issues)
- **Discussions**: Join conversations in [GitHub Discussions](https://github.com/TocConsulting/s3-security-scanner/discussions)

### Contributing
We welcome contributions! Please see our [Contributing Guide](CONTRIBUTING.md) for details on:
- Code style and standards
- Testing requirements
- Pull request process
- Development setup

### Roadmap
- [ ] Integration with AWS Security Hub
- [ ] Custom compliance framework support
- [ ] Automated remediation capabilities
- [ ] REST API interface
- [ ] Docker containerization
- [ ] CI/CD pipeline integrations

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Acknowledgments

- **AWS Security Best Practices**: Based on official AWS security recommendations
- **CIS Benchmarks**: Implements CIS AWS Foundations Benchmark controls
- **Security Community**: Inspired by the open-source security tools ecosystem

---

**Security Notice**: This tool is designed for defensive security purposes only. Always ensure you have proper authorization before scanning AWS resources. The tool requires read-only permissions and does not modify any AWS resources without explicit user confirmation.

**Performance Note**: Object-level scanning is sample-based (default: 100 objects per bucket) to balance security coverage with scan performance. For comprehensive object analysis, consider running dedicated object-level security tools.

**Version Compatibility**: This tool supports Python 3.8+ and is tested against the latest boto3 SDK versions. For legacy Python versions, please use an earlier release or upgrade your Python environment.

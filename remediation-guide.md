# S3 Security Scanner - Comprehensive Remediation Guide

This guide provides step-by-step remediation instructions for all security vulnerabilities detected by the S3 Security Scanner. Each vulnerability includes remediation steps using AWS Console, AWS CLI, and Python boto3 methods.

## Official AWS Documentation

| Topic | AWS Documentation |
|-------|------------------|
| S3 Security Best Practices | [AWS S3 Security](https://docs.aws.amazon.com/AmazonS3/latest/userguide/security-best-practices.html) |
| S3 Block Public Access | [Block Public Access](https://docs.aws.amazon.com/AmazonS3/latest/userguide/access-control-block-public-access.html) |
| S3 Encryption | [Server-Side Encryption](https://docs.aws.amazon.com/AmazonS3/latest/userguide/serv-side-encryption.html) |
| S3 Bucket Policies | [Bucket Policies](https://docs.aws.amazon.com/AmazonS3/latest/userguide/bucket-policies.html) |
| AWS CLI S3 Commands | [AWS CLI S3 Reference](https://docs.aws.amazon.com/cli/latest/reference/s3api/) |
| Boto3 S3 Documentation | [Boto3 S3 Service](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/s3.html) |

## Table of Contents

1. [Access Control Security](#access-control-security)
2. [Encryption & Data Protection](#encryption--data-protection)
3. [Versioning & Lifecycle Management](#versioning--lifecycle-management)
4. [Monitoring & Logging](#monitoring--logging)
5. [Replication & Backup](#replication--backup)
6. [Object-Level Security](#object-level-security)
7. [DNS Security](#dns-security)
8. [Compliance-Specific Configurations](#compliance-specific-configurations)

---

## Access Control Security

### 1. Public Access Block Configuration

**Issue**: Missing or incomplete S3 public access block settings
**Severity**: HIGH
**Compliance**: CIS S3.1, AWS-FSBP S3.1, PCI-DSS S3.1

#### AWS Console
1. Navigate to **S3 Console** → **Buckets**
2. Select your bucket → **Permissions** tab
3. Click **Edit** under **Block public access (bucket settings)**
4. Check all four options:
   - Block public access to buckets and objects granted through new access control lists (ACLs)
   - Block public access to buckets and objects granted through any access control lists (ACLs)
   - Block public access to buckets and objects granted through new public bucket or access point policies
   - Block public access to buckets and objects granted through any public bucket or access point policies
5. Click **Save changes**

#### AWS CLI
```bash
# Enable all public access block settings
aws s3api put-public-access-block \
  --bucket BUCKET_NAME \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Verify configuration
aws s3api get-public-access-block --bucket BUCKET_NAME
```

#### Python boto3
```python
import boto3

def enable_public_access_block(bucket_name):
    s3_client = boto3.client('s3')
    
    try:
        response = s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        print(f"Public access block enabled for {bucket_name}")
        return response
    except Exception as e:
        print(f"Error enabling public access block: {e}")
        return None

# Usage
enable_public_access_block('your-bucket-name')
```

---

### 2. Bucket Policy - Remove Public Access and Enforce SSL

**Issue**: Public access through bucket policies, missing SSL enforcement
**Severity**: HIGH
**Compliance**: CIS S3.5, AWS-FSBP S3.5, PCI-DSS S3.5

#### AWS Console
1. Navigate to **S3 Console** → **Buckets**
2. Select your bucket → **Permissions** tab
3. Scroll to **Bucket policy**
4. Click **Edit** and replace with SSL-enforcing policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureConnections",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::YOUR_BUCKET_NAME",
        "arn:aws:s3:::YOUR_BUCKET_NAME/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
```

5. Click **Save changes**

#### AWS CLI
```bash
# Create SSL-enforcing policy file
cat > ssl-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "DenyInsecureConnections",
      "Effect": "Deny",
      "Principal": "*",
      "Action": "s3:*",
      "Resource": [
        "arn:aws:s3:::BUCKET_NAME",
        "arn:aws:s3:::BUCKET_NAME/*"
      ],
      "Condition": {
        "Bool": {
          "aws:SecureTransport": "false"
        }
      }
    }
  ]
}
EOF

# Replace BUCKET_NAME with your actual bucket name
# On Linux:
sed -i 's/BUCKET_NAME/your-actual-bucket-name/g' ssl-policy.json
# On macOS:
# sed -i '' 's/BUCKET_NAME/your-actual-bucket-name/g' ssl-policy.json

# Apply the policy
aws s3api put-bucket-policy --bucket your-actual-bucket-name --policy file://ssl-policy.json

# Verify policy
aws s3api get-bucket-policy --bucket your-actual-bucket-name
```

#### Python boto3
```python
import boto3
import json

def enforce_ssl_policy(bucket_name):
    s3_client = boto3.client('s3')
    
    ssl_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "DenyInsecureConnections",
                "Effect": "Deny",
                "Principal": "*",
                "Action": "s3:*",
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*"
                ],
                "Condition": {
                    "Bool": {
                        "aws:SecureTransport": "false"
                    }
                }
            }
        ]
    }
    
    try:
        response = s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(ssl_policy)
        )
        print(f"SSL enforcement policy applied to {bucket_name}")
        return response
    except Exception as e:
        print(f"Error applying SSL policy: {e}")
        return None

# Usage
enforce_ssl_policy('your-bucket-name')
```

---

### 3. Bucket ACL - Remove Public Access Grants

**Issue**: Public access grants through Access Control Lists
**Severity**: HIGH
**Compliance**: AWS-FSBP S3.2, S3.3, PCI-DSS S3.19

#### AWS Console
1. Navigate to **S3 Console** → **Buckets**
2. Select your bucket → **Permissions** tab
3. Scroll to **Access control list (ACL)**
4. Click **Edit**
5. Remove any grants to:
   - **Everyone (public access)**
   - **Authenticated users group**
6. Keep only the **Bucket owner** permissions
7. Click **Save changes**

#### AWS CLI
```bash
# Set bucket ACL to private (removes all public grants)
aws s3api put-bucket-acl --bucket BUCKET_NAME --acl private

# Alternative: Set specific permissions for bucket owner only (using canonical user ID)
aws s3api put-bucket-acl --bucket BUCKET_NAME --grant-full-control id=YOUR_CANONICAL_USER_ID

# Verify ACL
aws s3api get-bucket-acl --bucket BUCKET_NAME
```

#### Python boto3
```python
import boto3

def set_private_acl(bucket_name):
    s3_client = boto3.client('s3')
    
    try:
        response = s3_client.put_bucket_acl(
            Bucket=bucket_name,
            ACL='private'
        )
        print(f"Bucket ACL set to private for {bucket_name}")
        return response
    except Exception as e:
        print(f"Error setting private ACL: {e}")
        return None

def remove_public_object_acls(bucket_name):
    """Remove public ACLs from all objects in bucket"""
    s3_client = boto3.client('s3')
    
    try:
        # List all objects
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=bucket_name)
        
        for page in pages:
            if 'Contents' in page:
                for obj in page['Contents']:
                    # Set object ACL to private
                    s3_client.put_object_acl(
                        Bucket=bucket_name,
                        Key=obj['Key'],
                        ACL='private'
                    )
                    print(f"Set private ACL for object: {obj['Key']}")

        print(f"All object ACLs set to private in {bucket_name}")
    except Exception as e:
        print(f"Error removing public object ACLs: {e}")

# Usage
set_private_acl('your-bucket-name')
remove_public_object_acls('your-bucket-name')
```

---

### 4. MFA Requirements for Sensitive Operations

**Issue**: Missing MFA requirements for sensitive operations
**Severity**: MEDIUM
**Compliance**: SOC2 MFA requirements

#### AWS Console
1. Navigate to **S3 Console** → **Buckets**
2. Select your bucket → **Permissions** tab
3. Click **Edit** under **Bucket policy**
4. Add MFA requirement policy:

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireMFAForSensitiveOperations",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:DeleteObject",
        "s3:DeleteBucket",
        "s3:PutBucketPolicy",
        "s3:PutBucketAcl"
      ],
      "Resource": [
        "arn:aws:s3:::YOUR_BUCKET_NAME",
        "arn:aws:s3:::YOUR_BUCKET_NAME/*"
      ],
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
```

#### AWS CLI
```bash
# Create MFA requirement policy
cat > mfa-policy.json << 'EOF'
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "RequireMFAForSensitiveOperations",
      "Effect": "Deny",
      "Principal": "*",
      "Action": [
        "s3:DeleteObject",
        "s3:DeleteBucket",
        "s3:PutBucketPolicy",
        "s3:PutBucketAcl"
      ],
      "Resource": [
        "arn:aws:s3:::BUCKET_NAME",
        "arn:aws:s3:::BUCKET_NAME/*"
      ],
      "Condition": {
        "BoolIfExists": {
          "aws:MultiFactorAuthPresent": "false"
        }
      }
    }
  ]
}
EOF

# Replace BUCKET_NAME
# On Linux:
sed -i 's/BUCKET_NAME/your-bucket-name/g' mfa-policy.json
# On macOS:
# sed -i '' 's/BUCKET_NAME/your-bucket-name/g' mfa-policy.json

# Apply MFA policy
aws s3api put-bucket-policy --bucket your-bucket-name --policy file://mfa-policy.json
```

#### Python boto3
```python
import boto3
import json

def enforce_mfa_requirement(bucket_name):
    s3_client = boto3.client('s3')
    
    mfa_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "RequireMFAForSensitiveOperations",
                "Effect": "Deny",
                "Principal": "*",
                "Action": [
                    "s3:DeleteObject",
                    "s3:DeleteBucket",
                    "s3:PutBucketPolicy",
                    "s3:PutBucketAcl"
                ],
                "Resource": [
                    f"arn:aws:s3:::{bucket_name}",
                    f"arn:aws:s3:::{bucket_name}/*"
                ],
                "Condition": {
                    "BoolIfExists": {
                        "aws:MultiFactorAuthPresent": "false"
                    }
                }
            }
        ]
    }
    
    try:
        response = s3_client.put_bucket_policy(
            Bucket=bucket_name,
            Policy=json.dumps(mfa_policy)
        )
        print(f"MFA requirement policy applied to {bucket_name}")
        return response
    except Exception as e:
        print(f"Error applying MFA policy: {e}")
        return None

# Usage
enforce_mfa_requirement('your-bucket-name')
```

---

## Encryption & Data Protection

### 5. Enable Server-Side Encryption

**Issue**: Missing default encryption at rest
**Severity**: HIGH
**Compliance**: All frameworks require encryption

#### AWS Console
1. Navigate to **S3 Console** → **Buckets**
2. Select your bucket → **Properties** tab
3. Scroll to **Default encryption**
4. Click **Edit**
5. Choose encryption type:
   - **SSE-S3**: Amazon S3 managed keys
   - **SSE-KMS**: AWS Key Management Service
6. If using KMS:
   - Choose AWS managed key: `aws/s3`
   - Or create/choose customer managed key
7. Click **Save changes**

#### AWS CLI
```bash
# Enable SSE-S3 encryption
aws s3api put-bucket-encryption \
  --bucket BUCKET_NAME \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'

# Enable SSE-KMS encryption with AWS managed key
aws s3api put-bucket-encryption \
  --bucket BUCKET_NAME \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "aws/s3"
      }
    }]
  }'

# Enable SSE-KMS with customer managed key
aws s3api put-bucket-encryption \
  --bucket BUCKET_NAME \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "aws:kms",
        "KMSMasterKeyID": "arn:aws:kms:region:account:key/key-id"
      },
      "BucketKeyEnabled": true
    }]
  }'

# Verify encryption
aws s3api get-bucket-encryption --bucket BUCKET_NAME
```

#### Python boto3
```python
import boto3

def enable_bucket_encryption(bucket_name, encryption_type='SSE-S3', kms_key_id=None):
    s3_client = boto3.client('s3')
    
    if encryption_type == 'SSE-S3':
        encryption_config = {
            'Rules': [{
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'AES256'
                }
            }]
        }
    elif encryption_type == 'SSE-KMS':
        encryption_config = {
            'Rules': [{
                'ApplyServerSideEncryptionByDefault': {
                    'SSEAlgorithm': 'aws:kms',
                    'KMSMasterKeyID': kms_key_id or 'aws/s3'
                },
                'BucketKeyEnabled': True
            }]
        }
    else:
        raise ValueError("Invalid encryption type. Use 'SSE-S3' or 'SSE-KMS'")
    
    try:
        response = s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration=encryption_config
        )
        print(f"{encryption_type} encryption enabled for {bucket_name}")
        return response
    except Exception as e:
        print(f"Error enabling encryption: {e}")
        return None

# Usage examples
enable_bucket_encryption('your-bucket-name', 'SSE-S3')
enable_bucket_encryption('your-bucket-name', 'SSE-KMS')
enable_bucket_encryption('your-bucket-name', 'SSE-KMS', 'your-kms-key-id')
```

---

### 6. KMS Key Management and Rotation

**Issue**: Improper KMS key management and rotation
**Severity**: HIGH
**Compliance**: SOC2 key management, GDPR encryption

#### AWS Console
1. Navigate to **KMS Console** → **Customer managed keys**
2. Select your KMS key
3. In **Key rotation** section:
   - Enable **Automatic key rotation**
   - Set rotation period (default: 365 days)
4. Review **Key policy** for proper access controls
5. Click **Save**

#### AWS CLI
```bash
# Enable automatic key rotation
aws kms enable-key-rotation --key-id YOUR_KMS_KEY_ID

# Get rotation status
aws kms get-key-rotation-status --key-id YOUR_KMS_KEY_ID

# Create a new customer managed key with rotation enabled
aws kms create-key \
  --description "S3 bucket encryption key" \
  --key-usage ENCRYPT_DECRYPT \
  --key-spec SYMMETRIC_DEFAULT \
  --enable-key-rotation

# Update key policy for restricted access
aws kms put-key-policy \
  --key-id YOUR_KMS_KEY_ID \
  --policy-name default \
  --policy file://key-policy.json
```

#### Python boto3
```python
import boto3
import json

def enable_key_rotation(key_id):
    kms_client = boto3.client('kms')
    
    try:
        # Enable automatic key rotation
        response = kms_client.enable_key_rotation(KeyId=key_id)
        print(f"Key rotation enabled for {key_id}")

        # Verify rotation status
        rotation_status = kms_client.get_key_rotation_status(KeyId=key_id)
        print(f"Rotation status: {rotation_status['KeyRotationEnabled']}")

        return response
    except Exception as e:
        print(f"Error enabling key rotation: {e}")
        return None

def create_kms_key_for_s3(description="S3 bucket encryption key"):
    kms_client = boto3.client('kms')
    
    # Key policy for S3 usage
    key_policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "Enable IAM User Permissions",
                "Effect": "Allow",
                "Principal": {
                    "AWS": f"arn:aws:iam::{boto3.client('sts').get_caller_identity()['Account']}:root"
                },
                "Action": "kms:*",
                "Resource": "*"
            },
            {
                "Sid": "Allow S3 Service",
                "Effect": "Allow",
                "Principal": {
                    "Service": "s3.amazonaws.com"
                },
                "Action": [
                    "kms:Decrypt",
                    "kms:GenerateDataKey"
                ],
                "Resource": "*"
            }
        ]
    }
    
    try:
        response = kms_client.create_key(
            Description=description,
            KeyUsage='ENCRYPT_DECRYPT',
            KeySpec='SYMMETRIC_DEFAULT',
            Policy=json.dumps(key_policy)
        )
        
        key_id = response['KeyMetadata']['KeyId']
        
        # Enable rotation
        kms_client.enable_key_rotation(KeyId=key_id)
        
        print(f"KMS key created: {key_id}")
        print(f"Key rotation enabled")

        return key_id
    except Exception as e:
        print(f"Error creating KMS key: {e}")
        return None

# Usage
enable_key_rotation('your-kms-key-id')
new_key_id = create_kms_key_for_s3()
```

---

## Versioning & Lifecycle Management

### 7. Enable Versioning and MFA Delete

**Issue**: Missing versioning for data protection
**Severity**: MEDIUM
**Compliance**: PCI-DSS S3.23, HIPAA data backup

#### AWS Console
1. Navigate to **S3 Console** → **Buckets**
2. Select your bucket → **Properties** tab
3. Scroll to **Bucket Versioning**
4. Click **Edit**
5. Select **Enable**
6. **For MFA Delete** (requires root account):
   - Cannot be enabled via console
   - Must use CLI or API

#### AWS CLI
```bash
# Enable versioning
aws s3api put-bucket-versioning \
  --bucket BUCKET_NAME \
  --versioning-configuration Status=Enabled

# Enable versioning with MFA Delete (requires root account and MFA device)
aws s3api put-bucket-versioning \
  --bucket BUCKET_NAME \
  --versioning-configuration Status=Enabled,MFADelete=Enabled \
  --mfa "arn:aws:iam::ACCOUNT:mfa/root-account-mfa-device 123456"

# Verify versioning status
aws s3api get-bucket-versioning --bucket BUCKET_NAME
```

#### Python boto3
```python
import boto3

def enable_versioning(bucket_name, mfa_delete=False, mfa_device=None, mfa_token=None):
    s3_client = boto3.client('s3')
    
    versioning_config = {
        'Status': 'Enabled'
    }
    
    # MFA Delete requires root account credentials
    if mfa_delete and mfa_device and mfa_token:
        versioning_config['MFADelete'] = 'Enabled'
    
    try:
        if mfa_delete and mfa_device and mfa_token:
            response = s3_client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration=versioning_config,
                MFA=f"{mfa_device} {mfa_token}"
            )
        else:
            response = s3_client.put_bucket_versioning(
                Bucket=bucket_name,
                VersioningConfiguration=versioning_config
            )
        
        print(f"Versioning enabled for {bucket_name}")
        if mfa_delete:
            print(f"MFA Delete enabled for {bucket_name}")

        return response
    except Exception as e:
        print(f"Error enabling versioning: {e}")
        return None

def verify_versioning_status(bucket_name):
    s3_client = boto3.client('s3')
    
    try:
        response = s3_client.get_bucket_versioning(Bucket=bucket_name)
        status = response.get('Status', 'Disabled')
        mfa_delete = response.get('MFADelete', 'Disabled')
        
        print(f"Versioning Status: {status}")
        print(f"MFA Delete: {mfa_delete}")
        
        return response
    except Exception as e:
        print(f"Error checking versioning status: {e}")
        return None

# Usage
enable_versioning('your-bucket-name')
verify_versioning_status('your-bucket-name')
```

---

### 8. Configure Lifecycle Rules

**Issue**: Missing data lifecycle management
**Severity**: LOW
**Compliance**: AWS-FSBP S3.13, GDPR data minimization

#### AWS Console
1. Navigate to **S3 Console** → **Buckets**
2. Select your bucket → **Management** tab
3. Click **Create lifecycle rule**
4. Configure rule:
   - **Rule name**: Enter descriptive name
   - **Status**: Enabled
   - **Filter**: Choose scope (entire bucket or prefix)
5. Configure **Lifecycle rule actions**:
   - **Transition current versions** (e.g., IA after 30 days, Glacier after 90 days)
   - **Transition previous versions** (for versioned buckets)
   - **Expire current versions** (delete after X days)
   - **Expire previous versions** (delete old versions)
6. Click **Create rule**

#### AWS CLI
```bash
# Create lifecycle configuration file
cat > lifecycle.json << 'EOF'
{
  "Rules": [
    {
      "ID": "DataLifecycleRule",
      "Status": "Enabled",
      "Filter": {},
      "Transitions": [
        {
          "Days": 30,
          "StorageClass": "STANDARD_IA"
        },
        {
          "Days": 90,
          "StorageClass": "GLACIER"
        },
        {
          "Days": 365,
          "StorageClass": "DEEP_ARCHIVE"
        }
      ],
      "Expiration": {
        "Days": 2555
      },
      "NoncurrentVersionTransitions": [
        {
          "NoncurrentDays": 30,
          "StorageClass": "STANDARD_IA"
        },
        {
          "NoncurrentDays": 90,
          "StorageClass": "GLACIER"
        }
      ],
      "NoncurrentVersionExpiration": {
        "NoncurrentDays": 365
      }
    }
  ]
}
EOF

# Apply lifecycle configuration
aws s3api put-bucket-lifecycle-configuration \
  --bucket BUCKET_NAME \
  --lifecycle-configuration file://lifecycle.json

# Verify lifecycle configuration
aws s3api get-bucket-lifecycle-configuration --bucket BUCKET_NAME
```

#### Python boto3
```python
import boto3

def create_lifecycle_rule(bucket_name, rule_name="DataLifecycleRule"):
    s3_client = boto3.client('s3')
    
    lifecycle_config = {
        'Rules': [
            {
                'ID': rule_name,
                'Status': 'Enabled',
                'Filter': {},
                'Transitions': [
                    {
                        'Days': 30,
                        'StorageClass': 'STANDARD_IA'
                    },
                    {
                        'Days': 90,
                        'StorageClass': 'GLACIER'
                    },
                    {
                        'Days': 365,
                        'StorageClass': 'DEEP_ARCHIVE'
                    }
                ],
                'Expiration': {
                    'Days': 2555  # ~7 years
                },
                'NoncurrentVersionTransitions': [
                    {
                        'NoncurrentDays': 30,
                        'StorageClass': 'STANDARD_IA'
                    },
                    {
                        'NoncurrentDays': 90,
                        'StorageClass': 'GLACIER'
                    }
                ],
                'NoncurrentVersionExpiration': {
                    'NoncurrentDays': 365
                }
            }
        ]
    }
    
    try:
        response = s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_config
        )
        print(f"Lifecycle rule '{rule_name}' created for {bucket_name}")
        return response
    except Exception as e:
        print(f"Error creating lifecycle rule: {e}")
        return None

def create_gdpr_compliant_lifecycle_rule(bucket_name, retention_days=365):
    """Create GDPR-compliant lifecycle rule for data minimization"""
    s3_client = boto3.client('s3')
    
    lifecycle_config = {
        'Rules': [
            {
                'ID': 'GDPRDataMinimization',
                'Status': 'Enabled',
                'Filter': {},
                'Expiration': {
                    'Days': retention_days
                },
                'NoncurrentVersionExpiration': {
                    'NoncurrentDays': 30
                }
            }
        ]
    }
    
    try:
        response = s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration=lifecycle_config
        )
        print(f"GDPR lifecycle rule created for {bucket_name} ({retention_days} days)")
        return response
    except Exception as e:
        print(f"Error creating GDPR lifecycle rule: {e}")
        return None

# Usage
create_lifecycle_rule('your-bucket-name')
create_gdpr_compliant_lifecycle_rule('your-bucket-name', 365)
```

---

### 9. Enable Object Lock

**Issue**: Missing WORM (Write Once, Read Many) capability
**Severity**: MEDIUM
**Compliance**: PCI-DSS S3.15, HIPAA audit trail protection

#### AWS Console
1. **Note**: Object Lock must be enabled during bucket creation
2. Navigate to **S3 Console** → **Create bucket**
3. In **Object Lock** section:
   - Check **Enable Object Lock**
4. After bucket creation, configure default retention:
   - Go to **Properties** tab → **Object Lock**
   - Click **Edit**
   - Set **Default retention mode**:
     - **Governance**: Can be overridden with proper permissions
     - **Compliance**: Cannot be overridden
   - Set **Default retention period**
5. Click **Save changes**

#### AWS CLI
```bash
# Create bucket with Object Lock enabled
aws s3api create-bucket \
  --bucket BUCKET_NAME \
  --region us-east-1 \
  --object-lock-enabled-for-bucket

# Configure default retention
aws s3api put-object-lock-configuration \
  --bucket BUCKET_NAME \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "GOVERNANCE",
        "Years": 1
      }
    }
  }'

# For compliance mode (cannot be overridden)
aws s3api put-object-lock-configuration \
  --bucket BUCKET_NAME \
  --object-lock-configuration '{
    "ObjectLockEnabled": "Enabled",
    "Rule": {
      "DefaultRetention": {
        "Mode": "COMPLIANCE",
        "Years": 7
      }
    }
  }'

# Verify Object Lock configuration
aws s3api get-object-lock-configuration --bucket BUCKET_NAME
```

#### Python boto3
```python
import boto3

def create_bucket_with_object_lock(bucket_name, region='us-east-1'):
    s3_client = boto3.client('s3', region_name=region)
    
    try:
        if region == 'us-east-1':
            response = s3_client.create_bucket(
                Bucket=bucket_name,
                ObjectLockEnabledForBucket=True
            )
        else:
            response = s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region},
                ObjectLockEnabledForBucket=True
            )
        
        print(f"Bucket {bucket_name} created with Object Lock enabled")
        return response
    except Exception as e:
        print(f"Error creating bucket with Object Lock: {e}")
        return None

def configure_object_lock_retention(bucket_name, mode='GOVERNANCE', years=1):
    s3_client = boto3.client('s3')
    
    object_lock_config = {
        'ObjectLockEnabled': 'Enabled',
        'Rule': {
            'DefaultRetention': {
                'Mode': mode,
                'Years': years
            }
        }
    }
    
    try:
        response = s3_client.put_object_lock_configuration(
            Bucket=bucket_name,
            ObjectLockConfiguration=object_lock_config
        )
        print(f"Object Lock configured for {bucket_name} - Mode: {mode}, Years: {years}")
        return response
    except Exception as e:
        print(f"Error configuring Object Lock: {e}")
        return None

def enable_legal_hold(bucket_name, object_key):
    """Enable legal hold on specific object"""
    s3_client = boto3.client('s3')
    
    try:
        response = s3_client.put_object_legal_hold(
            Bucket=bucket_name,
            Key=object_key,
            LegalHold={'Status': 'ON'}
        )
        print(f"Legal hold enabled for {object_key}")
        return response
    except Exception as e:
        print(f"Error enabling legal hold: {e}")
        return None

# Usage
create_bucket_with_object_lock('your-new-bucket-name')
configure_object_lock_retention('your-new-bucket-name', 'GOVERNANCE', 1)
configure_object_lock_retention('your-compliance-bucket', 'COMPLIANCE', 7)
```

---

## Monitoring & Logging

### 10. Enable Server Access Logging

**Issue**: Missing access audit trails
**Severity**: LOW
**Compliance**: All frameworks require logging

#### AWS Console
1. Navigate to **S3 Console** → **Buckets**
2. Select your bucket → **Properties** tab
3. Scroll to **Server access logging**
4. Click **Edit**
5. Select **Enable**
6. Choose **Target bucket** (where logs will be stored)
7. Set **Target prefix** (e.g., `access-logs/`)
8. Click **Save changes**

#### AWS CLI
```bash
# Create logging bucket first (if needed)
aws s3 mb s3://your-logging-bucket

# Enable server access logging
aws s3api put-bucket-logging \
  --bucket BUCKET_NAME \
  --bucket-logging-status '{
    "LoggingEnabled": {
      "TargetBucket": "your-logging-bucket",
      "TargetPrefix": "access-logs/"
    }
  }'

# Verify logging configuration
aws s3api get-bucket-logging --bucket BUCKET_NAME
```

#### Python boto3
```python
import boto3

def enable_access_logging(bucket_name, log_bucket_name, log_prefix='access-logs/'):
    s3_client = boto3.client('s3')
    
    # Create logging bucket if it doesn't exist
    try:
        s3_client.head_bucket(Bucket=log_bucket_name)
    except:
        try:
            s3_client.create_bucket(Bucket=log_bucket_name)
            print(f"Created logging bucket: {log_bucket_name}")
        except Exception as e:
            print(f"Error creating logging bucket: {e}")
            return None
    
    # Enable logging
    logging_config = {
        'LoggingEnabled': {
            'TargetBucket': log_bucket_name,
            'TargetPrefix': log_prefix
        }
    }
    
    try:
        response = s3_client.put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus=logging_config
        )
        print(f"Access logging enabled for {bucket_name}")
        print(f"   Logs will be stored in: s3://{log_bucket_name}/{log_prefix}")
        return response
    except Exception as e:
        print(f"Error enabling access logging: {e}")
        return None

def verify_logging_status(bucket_name):
    s3_client = boto3.client('s3')
    
    try:
        response = s3_client.get_bucket_logging(Bucket=bucket_name)
        if 'LoggingEnabled' in response:
            target_bucket = response['LoggingEnabled']['TargetBucket']
            target_prefix = response['LoggingEnabled']['TargetPrefix']
            print(f"Logging enabled: s3://{target_bucket}/{target_prefix}")
        else:
            print("Access logging is not enabled")
        return response
    except Exception as e:
        print(f"Error checking logging status: {e}")
        return None

# Usage
enable_access_logging('your-bucket-name', 'your-logging-bucket')
verify_logging_status('your-bucket-name')
```

---

### 11. Configure Event Notifications

**Issue**: Missing security event monitoring
**Severity**: LOW
**Compliance**: CIS S3.11, security monitoring

#### AWS Console
1. Navigate to **S3 Console** → **Buckets**
2. Select your bucket → **Properties** tab
3. Scroll to **Event notifications**
4. Click **Create event notification**
5. Configure notification:
   - **Event name**: Enter descriptive name
   - **Event types**: Select relevant events
     - `s3:ObjectCreated:*`
     - `s3:ObjectRemoved:*`
     - `s3:ObjectRestore:*`
   - **Destination**: Choose SNS topic, SQS queue, or Lambda function
6. Click **Save changes**

#### AWS CLI
```bash
# Create SNS topic for notifications
aws sns create-topic --name s3-security-notifications

# Get topic ARN
TOPIC_ARN=$(aws sns list-topics --query 'Topics[?contains(TopicArn, `s3-security-notifications`)].TopicArn' --output text)

# Create event notification configuration
cat > event-config.json << EOF
{
  "TopicConfigurations": [
    {
      "Id": "S3SecurityNotifications",
      "TopicArn": "$TOPIC_ARN",
      "Events": [
        "s3:ObjectCreated:*",
        "s3:ObjectRemoved:*",
        "s3:ObjectRestore:*"
      ]
    }
  ]
}
EOF

# Apply event notification
aws s3api put-bucket-notification-configuration \
  --bucket BUCKET_NAME \
  --notification-configuration file://event-config.json

# Verify configuration
aws s3api get-bucket-notification-configuration --bucket BUCKET_NAME
```

#### Python boto3
```python
import boto3

def create_sns_topic_for_s3(topic_name='s3-security-notifications'):
    sns_client = boto3.client('sns')
    
    try:
        response = sns_client.create_topic(Name=topic_name)
        topic_arn = response['TopicArn']
        print(f"SNS topic created: {topic_arn}")
        return topic_arn
    except Exception as e:
        print(f"Error creating SNS topic: {e}")
        return None

def configure_event_notifications(bucket_name, topic_arn):
    s3_client = boto3.client('s3')
    
    notification_config = {
        'TopicConfigurations': [
            {
                'Id': 'S3SecurityNotifications',
                'TopicArn': topic_arn,
                'Events': [
                    's3:ObjectCreated:*',
                    's3:ObjectRemoved:*',
                    's3:ObjectRestore:*'
                ]
            }
        ]
    }
    
    try:
        response = s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration=notification_config
        )
        print(f"Event notifications configured for {bucket_name}")
        return response
    except Exception as e:
        print(f"Error configuring event notifications: {e}")
        return None

def configure_lambda_notifications(bucket_name, lambda_function_arn):
    s3_client = boto3.client('s3')
    
    notification_config = {
        'LambdaConfigurations': [
            {
                'Id': 'S3SecurityLambdaNotifications',
                'LambdaFunctionArn': lambda_function_arn,
                'Events': [
                    's3:ObjectCreated:*',
                    's3:ObjectRemoved:*'
                ]
            }
        ]
    }
    
    try:
        response = s3_client.put_bucket_notification_configuration(
            Bucket=bucket_name,
            NotificationConfiguration=notification_config
        )
        print(f"Lambda notifications configured for {bucket_name}")
        return response
    except Exception as e:
        print(f"Error configuring Lambda notifications: {e}")
        return None

# Usage
topic_arn = create_sns_topic_for_s3()
if topic_arn:
    configure_event_notifications('your-bucket-name', topic_arn)
```

---

## Object-Level Security

### 12. Fix CORS Configuration

**Issue**: Overly permissive cross-origin access
**Severity**: MEDIUM
**Compliance**: Browser security, GDPR

#### AWS Console
1. Navigate to **S3 Console** → **Buckets**
2. Select your bucket → **Permissions** tab
3. Scroll to **Cross-origin resource sharing (CORS)**
4. Click **Edit**
5. Replace with secure CORS policy:

```json
[
  {
    "AllowedHeaders": ["*"],
    "AllowedMethods": ["GET", "POST"],
    "AllowedOrigins": ["https://yourdomain.com"],
    "ExposeHeaders": [],
    "MaxAgeSeconds": 3000
  }
]
```

6. Click **Save changes**

#### AWS CLI
```bash
# Create secure CORS configuration
cat > cors-config.json << 'EOF'
{
  "CORSRules": [
    {
      "AllowedHeaders": ["*"],
      "AllowedMethods": ["GET", "POST"],
      "AllowedOrigins": ["https://yourdomain.com"],
      "ExposeHeaders": [],
      "MaxAgeSeconds": 3000
    }
  ]
}
EOF

# Apply CORS configuration
aws s3api put-bucket-cors \
  --bucket BUCKET_NAME \
  --cors-configuration file://cors-config.json

# Remove CORS configuration completely (if not needed)
aws s3api delete-bucket-cors --bucket BUCKET_NAME

# Verify CORS configuration
aws s3api get-bucket-cors --bucket BUCKET_NAME
```

#### Python boto3
```python
import boto3

def configure_secure_cors(bucket_name, allowed_origins=None):
    s3_client = boto3.client('s3')
    
    if allowed_origins is None:
        allowed_origins = ['https://yourdomain.com']
    
    cors_config = {
        'CORSRules': [
            {
                'AllowedHeaders': ['*'],
                'AllowedMethods': ['GET', 'POST'],
                'AllowedOrigins': allowed_origins,
                'ExposeHeaders': [],
                'MaxAgeSeconds': 3000
            }
        ]
    }
    
    try:
        response = s3_client.put_bucket_cors(
            Bucket=bucket_name,
            CORSConfiguration=cors_config
        )
        print(f"Secure CORS configuration applied to {bucket_name}")
        print(f"   Allowed origins: {allowed_origins}")
        return response
    except Exception as e:
        print(f"Error configuring CORS: {e}")
        return None

def remove_cors_configuration(bucket_name):
    s3_client = boto3.client('s3')
    
    try:
        response = s3_client.delete_bucket_cors(Bucket=bucket_name)
        print(f"CORS configuration removed from {bucket_name}")
        return response
    except Exception as e:
        print(f"Error removing CORS configuration: {e}")
        return None

def verify_cors_configuration(bucket_name):
    s3_client = boto3.client('s3')
    
    try:
        response = s3_client.get_bucket_cors(Bucket=bucket_name)
        print(f"Current CORS configuration for {bucket_name}:")
        for rule in response['CORSRules']:
            print(f"  Origins: {rule['AllowedOrigins']}")
            print(f"  Methods: {rule['AllowedMethods']}")
        return response
    except Exception as e:
        if 'NoSuchCORSConfiguration' in str(e):
            print(f"No CORS configuration found for {bucket_name}")
        else:
            print(f"Error checking CORS configuration: {e}")
        return None

# Usage
configure_secure_cors('your-bucket-name', ['https://yourdomain.com', 'https://app.yourdomain.com'])
verify_cors_configuration('your-bucket-name')
```

---

### 13. Remediate Public Objects

**Issue**: Public access to individual objects
**Severity**: HIGH
**Compliance**: Data protection across all frameworks

#### AWS Console
1. Navigate to **S3 Console** → **Buckets**
2. Select your bucket → **Objects** tab
3. Select public objects (identified by scanner)
4. Click **Actions** → **Make private**
5. Confirm the action

#### AWS CLI
```bash
# List objects with public ACLs (requires script)
aws s3api list-objects-v2 --bucket BUCKET_NAME --query 'Contents[].Key' --output text | \
while read -r key; do
  aws s3api get-object-acl --bucket BUCKET_NAME --key "$key" --query 'Grants[?Grantee.URI==`http://acs.amazonaws.com/groups/global/AllUsers`]' --output text
  if [ $? -eq 0 ]; then
    echo "Public object found: $key"
  fi
done

# Make specific object private
aws s3api put-object-acl --bucket BUCKET_NAME --key OBJECT_KEY --acl private

# Bulk make all objects private (use with caution)
aws s3 cp s3://BUCKET_NAME/ s3://BUCKET_NAME/ --recursive --acl private

# Remove public access from all objects using sync
aws s3 sync s3://BUCKET_NAME/ s3://BUCKET_NAME/ --acl private
```

#### Python boto3
```python
import boto3

def find_public_objects(bucket_name):
    s3_client = boto3.client('s3')
    public_objects = []
    
    try:
        # List all objects
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=bucket_name)
        
        for page in pages:
            if 'Contents' in page:
                for obj in page['Contents']:
                    key = obj['Key']
                    
                    # Check object ACL
                    try:
                        acl = s3_client.get_object_acl(Bucket=bucket_name, Key=key)
                        for grant in acl['Grants']:
                            if grant['Grantee'].get('URI') == 'http://acs.amazonaws.com/groups/global/AllUsers':
                                public_objects.append(key)
                                break
                    except Exception as e:
                        print(f"Error checking ACL for {key}: {e}")

        return public_objects
    except Exception as e:
        print(f"Error finding public objects: {e}")
        return []

def make_objects_private(bucket_name, object_keys=None):
    s3_client = boto3.client('s3')
    
    if object_keys is None:
        # Find all public objects
        object_keys = find_public_objects(bucket_name)
    
    if not object_keys:
        print(f"No public objects found in {bucket_name}")
        return
    
    success_count = 0
    for key in object_keys:
        try:
            s3_client.put_object_acl(
                Bucket=bucket_name,
                Key=key,
                ACL='private'
            )
            print(f"Made private: {key}")
            success_count += 1
        except Exception as e:
            print(f"Error making {key} private: {e}")

    print(f"Successfully made {success_count}/{len(object_keys)} objects private")

def scan_for_sensitive_objects(bucket_name):
    """Scan for objects with sensitive patterns in filenames"""
    s3_client = boto3.client('s3')
    
    sensitive_patterns = [
        'password', 'passwd', 'pwd', 'secret', 'credential',
        'key', 'token', 'ssn', 'social', 'credit', 'card',
        '.pem', '.key', '.pfx', '.p12', '.ppk',
        '.sql', '.dump', '.bak', '.backup'
    ]
    
    sensitive_objects = []
    
    try:
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=bucket_name)
        
        for page in pages:
            if 'Contents' in page:
                for obj in page['Contents']:
                    key = obj['Key'].lower()
                    for pattern in sensitive_patterns:
                        if pattern in key:
                            sensitive_objects.append(obj['Key'])
                            break
        
        return sensitive_objects
    except Exception as e:
        print(f"Error scanning for sensitive objects: {e}")
        return []

# Usage
public_objects = find_public_objects('your-bucket-name')
print(f"Found {len(public_objects)} public objects")

make_objects_private('your-bucket-name')

sensitive_objects = scan_for_sensitive_objects('your-bucket-name')
print(f"Found {len(sensitive_objects)} potentially sensitive objects")
```

---

## DNS Security

### 14. Fix DNS Takeover Vulnerabilities

**Issue**: Subdomain takeover risks
**Severity**: CRITICAL
**Compliance**: Domain security

#### AWS Console
1. Navigate to **Route 53 Console** → **Hosted zones**
2. Select your domain's hosted zone
3. Review DNS records pointing to S3:
   - **CNAME** records
   - **A** records with S3 endpoints
4. For each S3-pointing record:
   - Verify the target bucket exists
   - Ensure you own the bucket
   - Remove or update orphaned records

#### AWS CLI
```bash
# List all hosted zones
aws route53 list-hosted-zones

# List records in a hosted zone
aws route53 list-resource-record-sets --hosted-zone-id Z1234567890ABC

# Check if bucket exists
aws s3 ls s3://suspected-bucket-name

# Delete orphaned DNS record
aws route53 change-resource-record-sets \
  --hosted-zone-id Z1234567890ABC \
  --change-batch '{
    "Changes": [{
      "Action": "DELETE",
      "ResourceRecordSet": {
        "Name": "subdomain.yourdomain.com",
        "Type": "CNAME",
        "TTL": 300,
        "ResourceRecords": [{
          "Value": "orphaned-bucket.s3-website-us-east-1.amazonaws.com"
        }]
      }
    }]
  }'

# Create bucket to claim orphaned subdomain (if needed)
aws s3 mb s3://orphaned-bucket-name
```

#### Python boto3
```python
import boto3
import re

def scan_dns_takeover_risks():
    route53_client = boto3.client('route53')
    s3_client = boto3.client('s3')
    
    risks = []
    
    try:
        # List all hosted zones
        zones = route53_client.list_hosted_zones()['HostedZones']
        
        for zone in zones:
            zone_id = zone['Id']
            zone_name = zone['Name']
            
            # Get all records in the zone
            records = route53_client.list_resource_record_sets(HostedZoneId=zone_id)
            
            for record_set in records['ResourceRecordSets']:
                if record_set['Type'] in ['CNAME', 'A']:
                    for record in record_set.get('ResourceRecords', []):
                        value = record['Value']
                        
                        # Check if record points to S3
                        if 's3-website' in value or 's3.amazonaws.com' in value:
                            # Extract bucket name
                            bucket_name = extract_bucket_name(value)
                            
                            if bucket_name:
                                # Check if bucket exists
                                try:
                                    s3_client.head_bucket(Bucket=bucket_name)
                                    print(f"Safe: {record_set['Name']} -> {bucket_name}")
                                except:
                                    risks.append({
                                        'subdomain': record_set['Name'],
                                        'bucket_name': bucket_name,
                                        'dns_value': value,
                                        'zone_id': zone_id
                                    })
                                    print(f"Risk: {record_set['Name']} -> {bucket_name} (bucket not found)")

        return risks
    except Exception as e:
        print(f"Error scanning DNS takeover risks: {e}")
        return []

def extract_bucket_name(dns_value):
    """Extract bucket name from S3 DNS value"""
    patterns = [
        r'([^.]+)\.s3-website-[^.]+\.amazonaws\.com',
        r'([^.]+)\.s3\.amazonaws\.com',
        r'([^.]+)\.s3-[^.]+\.amazonaws\.com'
    ]
    
    for pattern in patterns:
        match = re.match(pattern, dns_value)
        if match:
            return match.group(1)
    return None

def fix_dns_takeover(zone_id, record_name, old_value, new_value=None):
    """Fix DNS takeover by updating or deleting record"""
    route53_client = boto3.client('route53')
    
    if new_value:
        # Update record
        change_action = 'UPSERT'
        new_record = {
            'Name': record_name,
            'Type': 'CNAME',
            'TTL': 300,
            'ResourceRecords': [{'Value': new_value}]
        }
    else:
        # Delete record
        change_action = 'DELETE'
        new_record = {
            'Name': record_name,
            'Type': 'CNAME',
            'TTL': 300,
            'ResourceRecords': [{'Value': old_value}]
        }
    
    try:
        response = route53_client.change_resource_record_sets(
            HostedZoneId=zone_id,
            ChangeBatch={
                'Changes': [{
                    'Action': change_action,
                    'ResourceRecordSet': new_record
                }]
            }
        )
        print(f"DNS record {change_action.lower()}d: {record_name}")
        return response
    except Exception as e:
        print(f"Error fixing DNS record: {e}")
        return None

def secure_abandoned_bucket(bucket_name):
    """Create and secure an abandoned bucket to prevent takeover"""
    s3_client = boto3.client('s3')
    
    try:
        # Create bucket
        s3_client.create_bucket(Bucket=bucket_name)
        
        # Enable public access block
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        # Create placeholder content
        s3_client.put_object(
            Bucket=bucket_name,
            Key='index.html',
            Body=b'<html><body><h1>This domain is secured</h1></body></html>',
            ContentType='text/html'
        )
        
        print(f"Secured abandoned bucket: {bucket_name}")
        return True
    except Exception as e:
        print(f"Error securing abandoned bucket: {e}")
        return False

# Usage
risks = scan_dns_takeover_risks()
print(f"Found {len(risks)} DNS takeover risks")

for risk in risks:
    print(f"Risk: {risk['subdomain']} -> {risk['bucket_name']}")
    
    # Option 1: Secure the bucket
    secure_abandoned_bucket(risk['bucket_name'])
    
    # Option 2: Remove the DNS record
    # fix_dns_takeover(risk['zone_id'], risk['subdomain'], risk['dns_value'])
```

---

## Compliance-Specific Configurations

### 15. GDPR Data Residency Compliance

**Issue**: Bucket location not compliant with GDPR data residency requirements
**Severity**: HIGH
**Compliance**: GDPR Articles 44-49

#### AWS Console
1. **Note**: Bucket region cannot be changed after creation
2. Navigate to **S3 Console** → **Buckets**
3. Check bucket region in the bucket list
4. For non-EU buckets containing personal data:
   - Create new bucket in EU region
   - Migrate data to EU region
   - Update applications to use new bucket

#### AWS CLI
```bash
# Check bucket location
aws s3api get-bucket-location --bucket BUCKET_NAME

# Create new bucket in EU region for GDPR compliance
aws s3api create-bucket \
  --bucket your-eu-bucket-name \
  --region eu-west-1 \
  --create-bucket-configuration LocationConstraint=eu-west-1

# Migrate data to EU bucket
aws s3 sync s3://old-bucket s3://your-eu-bucket-name

# Enable all security features on new bucket
aws s3api put-public-access-block \
  --bucket your-eu-bucket-name \
  --public-access-block-configuration \
  "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

aws s3api put-bucket-encryption \
  --bucket your-eu-bucket-name \
  --server-side-encryption-configuration '{
    "Rules": [{
      "ApplyServerSideEncryptionByDefault": {
        "SSEAlgorithm": "AES256"
      }
    }]
  }'
```

#### Python boto3
```python
import boto3

def check_gdpr_compliance(bucket_name):
    s3_client = boto3.client('s3')
    
    try:
        # Get bucket location
        response = s3_client.get_bucket_location(Bucket=bucket_name)
        location = response.get('LocationConstraint')
        
        # US buckets return None for location
        if location is None:
            location = 'us-east-1'
        
        # GDPR compliant regions (EU/EEA)
        gdpr_regions = [
            'eu-west-1', 'eu-west-2', 'eu-west-3',
            'eu-central-1', 'eu-north-1', 'eu-south-1'
        ]
        
        is_compliant = location in gdpr_regions
        
        print(f"Bucket: {bucket_name}")
        print(f"Location: {location}")
        print(f"GDPR Compliant: {'Yes' if is_compliant else 'No'}")

        return is_compliant, location
    except Exception as e:
        print(f"Error checking GDPR compliance: {e}")
        return False, None

def create_gdpr_compliant_bucket(bucket_name, region='eu-west-1'):
    s3_client = boto3.client('s3', region_name=region)
    
    try:
        # Create bucket in EU region
        if region == 'us-east-1':
            response = s3_client.create_bucket(Bucket=bucket_name)
        else:
            response = s3_client.create_bucket(
                Bucket=bucket_name,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        
        print(f"Created GDPR compliant bucket: {bucket_name} in {region}")

        # Apply security configurations
        apply_gdpr_security_configuration(bucket_name, region)

        return response
    except Exception as e:
        print(f"Error creating GDPR compliant bucket: {e}")
        return None

def apply_gdpr_security_configuration(bucket_name, region):
    s3_client = boto3.client('s3', region_name=region)
    
    try:
        # 1. Enable public access block
        s3_client.put_public_access_block(
            Bucket=bucket_name,
            PublicAccessBlockConfiguration={
                'BlockPublicAcls': True,
                'IgnorePublicAcls': True,
                'BlockPublicPolicy': True,
                'RestrictPublicBuckets': True
            }
        )
        
        # 2. Enable encryption
        s3_client.put_bucket_encryption(
            Bucket=bucket_name,
            ServerSideEncryptionConfiguration={
                'Rules': [{
                    'ApplyServerSideEncryptionByDefault': {
                        'SSEAlgorithm': 'AES256'
                    }
                }]
            }
        )
        
        # 3. Enable versioning
        s3_client.put_bucket_versioning(
            Bucket=bucket_name,
            VersioningConfiguration={'Status': 'Enabled'}
        )
        
        # 4. Enable logging
        log_bucket = f"{bucket_name}-logs"
        try:
            s3_client.create_bucket(
                Bucket=log_bucket,
                CreateBucketConfiguration={'LocationConstraint': region}
            )
        except:
            pass  # Bucket might already exist
        
        s3_client.put_bucket_logging(
            Bucket=bucket_name,
            BucketLoggingStatus={
                'LoggingEnabled': {
                    'TargetBucket': log_bucket,
                    'TargetPrefix': 'access-logs/'
                }
            }
        )
        
        # 5. Create GDPR lifecycle policy
        s3_client.put_bucket_lifecycle_configuration(
            Bucket=bucket_name,
            LifecycleConfiguration={
                'Rules': [{
                    'ID': 'GDPRDataMinimization',
                    'Status': 'Enabled',
                    'Filter': {},
                    'Expiration': {'Days': 2555}  # 7 years
                }]
            }
        )
        
        print(f"Applied GDPR security configuration to {bucket_name}")

    except Exception as e:
        print(f"Error applying GDPR security configuration: {e}")

def migrate_to_gdpr_compliant_region(old_bucket, new_bucket, region='eu-west-1'):
    """Migrate data from non-compliant bucket to GDPR compliant bucket"""
    s3_client = boto3.client('s3')
    
    try:
        # Create new compliant bucket
        create_gdpr_compliant_bucket(new_bucket, region)
        
        # List and copy all objects
        paginator = s3_client.get_paginator('list_objects_v2')
        pages = paginator.paginate(Bucket=old_bucket)
        
        object_count = 0
        for page in pages:
            if 'Contents' in page:
                for obj in page['Contents']:
                    copy_source = {'Bucket': old_bucket, 'Key': obj['Key']}
                    s3_client.copy_object(
                        CopySource=copy_source,
                        Bucket=new_bucket,
                        Key=obj['Key']
                    )
                    object_count += 1
        
        print(f"Migrated {object_count} objects to GDPR compliant bucket")
        print(f"Please update your applications to use: {new_bucket}")
        print(f"After verification, consider deleting old bucket: {old_bucket}")

    except Exception as e:
        print(f"Error migrating to GDPR compliant bucket: {e}")

# Usage
is_compliant, location = check_gdpr_compliance('your-bucket-name')
if not is_compliant:
    migrate_to_gdpr_compliant_region('your-bucket-name', 'your-bucket-name-eu')
```

---

## Quick Reference Commands

### Bulk Security Hardening Script

```bash
#!/bin/bash
# bulk-s3-security-hardening.sh

BUCKET_NAME=$1
if [ -z "$BUCKET_NAME" ]; then
    echo "Usage: $0 BUCKET_NAME"
    exit 1
fi

echo "Applying security hardening to bucket: $BUCKET_NAME"

# 1. Enable public access block
echo "1. Enabling public access block..."
aws s3api put-public-access-block \
    --bucket "$BUCKET_NAME" \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# 2. Set bucket ACL to private
echo "2. Setting bucket ACL to private..."
aws s3api put-bucket-acl --bucket "$BUCKET_NAME" --acl private

# 3. Enable encryption
echo "3. Enabling server-side encryption..."
aws s3api put-bucket-encryption \
    --bucket "$BUCKET_NAME" \
    --server-side-encryption-configuration '{
        "Rules": [{
            "ApplyServerSideEncryptionByDefault": {
                "SSEAlgorithm": "AES256"
            }
        }]
    }'

# 4. Enable versioning
echo "4. Enabling versioning..."
aws s3api put-bucket-versioning \
    --bucket "$BUCKET_NAME" \
    --versioning-configuration Status=Enabled

# 5. Enable logging
echo "5. Enabling server access logging..."
LOG_BUCKET="${BUCKET_NAME}-logs"
aws s3 mb s3://"$LOG_BUCKET" 2>/dev/null || true
aws s3api put-bucket-logging \
    --bucket "$BUCKET_NAME" \
    --bucket-logging-status '{
        "LoggingEnabled": {
            "TargetBucket": "'$LOG_BUCKET'",
            "TargetPrefix": "access-logs/"
        }
    }'

# 6. Apply SSL enforcement policy
echo "6. Applying SSL enforcement policy..."
cat > /tmp/ssl-policy-${BUCKET_NAME}.json << EOF
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Sid": "DenyInsecureConnections",
            "Effect": "Deny",
            "Principal": "*",
            "Action": "s3:*",
            "Resource": [
                "arn:aws:s3:::${BUCKET_NAME}",
                "arn:aws:s3:::${BUCKET_NAME}/*"
            ],
            "Condition": {
                "Bool": {
                    "aws:SecureTransport": "false"
                }
            }
        }
    ]
}
EOF

aws s3api put-bucket-policy \
    --bucket "$BUCKET_NAME" \
    --policy file:///tmp/ssl-policy-${BUCKET_NAME}.json

rm /tmp/ssl-policy-${BUCKET_NAME}.json

echo "Security hardening completed for $BUCKET_NAME"
echo "Run s3-security-scanner to verify all configurations"
```

### Python Bulk Hardening Function

```python
def apply_comprehensive_security_hardening(bucket_name, region='us-east-1'):
    """Apply comprehensive security hardening to an S3 bucket"""
    s3_client = boto3.client('s3', region_name=region)
    
    hardening_steps = [
        ("Public Access Block", enable_public_access_block),
        ("Private ACL", set_private_acl),
        ("Encryption", lambda bn: enable_bucket_encryption(bn, 'SSE-S3')),
        ("Versioning", enable_versioning),
        ("Access Logging", lambda bn: enable_access_logging(bn, f"{bn}-logs")),
        ("SSL Enforcement", enforce_ssl_policy),
        ("Secure CORS", configure_secure_cors),
        ("Lifecycle Rules", create_lifecycle_rule),
        ("Event Notifications", lambda bn: configure_event_notifications(bn, create_sns_topic_for_s3()))
    ]
    
    success_count = 0
    for step_name, step_function in hardening_steps:
        try:
            print(f"Applying {step_name}...")
            step_function(bucket_name)
            success_count += 1
            print(f"{step_name} applied successfully")
        except Exception as e:
            print(f"Failed to apply {step_name}: {e}")

    print(f"\nSecurity hardening completed: {success_count}/{len(hardening_steps)} steps successful")
    return success_count == len(hardening_steps)

# Usage
apply_comprehensive_security_hardening('your-bucket-name')
```

---

## Additional Notes

### AWS IAM Permissions Required

To execute these remediation steps, ensure your AWS credentials have the following permissions:

```json
{
    "Version": "2012-10-17",
    "Statement": [
        {
            "Effect": "Allow",
            "Action": [
                "s3:*",
                "kms:*",
                "sns:*",
                "route53:*",
                "iam:GetRole",
                "iam:PassRole"
            ],
            "Resource": "*"
        }
    ]
}
```

### Validation Commands

After applying remediations, verify with:

```bash
# Run the S3 Security Scanner
s3-security-scanner --bucket your-bucket-name --compliance-only

# Check specific configurations
aws s3api get-public-access-block --bucket your-bucket-name
aws s3api get-bucket-encryption --bucket your-bucket-name
aws s3api get-bucket-versioning --bucket your-bucket-name
aws s3api get-bucket-logging --bucket your-bucket-name
```

### Emergency Response

For immediate security incident response:

```bash
# Emergency lockdown - block all public access
aws s3api put-public-access-block \
    --bucket BUCKET_NAME \
    --public-access-block-configuration \
    "BlockPublicAcls=true,IgnorePublicAcls=true,BlockPublicPolicy=true,RestrictPublicBuckets=true"

# Remove all bucket policies
aws s3api delete-bucket-policy --bucket BUCKET_NAME

# Set all objects to private
aws s3 sync s3://BUCKET_NAME/ s3://BUCKET_NAME/ --acl private
```

This comprehensive remediation guide provides solutions for all security vulnerabilities detected by the S3 Security Scanner. Each remediation includes multiple implementation methods to accommodate different operational preferences and automation requirements.
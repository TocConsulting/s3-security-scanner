"""Pattern analysis for S3 bucket naming and security analysis."""

import re
from typing import Dict, List, Any


class PatternAnalyzer:
    """Analyzes patterns in S3 bucket names for security insights."""

    def extract_bucket_naming_patterns(
        self, bucket_name: str
    ) -> Dict[str, Any]:
        """Extract and analyze bucket naming patterns for sensitive info.

        Args:
            bucket_name: S3 bucket name to analyze

        Returns:
            Dictionary containing identified patterns and components
        """
        patterns = {
            "components": [],
            "separators": [],
            "environments": [],
            "business_indicators": [],
            "version_indicators": [],
            "has_org_prefix": False,
            "has_predictable_structure": False,
            "sensitive_keywords": [],
        }

        # Common separators
        separators = ["-", "_", "."]
        used_separators = [sep for sep in separators if sep in bucket_name]
        patterns["separators"] = used_separators

        # Split bucket name into components
        components = re.split(r"[-_.]", bucket_name.lower())
        patterns["components"] = components

        # Environment indicators
        env_keywords = [
            "prod",
            "production",
            "dev",
            "development",
            "staging",
            "stage",
            "test",
            "testing",
            "qa",
            "demo",
            "sandbox",
        ]
        found_envs = [comp for comp in components if comp in env_keywords]
        patterns["environments"] = found_envs

        # Business/functional indicators
        business_keywords = [
            "api",
            "web",
            "app",
            "data",
            "backup",
            "logs",
            "assets",
            "media",
            "docs",
            "documentation",
            "config",
            "secrets",
            "keys",
            "database",
            "db",
            "analytics",
            "reports",
            "exports",
            "imports",
            "uploads",
            "downloads",
        ]
        found_business = [
            comp for comp in components if comp in business_keywords
        ]
        patterns["business_indicators"] = found_business

        # Version indicators
        version_pattern = re.compile(r"v\d+|version\d+|\d+\.\d+")
        found_versions = [
            comp for comp in components if version_pattern.match(comp)
        ]
        patterns["version_indicators"] = found_versions

        # Organization prefix detection (first component might be org name)
        if len(components) > 1:
            patterns["has_org_prefix"] = True

        # Predictable structure (org-env-function-version pattern)
        if len(components) >= 3 and found_envs and found_business:
            patterns["has_predictable_structure"] = True

        # Sensitive keywords
        sensitive_keywords = [
            "secret",
            "key",
            "password",
            "auth",
            "credential",
            "token",
            "private",
            "internal",
            "confidential",
            "admin",
            "root",
            "user",
            "customer",
            "client",
            "personal",
            "pii",
            "sensitive",
        ]
        found_sensitive = [
            comp for comp in components if comp in sensitive_keywords
        ]
        patterns["sensitive_keywords"] = found_sensitive

        return patterns

    def assess_information_disclosure_risk(
        self, bucket_name: str, patterns: Dict[str, Any]
    ) -> Dict[str, Any]:
        """Assess the information disclosure risk level based on bucket naming patterns.

        Args:
            bucket_name: S3 bucket name
            patterns: Extracted naming patterns

        Returns:
            Risk assessment with severity level and recommendations
        """
        risk_factors = []
        severity = "LOW"
        risk_level = "MINOR"

        # Check for environment disclosure
        if patterns["environments"]:
            risk_factors.append(
                f"Reveals environment: {', '.join(patterns['environments'])}"
            )

        # Check for business logic disclosure
        if patterns["business_indicators"]:
            risk_factors.append(
                f"Reveals business function: {', '.join(patterns['business_indicators'])}"
            )

        # Check for sensitive keywords
        if patterns["sensitive_keywords"]:
            risk_factors.append(
                f"Contains sensitive keywords: {', '.join(patterns['sensitive_keywords'])}"
            )
            severity = "HIGH"
            risk_level = "CRITICAL"

        # Check for predictable structure
        if patterns["has_predictable_structure"]:
            risk_factors.append(
                "Follows predictable naming pattern that enables enumeration"
            )
            if severity == "LOW":
                severity = "MEDIUM"
                risk_level = "MODERATE"

        # Check for organization prefix
        if patterns["has_org_prefix"]:
            risk_factors.append("Reveals organizational structure")

        # Check for version information
        if patterns["version_indicators"]:
            risk_factors.append(
                f"Reveals versioning: {', '.join(patterns['version_indicators'])}"
            )

        # Determine overall risk level
        if len(risk_factors) == 0:
            risk_level = "NONE"
            severity = "INFO"
        elif len(risk_factors) >= 3 and patterns["has_predictable_structure"]:
            risk_level = "CRITICAL"
            severity = "HIGH"
        elif len(risk_factors) >= 2:
            risk_level = "MODERATE"
            severity = "MEDIUM"
        else:
            risk_level = "MINOR"
            severity = "LOW"

        # Generate recommendation
        if risk_level == "CRITICAL":
            recommendation = "Immediately review bucket naming strategy - use non-descriptive names or implement DNS aliasing"
        elif risk_level == "MODERATE":
            recommendation = "Consider using less descriptive bucket names to reduce information disclosure"
        elif risk_level == "MINOR":
            recommendation = "Minor information disclosure - consider generic bucket naming for security"
        else:
            recommendation = "No significant information disclosure detected"

        return {
            "risk_level": risk_level,
            "severity": severity,
            "disclosed_info": risk_factors,
            "recommendation": recommendation,
            "risk_score": len(risk_factors) * 10
            + (50 if patterns["has_predictable_structure"] else 0),
        }

    def check_bucket_enumeration_risk(
        self, bucket_name: str, patterns: Dict[str, Any]
    ) -> List[str]:
        """Generate potential bucket names based on discovered patterns for enumeration risk assessment.

        Args:
            bucket_name: Original bucket name
            patterns: Extracted naming patterns

        Returns:
            List of potential bucket names that could be enumerated
        """
        potential_buckets = []

        if not patterns["has_predictable_structure"]:
            return potential_buckets

        components = patterns["components"]

        # Environment-based enumeration
        if patterns["environments"]:
            env_alternatives = ["prod", "dev", "staging", "test", "qa", "demo"]
            for env in env_alternatives:
                if env not in patterns["environments"]:
                    # Replace environment component
                    for i, comp in enumerate(components):
                        if comp in patterns["environments"]:
                            new_components = components.copy()
                            new_components[i] = env
                            potential_bucket = "-".join(new_components)
                            potential_buckets.append(potential_bucket)

        # Business function enumeration
        if patterns["business_indicators"]:
            business_alternatives = [
                "api",
                "web",
                "app",
                "data",
                "backup",
                "logs",
                "assets",
                "config",
                "secrets",
                "db",
                "analytics",
            ]
            for business in business_alternatives:
                if business not in patterns["business_indicators"]:
                    # Replace business component
                    for i, comp in enumerate(components):
                        if comp in patterns["business_indicators"]:
                            new_components = components.copy()
                            new_components[i] = business
                            potential_bucket = "-".join(new_components)
                            potential_buckets.append(potential_bucket)

        # Version enumeration
        if patterns["version_indicators"]:
            version_alternatives = ["v1", "v2", "v3", "v4", "v5"]
            for version in version_alternatives:
                if version not in patterns["version_indicators"]:
                    # Replace version component
                    for i, comp in enumerate(components):
                        if comp in patterns["version_indicators"]:
                            new_components = components.copy()
                            new_components[i] = version
                            potential_bucket = "-".join(new_components)
                            potential_buckets.append(potential_bucket)

        # Limit to top 10 most likely candidates
        return potential_buckets[:10]

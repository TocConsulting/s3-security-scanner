"""HTML report generator for S3 Security Scanner."""

import os
from datetime import datetime
from typing import Dict, List, Any
from jinja2 import Environment, FileSystemLoader, select_autoescape

from .utils import format_bytes, get_severity_color


class HTMLReporter:
    """Generate beautiful HTML reports for S3 security scan results."""

    def __init__(self, template_dir: str = None):
        """Initialize HTML reporter with template directory."""
        if template_dir is None:
            template_dir = os.path.join(os.path.dirname(__file__), "templates")

        self.env = Environment(
            loader=FileSystemLoader(template_dir),
            autoescape=select_autoescape(["html", "xml"]),
        )

        # Add custom filters and functions
        self.env.filters["format_bytes"] = format_bytes
        self.env.filters["format_datetime"] = self._format_datetime
        self.env.filters["get_severity_color"] = get_severity_color
        self.env.globals["zip"] = zip

    def _format_datetime(self, dt) -> str:
        """Format datetime for display."""
        if isinstance(dt, str):
            try:
                dt = datetime.fromisoformat(dt.replace("Z", "+00:00"))
            except ValueError:
                return dt

        if isinstance(dt, datetime):
            return dt.strftime("%Y-%m-%d %H:%M:%S UTC")

        return str(dt)

    def _calculate_chart_data(
        self, results: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Calculate data for charts and visualizations."""
        # Filter out error results for chart calculations
        valid_results = [r for r in results if not r.get("scan_error", False)]

        if not valid_results:
            return {
                "security_score_distribution": [0, 0, 0, 0, 0],
                "compliance_labels": [],
                "compliance_percentages": [],
                "severity_counts": [0, 0, 0, 0],
                "feature_adoption": [0, 0, 0, 0, 0],
            }

        # Security score distribution
        score_ranges = [0, 0, 0, 0, 0]  # 0-20, 21-40, 41-60, 61-80, 81-100
        for result in valid_results:
            score = result.get("security_score", 0)
            if score <= 20:
                score_ranges[0] += 1
            elif score <= 40:
                score_ranges[1] += 1
            elif score <= 60:
                score_ranges[2] += 1
            elif score <= 80:
                score_ranges[3] += 1
            else:
                score_ranges[4] += 1

        # Compliance data
        compliance_data = {
            "CIS": [],
            "AWS-FSBP": [],
            "PCI-DSS": [],
            "HIPAA": [],
            "SOC2": [],
            "ISO27001": [],
            "ISO27017": [],
            "ISO27018": [],
            "GDPR": [],
        }
        for result in valid_results:
            compliance_status = result.get("compliance_status", {})
            for framework in compliance_data.keys():
                if framework in compliance_status:
                    percentage = compliance_status[framework].get(
                        "compliance_percentage", 0
                    )
                    compliance_data[framework].append(percentage)

        compliance_labels = []
        compliance_percentages = []
        for framework, percentages in compliance_data.items():
            if percentages:
                compliance_labels.append(framework)
                avg_percentage = sum(percentages) / len(percentages)
                compliance_percentages.append(round(avg_percentage, 1))

        # Severity counts
        severity_counts = {"HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for result in valid_results:
            for issue in result.get("issues", []):
                severity = issue.get("severity", "INFO")
                if severity in severity_counts:
                    severity_counts[severity] += 1

        # Feature adoption
        total_buckets = len(valid_results)
        if total_buckets == 0:
            feature_adoption = [0, 0, 0, 0, 0]
        else:
            encryption_enabled = sum(
                1
                for r in valid_results
                if r.get("encryption", {}).get("is_enabled", False)
            )
            versioning_enabled = sum(
                1
                for r in valid_results
                if r.get("versioning", {}).get("is_enabled", False)
            )
            logging_enabled = sum(
                1
                for r in valid_results
                if r.get("logging", {}).get("is_enabled", False)
            )
            public_access_block = sum(
                1
                for r in valid_results
                if r.get("public_access_block", {}).get(
                    "is_properly_configured", False
                )
            )
            mfa_delete_enabled = sum(
                1
                for r in valid_results
                if r.get("versioning", {}).get("mfa_delete_enabled", False)
            )

            feature_adoption = [
                round(encryption_enabled / total_buckets * 100, 1),
                round(versioning_enabled / total_buckets * 100, 1),
                round(logging_enabled / total_buckets * 100, 1),
                round(public_access_block / total_buckets * 100, 1),
                round(mfa_delete_enabled / total_buckets * 100, 1),
            ]

        return {
            "security_score_distribution": score_ranges,
            "compliance_labels": compliance_labels,
            "compliance_percentages": compliance_percentages,
            "severity_counts": [
                severity_counts["HIGH"],
                severity_counts["MEDIUM"],
                severity_counts["LOW"],
                severity_counts["INFO"],
            ],
            "feature_adoption": feature_adoption,
        }

    def _calculate_compliance_summary(
        self, results: List[Dict[str, Any]]
    ) -> Dict[str, Dict[str, Any]]:
        """Calculate compliance summary statistics."""
        if not results:
            return {}

        frameworks = [
            "CIS",
            "AWS-FSBP",
            "PCI-DSS",
            "HIPAA",
            "SOC2",
            "ISO27001",
            "ISO27017",
            "ISO27018",
            "GDPR",
        ]
        compliance_summary = {}

        for framework in frameworks:
            compliant_count = 0
            total_count = 0
            compliance_percentages = []

            for result in results:
                compliance_status = result.get("compliance_status", {})
                if framework in compliance_status:
                    total_count += 1
                    if compliance_status[framework].get("is_compliant", False):
                        compliant_count += 1
                    # Collect individual bucket compliance percentages
                    compliance_percentages.append(
                        compliance_status[framework].get(
                            "compliance_percentage", 0
                        )
                    )

            if total_count > 0:
                # Calculate average compliance percentage across all buckets
                avg_compliance = (
                    sum(compliance_percentages) / len(compliance_percentages)
                    if compliance_percentages
                    else 0
                )

                compliance_summary[framework] = {
                    "compliant_buckets": compliant_count,
                    "total_buckets": total_count,
                    "non_compliant_buckets": total_count - compliant_count,
                    "compliance_percentage": round(
                        compliant_count / total_count * 100, 1
                    ),
                    "average_compliance_percentage": round(avg_compliance, 1),
                }

        return compliance_summary

    def _enhance_results_for_display(
        self, results: List[Dict[str, Any]]
    ) -> List[Dict[str, Any]]:
        """Enhance results with additional display-friendly data."""
        enhanced_results = []

        for result in results:
            # Skip error results for HTML display
            if result.get("scan_error", False):
                continue
            enhanced_result = result.copy()

            # Ensure all required fields exist with defaults
            # Don't override None security_score for error results
            if enhanced_result.get("security_score") is None:
                enhanced_result["security_score"] = "Error"
            else:
                enhanced_result.setdefault("security_score", 0)
            enhanced_result.setdefault("is_public", False)
            enhanced_result.setdefault("issues", [])
            enhanced_result.setdefault("has_high_severity", False)
            enhanced_result.setdefault("has_medium_severity", False)
            enhanced_result.setdefault("compliance_status", {})

            # Ensure nested objects exist
            enhanced_result.setdefault("encryption", {"is_enabled": False})
            enhanced_result.setdefault(
                "versioning",
                {"is_enabled": False, "mfa_delete_enabled": False},
            )
            enhanced_result.setdefault("logging", {"is_enabled": False})
            enhanced_result.setdefault(
                "public_access_block", {"is_properly_configured": False}
            )
            enhanced_result.setdefault(
                "object_level_security",
                {
                    "public_object_count": 0,
                    "sensitive_object_count": 0,
                    "total_objects_scanned": 0,
                },
            )

            # Format creation date
            if (
                "creation_date" in enhanced_result
                and enhanced_result["creation_date"]
            ):
                creation_date = enhanced_result["creation_date"]
                if isinstance(creation_date, str):
                    try:
                        enhanced_result["creation_date"] = (
                            datetime.fromisoformat(
                                creation_date.replace("Z", "+00:00")
                            )
                        )
                    except ValueError:
                        enhanced_result["creation_date"] = None

            enhanced_results.append(enhanced_result)

        return enhanced_results

    def generate_report(
        self,
        results: List[Dict[str, Any]],
        summary: Dict[str, Any],
        output_file: str,
    ) -> str:
        """Generate HTML report from scan results."""

        # Load template
        template = self.env.get_template("report.html")

        # Enhance results for display
        enhanced_results = self._enhance_results_for_display(results)

        # Calculate chart data
        chart_data = self._calculate_chart_data(enhanced_results)

        # Calculate compliance summary
        compliance_summary = self._calculate_compliance_summary(
            enhanced_results
        )

        # Enhance summary with additional stats
        enhanced_summary = summary.copy()
        enhanced_summary.setdefault("total_objects_scanned", 0)
        enhanced_summary.setdefault("total_sensitive_objects", 0)
        enhanced_summary.setdefault("total_public_objects", 0)

        # Calculate object-level statistics
        total_objects_scanned = sum(
            r.get("object_level_security", {}).get("total_objects_scanned", 0)
            for r in enhanced_results
        )
        total_sensitive_objects = sum(
            r.get("object_level_security", {}).get("sensitive_object_count", 0)
            for r in enhanced_results
        )
        total_public_objects = sum(
            r.get("object_level_security", {}).get("public_object_count", 0)
            for r in enhanced_results
        )

        enhanced_summary.update(
            {
                "total_objects_scanned": total_objects_scanned,
                "total_sensitive_objects": total_sensitive_objects,
                "total_public_objects": total_public_objects,
            }
        )

        # Format scan time
        if "scan_time" in enhanced_summary:
            scan_time = enhanced_summary["scan_time"]
            if isinstance(scan_time, str):
                try:
                    enhanced_summary["scan_time"] = datetime.fromisoformat(
                        scan_time.replace("Z", "+00:00")
                    ).strftime("%Y-%m-%d %H:%M:%S UTC")
                except ValueError:
                    pass

        # Render template
        html_content = template.render(
            summary=enhanced_summary,
            results=enhanced_results,
            compliance_summary=compliance_summary,
            **chart_data,
        )

        # Write to file
        with open(output_file, "w", encoding="utf-8") as f:
            f.write(html_content)

        return output_file

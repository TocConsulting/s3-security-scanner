FROM python:3.11-slim

LABEL maintainer="Toc Consulting <tarek@tocconsulting.fr>"
LABEL description="AWS S3 security scanner with compliance mapping for CIS, PCI-DSS, HIPAA, SOC 2, ISO, and GDPR"
LABEL version="1.0.1"

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONUNBUFFERED=1

# Set working directory
WORKDIR /app

# Install system dependencies (needed for some Python packages)
RUN apt-get update && apt-get install -y --no-install-recommends \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy project files
COPY pyproject.toml README.md LICENSE ./
COPY s3_security_scanner/ ./s3_security_scanner/

# Install the package
RUN pip install --no-cache-dir .

# Create output directory
RUN mkdir -p /app/output

# Set default output directory
ENV S3_SCANNER_OUTPUT_DIR=/app/output

# Default entrypoint
ENTRYPOINT ["s3-security-scanner"]

# Default command (show help)
CMD ["--help"]

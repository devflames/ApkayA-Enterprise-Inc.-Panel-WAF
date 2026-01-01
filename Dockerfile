# Apkaya Panel WAF - Docker Image
# Copyright (c) 2025-2026 Albert Camings
# Developed by: Albert Camings (Full Stack Developer)
# License: MIT License - Open Source

FROM python:3.12-slim

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    wget \
    git \
    nginx \
    openssh-client \
    certbot \
    python3-certbot-nginx \
    && rm -rf /var/lib/apt/lists/*

# Copy application
COPY . /app

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Create necessary directories
RUN mkdir -p /app/config /app/data /app/logs /app/backup /app/ssl

# Expose ports
EXPOSE 2323 80 443

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=40s --retries=3 \
    CMD curl -f http://localhost:2323/api/system/health || exit 1

# Set environment variables
ENV FLASK_ENV=production
ENV FLASK_DEBUG=false
ENV PYTHONUNBUFFERED=1

# Default command
CMD ["python", "run.py"]

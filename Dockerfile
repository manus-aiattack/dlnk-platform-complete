FROM python:3.11-slim

# Create non-root user early to avoid running as root
RUN groupadd -r manus && useradd -r -g manus manus

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    libpq-dev \
    postgresql-client \
    git \
    curl \
    wget \
    nmap \
    sqlmap \
    && rm -rf /var/lib/apt/lists/*

# Copy production requirements only
COPY requirements-production.txt requirements.txt

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY --chown=manus:manus . .

# Create necessary directories with proper permissions
RUN mkdir -p /app/workspace/loot/exfiltrated \
    && mkdir -p /app/logs \
    && chown -R manus:manus /app/workspace \
    && chown -R manus:manus /app/logs \
    && chmod -R 644 /app/workspace \
    && chmod -R 644 /app/logs

# Set environment variables
ENV PYTHONUNBUFFERED=1
ENV LOG_LEVEL=INFO

# Switch to non-root user
USER manus

# Expose ports
EXPOSE 8000 3000

# Health check (running as non-root user)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Default command (running as non-root user)
CMD ["python", "api/main.py"]


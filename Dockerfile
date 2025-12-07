FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    postgresql-client \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY tenebrinet/ ./tenebrinet/
COPY config/ ./config/
COPY scripts/ ./scripts/

# Create data directories
RUN mkdir -p data/logs data/models

# Expose ports
# 2222: SSH honeypot
# 8080: HTTP honeypot
# 2121: FTP honeypot
# 8000: API
EXPOSE 2222 8080 2121 8000

# Health check using curl (available in the image)
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:8000/health || exit 1

# Run application
CMD ["python", "-m", "tenebrinet.cli", "--config", "config/honeypot.yml"]

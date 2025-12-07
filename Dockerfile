FROM python:3.11-slim

WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y \
    gcc \
    g++ \
    postgresql-client \
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
EXPOSE 2222 8080 2121 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import requests; requests.get('http://localhost:8000/health')"

# Run application
CMD ["python", "-m", "tenebrinet.core.honeypot", "--config", "config/honeypot.yml"]

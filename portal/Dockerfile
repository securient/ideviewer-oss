# IDE Viewer Portal - Production Container
#
# Build:
#   docker build -t ideviewer-portal .
#
# Run:
#   docker run -p 8080:8080 \
#     -e SECRET_KEY=your-secret-key \
#     -e DATABASE_URL=postgresql://user:pass@host:5432/ideviewer \
#     ideviewer-portal

FROM python:3.10-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    FLASK_APP=run.py \
    FLASK_CONFIG=production \
    PORT=8080

# Create non-root user for security
RUN groupadd -r ideviewer && useradd -r -g ideviewer ideviewer

# Set working directory
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq-dev \
    gcc \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for layer caching
COPY requirements.txt .

# Install Python dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Create instance directory for any local files
RUN mkdir -p instance && chown -R ideviewer:ideviewer /app

# Switch to non-root user
USER ideviewer

# Expose port
EXPOSE 8080

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD python -c "import urllib.request; urllib.request.urlopen('http://localhost:8080/api/health')" || exit 1

# Run with gunicorn
CMD ["gunicorn", "--bind", "0.0.0.0:8080", "--workers", "4", "--threads", "2", "--timeout", "120", "run:app"]

# Stage 1: Builder
FROM python:3.11-slim as builder

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Stage 2: Runtime
FROM python:3.11-slim

# Set timezone to UTC (Critical for TOTP)
ENV TZ=UTC
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && echo $TZ > /etc/timezone

WORKDIR /app

# Install system dependencies (cron)
RUN apt-get update && apt-get install -y cron && rm -rf /var/lib/apt/lists/*

# Copy python dependencies from builder
COPY --from=builder /usr/local/lib/python3.11/site-packages /usr/local/lib/python3.11/site-packages
COPY --from=builder /usr/local/bin /usr/local/bin

# Copy application code
COPY . .

# Setup Cron
# 1. Copy the cron file to the cron.d directory
COPY cron/2fa_cron /etc/cron.d/2fa_cron
# 2. Give execution rights on the cron job
RUN chmod 0644 /etc/cron.d/2fa_cron
# 3. Apply cron job
RUN crontab /etc/cron.d/2fa_cron
# 4. Create directories for volumes
RUN mkdir -p /data /cron && chmod 755 /data /cron

# Expose the port
EXPOSE 8080

# Start Cron AND the API Server
CMD cron && uvicorn main:app --host 0.0.0.0 --port 8080
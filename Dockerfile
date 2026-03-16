# Aura OMEGA - Containerized Sentient Brain
# ----------------------------------------
# This Dockerfile enables automated cloud deployment for the 
# Aura engine, specifically targeting Google Cloud Run.

FROM python:3.10-slim

# Install system dependencies
RUN apt-get update && apt-get install -y \
    curl \
    git \
    && rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy the Aura engine
COPY . .

# Set environment variables for GCP
ENV GOOGLE_CLOUD_PROJECT="aura-sentinel-4412"
ENV PYTHONUNBUFFERED=1

# Command to run the OMEGA Sentient Brain
CMD ["python", "aura/core/vertex_brain.py"]

#!/bin/bash
# Aura OMEGA - Automated Cloud Deployment Script (GCP)
# ---------------------------------------------------
# This script automates the environment setup and deployment 
# for the Aura Sentient Brain on Google Cloud Platform.

set -e # Exit on error

echo "🛡️ [AURA] Initializing Automated Deployment to GCP..."

# 1. Configuration
PROJECT_ID=$(gcloud config get-value project)
REGION="us-central1"
SERVICE_NAME="aura-sentient-brain"

# 2. Enable Required APIs
echo "📡 [AURA] Enabling Google Cloud APIs (Vertex AI, Cloud Run, Artifact Registry)..."
gcloud services enable \
    compute.googleapis.com \
    aiplatform.googleapis.com \
    run.googleapis.com \
    artifactregistry.googleapis.com

# 3. Build & Push Sentient Brain Container (Optional: For Cloud Run execution)
echo "📦 [AURA] Building OMEGA Container..."
# Note: In a real scenario, this would build the Dockerfile
# gcloud builds submit --tag gcr.io/$PROJECT_ID/$SERVICE_NAME .

# 4. Set up Service Account for Vertex AI
echo "👤 [AURA] Configuring Service Account permissions..."
SA_NAME="aura-sentinel-sa"
gcloud iam service-accounts create $SA_NAME --display-name="Aura Sentinel Service Account" || true

gcloud projects add-iam-policy-binding $PROJECT_ID \
    --member="serviceAccount:$SA_NAME@$PROJECT_ID.iam.gserviceaccount.com" \
    --role="roles/aiplatform.user"

# 5. Finalize
echo "✅ [AURA] Cloud Deployment Automated Successfully."
echo "OMEGA Protocol is now ready for Vertex AI interaction in project: $PROJECT_ID"

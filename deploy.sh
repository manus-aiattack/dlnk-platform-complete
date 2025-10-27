#!/bin/bash

# Manus AI Attack Platform - Production Deployment Script
set -e

echo "🚀 Starting Manus AI Attack Platform Production Deployment..."

# Check if required tools are installed
command -v kubectl >/dev/null 2>&1 || { echo "❌ kubectl is not installed. Please install it first."; exit 1; }
command -v docker >/dev/null 2>&1 || { echo "❌ Docker is not installed. Please install it first."; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "❌ curl is not installed. Please install it first."; exit 1; }

# Load environment variables
if [ -f .env.production ]; then
    export $(cat .env.production | grep -v '^#' | xargs)
    echo "✅ Loaded .env.production file"
else
    echo "❌ .env.production file not found!"
    exit 1
fi

# Create namespace
echo "📝 Creating Kubernetes namespace..."
kubectl apply -f k8s/namespace.yaml

# Create service account and cluster role
echo "📝 Creating service account and cluster role..."
kubectl apply -f k8s/service-account.yaml

# Create configmap
echo "📝 Creating ConfigMap..."
kubectl apply -f k8s/configmap.yaml

# Create secrets
echo "📝 Creating Secrets..."
kubectl apply -f k8s/secrets.yaml

# Build Docker image
echo "🔨 Building Docker image..."
docker build -t manus-ai-attack-platform:latest -f Dockerfile.prod .

# Apply deployment
echo "🚀 Applying deployment..."
kubectl apply -f k8s/deployment.yaml

# Wait for deployment to be ready
echo "⏳ Waiting for deployment to be ready..."
kubectl wait --for=condition=available --timeout=300s deployment/manus-ai-attack-platform -n manus-production

# Get service URL
SERVICE_URL=$(kubectl get service manus-service -n manus-production -o jsonpath='{.spec.clusterIP}')
echo "✅ Service is available at: http://${SERVICE_URL}:80"

# Run health check
echo "🏥 Running health check..."
HEALTH_CHECK_URL="http://${SERVICE_URL}:80/health"
for i in {1..10}; do
    if curl -s ${HEALTH_CHECK_URL} > /dev/null; then
        echo "✅ Health check passed!"
        break
    else
        echo "⏳ Waiting for health check (attempt $i/10)..."
        sleep 10
    fi
done

# Display deployment status
echo ""
echo "📊 Deployment Status:"
kubectl get pods -n manus-production
kubectl get services -n manus-production
kubectl get deployments -n manus-production

echo ""
echo "🎉 Manus AI Attack Platform deployed successfully!"
echo "🔗 Access the platform at: http://${SERVICE_URL}:80"
echo "📈 View metrics at: http://${SERVICE_URL}:80/metrics"
echo "💡 Check logs with: kubectl logs -f deployment/manus-ai-attack-platform -n manus-production"

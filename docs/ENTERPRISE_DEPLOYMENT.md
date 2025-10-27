# dLNk dLNk Framework - Enterprise Deployment Guide

## Enterprise & Advanced Capabilities Deployment

This guide covers the deployment of the enhanced dLNk dLNk Framework with distributed architecture, AI/ML capabilities, and commercial-grade features.

---

## Table of Contents

1. [Prerequisites](#prerequisites)
2. [Architecture Overview](#architecture-overview)
3. [Local Development Setup](#local-development-setup)
4. [Docker Deployment](#docker-deployment)
5. [Kubernetes Deployment](#kubernetes-deployment)
6. [AI/ML Model Setup](#aiml-model-setup)
7. [License Management](#license-management)
8. [Configuration](#configuration)
9. [Monitoring and Logging](#monitoring-and-logging)
10. [Troubleshooting](#troubleshooting)

---

## Prerequisites

### Hardware Requirements

**Minimum (Development):**
- CPU: 4 cores
- RAM: 16 GB
- Storage: 100 GB SSD
- GPU: Optional (for AI features)

**Recommended (Production):**
- CPU: 16+ cores
- RAM: 64+ GB
- Storage: 500 GB NVMe SSD
- GPU: NVIDIA GPU with 16GB+ VRAM (for Local LLM)

### Software Requirements

- **Operating System:** Ubuntu 22.04 LTS or later
- **Docker:** 24.0+ with Docker Compose
- **Kubernetes:** 1.27+ (for distributed deployment)
- **Python:** 3.11+
- **NVIDIA Driver:** 535+ (for GPU support)
- **CUDA:** 12.1+ (for GPU support)

---

## Architecture Overview

The enhanced framework consists of the following microservices:

1. **Orchestrator Service** - Coordinates workflow execution
2. **Agent Manager Service** - Manages dynamic agent execution
3. **AI Planner Service** - AI-driven attack planning with Local LLM
4. **Threat Intelligence Service** - Real-time threat data ingestion
5. **License Management Service** - Commercial license validation
6. **Redis Cluster** - Context management and pub/sub
7. **PostgreSQL** - Persistent storage
8. **API Gateway** - Load balancing and routing

---

## Distributed Deployment (Docker Compose)

### Standard Deployment

```bash
# Build images
docker-compose -f docker-compose.distributed.yml build

# Start services
docker-compose -f docker-compose.distributed.yml up -d

# Check status
docker-compose -f docker-compose.distributed.yml ps

# View logs
docker-compose -f docker-compose.distributed.yml logs -f
```

### Scale Services

```bash
# Scale orchestrator
docker-compose -f docker-compose.distributed.yml up -d --scale orchestrator=3

# Scale agent manager
docker-compose -f docker-compose.distributed.yml up -d --scale agent-manager=5
```

---

## Kubernetes Deployment

### 1. Create Namespace

```bash
kubectl create namespace dlnk-dlnk
```

### 2. Deploy Core Services

```bash
# Deploy Redis
kubectl apply -f k8s/redis-deployment.yaml -n dlnk-dlnk

# Deploy PostgreSQL
kubectl apply -f k8s/postgres-deployment.yaml -n dlnk-dlnk

# Deploy Orchestrator
kubectl apply -f k8s/orchestrator-deployment.yaml -n dlnk-dlnk

# Deploy Agent Manager
kubectl apply -f k8s/agent-manager-deployment.yaml -n dlnk-dlnk

# Deploy AI Planner
kubectl apply -f k8s/ai-planner-deployment.yaml -n dlnk-dlnk

# Deploy Threat Intelligence
kubectl apply -f k8s/threat-intel-deployment.yaml -n dlnk-dlnk

# Deploy License Service
kubectl apply -f k8s/license-deployment.yaml -n dlnk-dlnk
```

### 3. Verify Deployment

```bash
# Check pods
kubectl get pods -n dlnk-dlnk

# Check services
kubectl get svc -n dlnk-dlnk
```

---

## AI/ML Model Setup

### Download Local LLM Model

```bash
# Create models directory
mkdir -p /models/llm

# Download Mistral 7B Instruct (Recommended)
huggingface-cli download mistralai/Mistral-7B-Instruct-v0.2 --local-dir /models/llm/mistral-7b-instruct
```

### Configure Model Path

```bash
export LLM_MODEL_PATH=/models/llm/mistral-7b-instruct
```

---

## License Management

### Generate License

```bash
curl -X POST http://localhost:8007/license/generate \
  -H "Content-Type: application/json" \
  -d '{
    "license_type": "enterprise",
    "organization": "Your Organization",
    "duration_days": 365
  }'
```

### Validate License

```bash
curl -X POST http://localhost:8007/license/validate \
  -H "Content-Type: application/json" \
  -d '{
    "license_key": "XXXX-XXXX-XXXX-XXXX",
    "hardware_id": "ABC123"
  }'
```

---

## Configuration

### Environment Variables

```bash
# Redis Configuration
REDIS_HOST=localhost
REDIS_PORT=6379

# PostgreSQL Configuration
POSTGRES_HOST=localhost
POSTGRES_PORT=5432
POSTGRES_DB=dlnk_dlnk
POSTGRES_USER=dlnk_user
POSTGRES_PASSWORD=your_password

# LLM Configuration
LLM_MODEL_PATH=/models/llm/mistral-7b-instruct
LLM_CONTEXT_LENGTH=8192
LLM_TEMPERATURE=0.7

# License Configuration
LICENSE_SECRET_KEY=your_secret_key

# Agent Configuration
MAX_CONCURRENT_AGENTS=100
AGENT_TIMEOUT=3600
```

---

## Monitoring and Logging

### Prometheus Metrics

Access Prometheus: `http://localhost:9090`

### Grafana Dashboards

Access Grafana: `http://localhost:3000`

Default credentials:
- Username: `admin`
- Password: `admin_change_me`

---

## Troubleshooting

### Check Service Health

```bash
curl http://localhost:8001/health  # Orchestrator
curl http://localhost:8002/health  # Agent Manager
curl http://localhost:8003/health  # AI Planner
curl http://localhost:8006/health  # Threat Intel
curl http://localhost:8007/health  # License Service
```

### View Logs

```bash
# Docker
docker-compose -f docker-compose.distributed.yml logs -f

# Kubernetes
kubectl logs -f deployment/dlnk-orchestrator -n dlnk-dlnk
```

---

## Production Deployment Checklist

- [ ] Change all default passwords
- [ ] Generate secure license secret key
- [ ] Configure SSL/TLS certificates
- [ ] Set up firewall rules
- [ ] Configure backup strategy
- [ ] Enable monitoring and alerting
- [ ] Review security settings
- [ ] Test disaster recovery
- [ ] Document configurations
- [ ] Train operators

---

**Last Updated:** 2024-01-20
**Version:** 3.0 Enterprise Edition


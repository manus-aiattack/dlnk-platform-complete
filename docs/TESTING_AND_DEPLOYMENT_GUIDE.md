# Apex Predator Framework - Testing & Deployment Guide

## Prerequisites

### System Requirements

**Minimum**:
- CPU: 4 cores
- RAM: 8 GB
- Storage: 50 GB
- OS: Ubuntu 20.04+ / Debian 11+ / Kali Linux

**Recommended**:
- CPU: 8+ cores
- RAM: 16+ GB
- Storage: 100+ GB SSD
- OS: Ubuntu 22.04 LTS

### Required Services

1. **Redis Server** (v6.0+)
   ```bash
   sudo apt update
   sudo apt install redis-server -y
   sudo systemctl enable redis-server
   sudo systemctl start redis-server
   ```

2. **Python 3.10+**
   ```bash
   python3 --version  # Should be 3.10 or higher
   ```

3. **Virtual Environment**
   ```bash
   python3 -m venv venv
   source venv/bin/activate
   ```

## Installation Steps

### 1. Install Framework Dependencies

```bash
cd /path/to/apex_predator_FINAL

# Install Python dependencies
pip install -r requirements.txt

# Install system tools (optional but recommended)
sudo apt install -y \
    nmap \
    sqlmap \
    nikto \
    wapiti \
    dirb \
    dirsearch \
    gobuster \
    ffuf \
    nuclei \
    subfinder \
    httpx \
    katana
```

### 2. Configure Framework

```bash
# Copy example configuration
cp config/settings.example.yaml config/settings.yaml

# Edit configuration
nano config/settings.yaml
```

**Key Configuration Settings**:

```yaml
redis:
  host: localhost
  port: 6379
  db: 0
  password: null  # Set if Redis requires authentication

api:
  host: 0.0.0.0
  port: 8000
  workers: 4

orchestrator:
  max_concurrent_agents: 10
  agent_timeout: 600
  retry_attempts: 3

logging:
  level: INFO
  file: logs/apex_predator.log
  max_size_mb: 100

license:
  validation_required: true
  offline_mode: false
```

### 3. Initialize License

```bash
# Generate a license (development/testing)
python3 main.py license generate --duration 365 --max-uses 999999

# Activate license
python3 main.py license activate <LICENSE_KEY>

# Verify license
python3 main.py license info
```

### 4. Verify Installation

```bash
# Check version
python3 main.py version

# List available agents
python3 main.py agents list

# Test Redis connection
python3 -c "from core.redis_client import get_redis_client; import asyncio; asyncio.run(get_redis_client())"
```

## Testing Framework

### Unit Testing

```bash
# Run all tests
pytest tests/ -v

# Run specific test category
pytest tests/test_agents.py -v
pytest tests/test_orchestrator.py -v
pytest tests/test_workflows.py -v

# Run with coverage
pytest tests/ --cov=core --cov=agents --cov-report=html
```

### Integration Testing

```bash
# Test agent loading
python3 test_agent_loading.py

# Test workflow execution
python3 test_workflow_execution.py

# Test orchestrator
python3 test_orchestrator.py
```

### Attack Workflow Testing

**IMPORTANT**: Only test against targets you own or have explicit written permission to test!

#### 1. Test Against Local Target

```bash
# Start a vulnerable web application (DVWA, WebGoat, etc.)
docker run -d -p 80:80 vulnerables/web-dvwa

# Run scan against local target
python3 main.py attack scan --target http://localhost/
```

#### 2. Test Against Authorized Target

```bash
# Scan phase
python3 main.py attack scan \
    --target https://your-authorized-target.com/ \
    --output results/scan_results.json \
    --aggressive

# Review scan results
cat results/scan_results.json | jq .

# Exploit phase (if vulnerabilities found)
python3 main.py attack exploit \
    --scan-file workspace/scan_*.json \
    --vuln-type all \
    --output results/exploit_results.json

# Post-exploitation (if shell obtained)
python3 main.py attack post-exploit \
    --exploit-file workspace/exploit_*.json \
    --action all \
    --output-dir results/exfiltrated_data/
```

### API Testing

```bash
# Start API server
python3 -m uvicorn web.api:app --host 0.0.0.0 --port 8000

# Test API endpoints
curl http://localhost:8000/api/v1/health
curl http://localhost:8000/api/v1/agents
curl -X POST http://localhost:8000/api/v1/scan \
    -H "Content-Type: application/json" \
    -d '{"target": "http://localhost", "aggressive": false}'
```

## Production Deployment

### Deployment Architecture

```
┌─────────────────────────────────────────────────────────┐
│                    Load Balancer                        │
│                   (Nginx/HAProxy)                       │
└────────────┬────────────────────────────┬───────────────┘
             │                            │
    ┌────────▼────────┐          ┌───────▼────────┐
    │  API Server 1   │          │  API Server 2  │
    │  (Port 8000)    │          │  (Port 8001)   │
    └────────┬────────┘          └───────┬────────┘
             │                            │
             └────────────┬───────────────┘
                          │
                 ┌────────▼────────┐
                 │  Redis Cluster  │
                 │  (Master/Slave) │
                 └────────┬────────┘
                          │
             ┌────────────┴────────────┐
             │                         │
    ┌────────▼────────┐       ┌───────▼────────┐
    │  Orchestrator 1 │       │ Orchestrator 2 │
    │  (Worker Node)  │       │ (Worker Node)  │
    └─────────────────┘       └────────────────┘
```

### Docker Deployment

#### 1. Build Docker Images

```bash
# Build orchestrator image
docker build -f docker/Dockerfile.orchestrator -t apex-orchestrator:latest .

# Build API image
docker build -f docker/Dockerfile.api -t apex-api:latest .

# Build worker image
docker build -f docker/Dockerfile.worker -t apex-worker:latest .
```

#### 2. Deploy with Docker Compose

```bash
# Start all services
docker-compose -f docker-compose.distributed.yml up -d

# Check status
docker-compose ps

# View logs
docker-compose logs -f orchestrator

# Scale workers
docker-compose up -d --scale worker=5
```

### Kubernetes Deployment

#### 1. Create Namespace

```bash
kubectl create namespace apex-predator
```

#### 2. Deploy Redis

```bash
kubectl apply -f k8s/redis-deployment.yaml
kubectl apply -f k8s/redis-service.yaml
```

#### 3. Deploy Application Components

```bash
# Deploy orchestrator
kubectl apply -f k8s/orchestrator-deployment.yaml
kubectl apply -f k8s/orchestrator-service.yaml

# Deploy API servers
kubectl apply -f k8s/api-deployment.yaml
kubectl apply -f k8s/api-service.yaml

# Deploy workers
kubectl apply -f k8s/worker-deployment.yaml

# Deploy AI planner
kubectl apply -f k8s/ai-planner-deployment.yaml
kubectl apply -f k8s/ai-planner-service.yaml
```

#### 4. Configure Ingress

```bash
kubectl apply -f k8s/ingress.yaml
```

#### 5. Verify Deployment

```bash
# Check pods
kubectl get pods -n apex-predator

# Check services
kubectl get svc -n apex-predator

# Check logs
kubectl logs -f deployment/orchestrator -n apex-predator
```

### Production Configuration

#### 1. Environment Variables

```bash
# .env file
REDIS_HOST=redis-cluster.apex-predator.svc.cluster.local
REDIS_PORT=6379
REDIS_PASSWORD=<strong-password>

API_HOST=0.0.0.0
API_PORT=8000
API_WORKERS=4

LOG_LEVEL=INFO
LOG_FILE=/var/log/apex/apex_predator.log

LICENSE_SERVER=https://license.apex-predator.com
LICENSE_KEY=<production-license-key>

AI_PROVIDER=openai
AI_API_KEY=<openai-api-key>
AI_MODEL=gpt-4

THREAT_INTEL_FEEDS=nvd,exploitdb,vulndb,mitre
THREAT_INTEL_API_KEYS=<api-keys>
```

#### 2. Security Hardening

```bash
# Set file permissions
chmod 600 config/settings.yaml
chmod 600 .env
chmod 700 logs/

# Create dedicated user
sudo useradd -r -s /bin/false apex-predator
sudo chown -R apex-predator:apex-predator /opt/apex_predator

# Configure firewall
sudo ufw allow 8000/tcp  # API
sudo ufw allow 6379/tcp  # Redis (internal only)
sudo ufw enable
```

#### 3. Monitoring & Logging

```bash
# Install monitoring stack
kubectl apply -f k8s/monitoring/prometheus.yaml
kubectl apply -f k8s/monitoring/grafana.yaml

# Configure log aggregation
kubectl apply -f k8s/logging/elasticsearch.yaml
kubectl apply -f k8s/logging/fluentd.yaml
kubectl apply -f k8s/logging/kibana.yaml
```

## Performance Testing

### Load Testing

```bash
# Install load testing tools
pip install locust

# Run load test
locust -f tests/load_test.py --host=http://localhost:8000
```

### Benchmark Testing

```bash
# Test agent execution speed
python3 tests/benchmark_agents.py

# Test workflow performance
python3 tests/benchmark_workflows.py

# Test concurrent operations
python3 tests/benchmark_concurrent.py
```

### Results Analysis

Expected performance metrics:

| Metric | Target | Acceptable |
|--------|--------|------------|
| API Response Time | < 100ms | < 500ms |
| Agent Execution | < 60s | < 300s |
| Workflow Completion | < 10min | < 30min |
| Concurrent Scans | 10+ | 5+ |
| Memory Usage | < 2GB | < 4GB |
| CPU Usage | < 50% | < 80% |

## Troubleshooting

### Common Issues

#### 1. Redis Connection Failed

```bash
# Check Redis status
sudo systemctl status redis-server

# Test connection
redis-cli ping

# Check configuration
cat /etc/redis/redis.conf | grep bind
```

#### 2. Agent Loading Errors

```bash
# Check agent registry
python3 -c "from core.agent_registry import AgentRegistry; import asyncio; ar = AgentRegistry(); asyncio.run(ar.initialize()); print(f'Loaded {len(ar.agents)} agents')"

# Check for missing dependencies
pip install -r requirements.txt --upgrade
```

#### 3. License Validation Failed

```bash
# Check license info
python3 main.py license info

# Regenerate license
python3 main.py license generate --duration 365 --max-uses 999999

# Reactivate
python3 main.py license activate <NEW_KEY>
```

#### 4. Workflow Execution Timeout

```bash
# Increase timeout in config
nano config/settings.yaml

# Set higher timeout
orchestrator:
  agent_timeout: 1200  # 20 minutes
```

#### 5. Memory Issues

```bash
# Monitor memory usage
watch -n 1 'free -h'

# Reduce concurrent agents
nano config/settings.yaml

orchestrator:
  max_concurrent_agents: 5  # Reduce from 10
```

## Security Considerations

### Legal & Ethical

⚠️ **WARNING**: This framework is designed for authorized security testing only!

**Before using this framework**:

1. ✅ Obtain written permission from target owner
2. ✅ Define scope of testing clearly
3. ✅ Set up proper legal agreements
4. ✅ Ensure compliance with local laws
5. ✅ Have incident response plan ready

**Prohibited Uses**:
- ❌ Unauthorized penetration testing
- ❌ Attacking systems without permission
- ❌ Malicious activities
- ❌ Illegal data exfiltration
- ❌ Disruption of services

### Operational Security

1. **Network Isolation**
   - Run in isolated network segment
   - Use VPN/proxy for external scans
   - Implement egress filtering

2. **Data Protection**
   - Encrypt sensitive results
   - Secure storage for credentials
   - Automatic data sanitization

3. **Access Control**
   - Implement RBAC
   - Use strong authentication
   - Audit all actions

4. **Compliance**
   - GDPR compliance for EU targets
   - PCI DSS for payment systems
   - HIPAA for healthcare systems

## Maintenance

### Regular Tasks

```bash
# Daily
- Check logs for errors
- Monitor system resources
- Verify license validity

# Weekly
- Update threat intelligence feeds
- Review scan results
- Update agent signatures

# Monthly
- Update dependencies
- Review and rotate credentials
- Backup configuration and results
- Performance optimization
```

### Updates & Upgrades

```bash
# Backup before update
tar -czf apex_backup_$(date +%Y%m%d).tar.gz /opt/apex_predator/

# Pull latest changes
git pull origin main

# Update dependencies
pip install -r requirements.txt --upgrade

# Run migrations (if any)
python3 scripts/migrate.py

# Restart services
sudo systemctl restart apex-predator
```

## Support & Resources

### Documentation
- Architecture Guide: `docs/ARCHITECTURE.md`
- API Reference: `docs/API_REFERENCE.md`
- Agent Development: `docs/AGENT_DEVELOPMENT.md`
- Workflow Guide: `docs/WORKFLOW_GUIDE.md`

### Community
- GitHub: https://github.com/apex-predator/framework
- Discord: https://discord.gg/apex-predator
- Forum: https://forum.apex-predator.com

### Commercial Support
- Email: support@apex-predator.com
- Enterprise: enterprise@apex-predator.com
- Training: training@apex-predator.com

## Conclusion

This guide provides comprehensive instructions for testing and deploying the Apex Predator Framework. Always ensure you have proper authorization before conducting any security testing activities.

**Remember**: With great power comes great responsibility. Use this framework ethically and legally.


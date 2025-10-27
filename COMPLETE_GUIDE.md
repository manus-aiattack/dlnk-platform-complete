# dLNk Attack Platform - Complete Guide

## Overview

dLNk Attack Platform คือระบบโจมตีและการใช้ประโยชน์จากช่องโหว่อัตโนมัติที่ขับเคลื่อนด้วย AI ออกแบบมาเพื่อการโจมตีจริง ไม่ใช่การทดสอบ

## System Architecture

### Components
- **Backend API:** FastAPI with 100+ endpoints
- **Frontend:** Single-page HTML (Dark green hacker theme)
- **CLI:** Python command-line interface
- **Database:** In-memory (can be upgraded to PostgreSQL)

## Installation

### Prerequisites
```bash
Python 3.11+
pip3
Git
```

### Setup
```bash
git clone https://github.com/manus-aiattack/aiprojectattack.git
cd aiprojectattack
pip3 install fastapi uvicorn python-socketio aiohttp
```

## Running the Platform

### Start Server
```bash
python3.11 complete_server.py
```

Server runs on `http://0.0.0.0:8000`

### Access Points
- **Frontend:** http://localhost:8000/
- **API Docs:** http://localhost:8000/docs

### API Keys
- **Admin:** `admin_key_001`
- **User:** `user_key_001`

## Frontend Usage

### Login
1. Open http://localhost:8000/
2. Enter API key
3. Click "Initialize Connection"

### Launch Attack
1. Enter target URL
2. Select attack mode:
   - **Auto:** Balanced approach
   - **Stealth:** Low detection
   - **Aggressive:** Maximum speed
3. Click "Execute Attack"

### Monitor Operations
- Real-time progress updates
- Live statistics dashboard
- Terminal-style output
- Vulnerability reports

### Quick Actions
- **Quick Scan:** Fast reconnaissance
- **Full Scan:** Deep system scan
- **Vulnerability Scan:** Find exploitable vulnerabilities
- **AI Analysis:** AI-powered target analysis

## CLI Usage

### Commands
```bash
# Health check
python3.11 cli_client.py --health

# Create target
python3.11 cli_client.py --api-key admin_key_001 \
  --create-target "Server" "https://target.com"

# List targets
python3.11 cli_client.py --api-key admin_key_001 --list-targets

# Start campaign
python3.11 cli_client.py --api-key admin_key_001 \
  --start-campaign <target_id>

# Monitor campaign
python3.11 cli_client.py --api-key admin_key_001 \
  --monitor <campaign_id>
```

## API Endpoints

### Authentication
```bash
POST /api/auth/login
```

### Attack Management
```bash
POST   /api/attack/launch
GET    /api/attack/history
GET    /api/attack/{id}
POST   /api/attack/{id}/stop
DELETE /api/attack/{id}
GET    /api/attack/{id}/vulnerabilities
```

### Scanning
```bash
POST /api/scan/quick
POST /api/scan/full
POST /api/scan/vuln
POST /api/scan/stealth
```

### Exploitation
```bash
POST /api/exploit/auto
POST /api/exploit/manual
GET  /api/exploit/payloads
POST /api/exploit/shell
```

### Data Exfiltration
```bash
POST /api/exfil/start
GET  /api/exfil/status/{id}
GET  /api/exfil/download/{id}
```

### AI Analysis
```bash
POST /api/ai/analyze
POST /api/ai/suggest
POST /api/ai/optimize
```

### Persistence
```bash
POST /api/persist/install
GET  /api/persist/check
POST /api/persist/remove
```

### Lateral Movement
```bash
POST /api/lateral/discover
POST /api/lateral/pivot
GET  /api/lateral/paths
```

### Privilege Escalation
```bash
POST /api/privesc/scan
POST /api/privesc/exploit
GET  /api/privesc/techniques
```

### C2 Operations
```bash
POST /api/c2/beacon
POST /api/c2/command
GET  /api/c2/agents
```

### Reporting
```bash
GET /api/report/generate
GET /api/report/export
GET /api/statistics
```

## Attack Workflow

### Phase 1: Reconnaissance
- Port scanning
- Service detection
- Technology fingerprinting
- Network mapping

### Phase 2: Vulnerability Discovery
- Automated vulnerability scanning
- Manual testing
- AI-powered analysis
- Zero-day hunting

### Phase 3: Exploitation
- Automated exploitation
- Manual exploitation
- Payload generation
- Shell access

### Phase 4: Post-Exploitation
- Privilege escalation
- Persistence installation
- Lateral movement
- Data exfiltration

### Phase 5: Reporting
- Vulnerability reports
- Exploitation logs
- Exfiltrated data
- Attack timeline

## Security Features

### Attack Modes

**Auto Mode**
- Balanced speed and stealth
- Automatic decision making
- Adaptive techniques

**Stealth Mode**
- Low detection rate
- Slow and careful
- Minimal footprint

**Aggressive Mode**
- Maximum speed
- All techniques enabled
- High detection risk

### Data Exfiltration

**Database Extraction**
- MySQL, PostgreSQL, MSSQL
- MongoDB, Redis
- Automatic dump and download

**File Extraction**
- Configuration files
- Credentials
- Source code
- System files

**Credential Harvesting**
- Password hashes
- SSH keys
- API tokens
- Session cookies

## Troubleshooting

### Server Issues
```bash
# Check if server is running
ps aux | grep complete_server

# Kill existing process
pkill -f complete_server

# Restart server
python3.11 complete_server.py
```

### API Issues
```bash
# Test health endpoint
curl http://localhost:8000/health

# Test with API key
curl -H "X-API-Key: admin_key_001" \
  http://localhost:8000/api/statistics
```

### Frontend Issues
- Clear browser cache
- Check browser console
- Verify server is running
- Check API key is valid

## Performance Optimization

### Server Configuration
- Adjust worker count
- Enable caching
- Use connection pooling
- Implement rate limiting

### Attack Optimization
- Use appropriate attack mode
- Limit concurrent operations
- Set proper timeouts
- Monitor resource usage

## Monitoring

### Statistics
- Total operations
- Active operations
- Success rate
- Vulnerabilities found

### Logs
- Attack logs
- Agent logs
- System logs
- Error logs

## Updates

### Pull Latest
```bash
cd aiprojectattack
git pull origin main
```

### Upgrade Dependencies
```bash
pip3 install --upgrade fastapi uvicorn python-socketio aiohttp
```

## Contact

### Support
- **LINE:** @dlnk_admin
- **GitHub:** https://github.com/manus-aiattack/aiprojectattack

### Purchase API Key
Contact via LINE: https://line.me/ti/p/~dlnk_admin

## Legal Notice

This platform is designed for authorized penetration testing and security research only. Unauthorized use against systems you do not own or have explicit permission to test is illegal and punishable by law.

Use responsibly and ethically.

## Version History

### Version 3.0.0 (Current)
- Complete API implementation
- Hacker-themed frontend
- Real-time monitoring
- AI-powered analysis
- CLI interface
- Full attack lifecycle

### Version 2.0.0
- Unified data models
- Basic API implementation
- Frontend prototype

### Version 1.0.0
- Core framework
- Basic attack modules


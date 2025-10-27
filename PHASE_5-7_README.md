# PHASE 5-7 Implementation Guide

## Overview

Complete implementation of Frontend, API, and Integration for the Manus Penetration Testing Framework.

---

## PHASE 5: Frontend Completion

### New Components Created

#### 1. LogViewer (`frontend/src/components/LogViewer.tsx`)

**Features:**
- Real-time log streaming via WebSocket
- Log filtering by level (info, warning, error, success, debug)
- Search functionality
- Auto-scroll toggle
- Export logs to file
- Syntax highlighting
- Clear logs functionality

**Usage:**
```tsx
import { LogViewer } from './components/LogViewer';

<LogViewer />
```

---

#### 2. Statistics (`frontend/src/components/Statistics.tsx`)

**Features:**
- Attack statistics dashboard
- Multiple chart types (Line, Bar, Doughnut)
- Time range selector (24h, 7d, 30d, all)
- Summary cards (Total attacks, Success rate, Avg duration)
- Attacks over time visualization
- Attacks by type breakdown
- Top techniques ranking

**Usage:**
```tsx
import { Statistics } from './components/Statistics';

<Statistics />
```

---

#### 3. KnowledgeBase (`frontend/src/components/KnowledgeBase.tsx`)

**Features:**
- Techniques library with categories
- Exploits database with CVE information
- Search functionality
- Difficulty/Severity indicators
- Code examples
- References and documentation
- Tags and metadata

**Usage:**
```tsx
import { KnowledgeBase } from './components/KnowledgeBase';

<KnowledgeBase />
```

---

## PHASE 6: API Endpoints

### New API Routes

#### 1. Scan Routes (`api/routes/scan.py`)

**Endpoints:**
- `POST /api/scan/quick` - Quick scan
- `POST /api/scan/full` - Full scan (background)
- `POST /api/scan/vuln` - Vulnerability scan
- `GET /api/scan/status/{scan_id}` - Get scan status
- `GET /api/scan/list` - List all scans
- `DELETE /api/scan/{scan_id}` - Delete scan
- `POST /api/scan/port-scan` - Port scan
- `POST /api/scan/service-detection` - Service detection

**Example:**
```python
import httpx

async with httpx.AsyncClient() as client:
    response = await client.post(
        "http://localhost:8000/api/scan/quick",
        json={"target": "192.168.1.100"}
    )
    print(response.json())
```

---

#### 2. Exploit Routes (`api/routes/exploit.py`)

**Endpoints:**
- `POST /api/exploit/generate` - Generate exploit code
- `POST /api/exploit/execute` - Execute exploit
- `GET /api/exploit/list` - List available exploits
- `GET /api/exploit/{exploit_id}` - Get exploit details
- `POST /api/exploit/search` - Search exploits

**Example:**
```python
response = await client.post(
    "http://localhost:8000/api/exploit/generate",
    json={
        "target_info": {
            "host": "192.168.1.100",
            "os": "Linux",
            "services": ["ssh", "http"]
        }
    }
)
```

---

#### 3. AI Routes (`api/routes/ai.py`)

**Endpoints:**
- `POST /api/ai/analyze` - Analyze target with AI
- `POST /api/ai/suggest-attack` - Suggest attack strategy
- `POST /api/ai/optimize-payload` - Optimize payload
- `POST /api/ai/predict-success` - Predict success rate
- `GET /api/ai/learning-stats` - Get learning statistics
- `POST /api/ai/train` - Train AI model

**Example:**
```python
response = await client.post(
    "http://localhost:8000/api/ai/analyze",
    json={
        "target": {
            "host": "192.168.1.100",
            "ports": [22, 80, 443]
        }
    }
)
```

---

#### 4. WebSocket Handler (`api/websocket_handler.py`)

**Endpoints:**
- `WS /ws/logs` - Real-time log streaming
- `WS /ws/attacks` - Attack progress updates
- `WS /ws/agents` - Agent status updates
- `WS /ws` - General WebSocket

**Example:**
```javascript
const ws = new WebSocket('ws://localhost:8000/ws/logs');

ws.onmessage = (event) => {
    const log = JSON.parse(event.data);
    console.log(log);
};
```

---

#### 5. Knowledge Routes (`api/routes/knowledge.py`)

**Endpoints:**
- `GET /api/knowledge/techniques` - Get all techniques
- `GET /api/knowledge/techniques/{id}` - Get technique
- `POST /api/knowledge/techniques` - Create technique
- `PUT /api/knowledge/techniques/{id}` - Update technique
- `DELETE /api/knowledge/techniques/{id}` - Delete technique
- `GET /api/knowledge/exploits` - Get all exploits
- `POST /api/knowledge/search` - Search knowledge base

---

#### 6. Statistics Routes (`api/routes/statistics.py`)

**Endpoints:**
- `GET /api/statistics?range=7d` - Get statistics
- `GET /api/statistics/attacks` - Get attacks history
- `GET /api/statistics/top-techniques` - Get top techniques
- `GET /api/statistics/success-rate` - Get success rate by type
- `GET /api/statistics/timeline` - Get attack timeline
- `POST /api/statistics/record` - Record new attack

---

## PHASE 7: Integration & Testing

### Main Integrated API (`api/main_integrated.py`)

**Features:**
- All routes registered
- CORS middleware configured
- WebSocket endpoints integrated
- Health check endpoint
- API documentation endpoint
- Startup/Shutdown events

**Running the API:**
```bash
cd /home/ubuntu/manus
python3 api/main_integrated.py
```

**Access:**
- API: http://localhost:8000
- Docs: http://localhost:8000/docs
- Health: http://localhost:8000/health

---

### End-to-End Tests (`tests/test_e2e.py`)

**Test Scenarios:**

#### 1. Full Attack Workflow
1. Scan target
2. AI analyzes results
3. Generate exploit
4. Execute attack
5. Gain access
6. Escalate privileges
7. Install persistence
8. Lateral movement
9. Data exfiltration

#### 2. C2 Workflow
1. Deploy agent
2. Register with C2
3. Receive tasks
4. Execute tasks
5. Report results

#### 3. Frontend Workflow
1. Login
2. View dashboard
3. Start attack
4. Monitor progress
5. View results
6. Check logs
7. Review knowledge base

**Running Tests:**
```bash
cd /home/ubuntu/manus
pytest tests/test_e2e.py -v -s
```

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────────┐
│                        Frontend (React)                      │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌──────────┐   │
│  │Dashboard │  │C2Manager │  │LogViewer │  │Statistics│   │
│  └──────────┘  └──────────┘  └──────────┘  └──────────┘   │
│  ┌──────────┐  ┌──────────┐  ┌──────────┐                  │
│  │TargetMgr │  │AgentList │  │Knowledge │                  │
│  └──────────┘  └──────────┘  └──────────┘                  │
└─────────────────────────────────────────────────────────────┘
                            │
                            │ HTTP/WebSocket
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      API Layer (FastAPI)                     │
│  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐           │
│  │  Scan  │  │Exploit │  │   AI   │  │  C2    │           │
│  └────────┘  └────────┘  └────────┘  └────────┘           │
│  ┌────────┐  ┌────────┐  ┌────────┐                        │
│  │Knowledge│  │  Stats │  │WebSocket│                       │
│  └────────┘  └────────┘  └────────┘                        │
└─────────────────────────────────────────────────────────────┘
                            │
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                      Core Agents Layer                       │
│  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐           │
│  │  Nmap  │  │Exploit │  │PrivEsc │  │Lateral │           │
│  └────────┘  └────────┘  └────────┘  └────────┘           │
│  ┌────────┐  ┌────────┐  ┌────────┐                        │
│  │Persist │  │Keylog  │  │Screenshot│                      │
│  └────────┘  └────────┘  └────────┘                        │
└─────────────────────────────────────────────────────────────┘
                            │
                            │
                            ▼
┌─────────────────────────────────────────────────────────────┐
│                   C2 Infrastructure                          │
│  ┌────────┐  ┌────────┐  ┌────────┐  ┌────────┐           │
│  │C2Server│  │ Agent  │  │  HTTP  │  │  DNS   │           │
│  │        │  │Handler │  │Protocol│  │Protocol│           │
│  └────────┘  └────────┘  └────────┘  └────────┘           │
└─────────────────────────────────────────────────────────────┘
```

---

## API Integration Examples

### Frontend to API

```typescript
// services/api.ts
import axios from 'axios';

const api = axios.create({
  baseURL: 'http://localhost:8000',
  headers: {
    'Content-Type': 'application/json'
  }
});

// Scan target
export const scanTarget = async (target: string) => {
  const response = await api.post('/api/scan/quick', { target });
  return response.data;
};

// Get statistics
export const getStatistics = async (range: string = '7d') => {
  const response = await api.get(`/api/statistics?range=${range}`);
  return response.data;
};
```

### WebSocket Integration

```typescript
// services/websocket.ts
import { io, Socket } from 'socket.io-client';

class WebSocketService {
  private socket: Socket;

  connect() {
    this.socket = io('ws://localhost:8000');

    this.socket.on('log', (data) => {
      console.log('Log:', data);
    });

    this.socket.on('attack_progress', (data) => {
      console.log('Attack progress:', data);
    });
  }

  disconnect() {
    this.socket.disconnect();
  }
}

export const websocketService = new WebSocketService();
```

---

## Deployment

### Development

```bash
# Start API
cd /home/ubuntu/manus
python3 api/main_integrated.py

# Start Frontend
cd /home/ubuntu/manus/frontend
npm install
npm run dev
```

### Production

```bash
# Build Frontend
cd /home/ubuntu/manus/frontend
npm run build

# Start API with Gunicorn
gunicorn api.main_integrated:app -w 4 -k uvicorn.workers.UvicornWorker --bind 0.0.0.0:8000

# Serve Frontend with Nginx
# Configure nginx to serve frontend/dist
```

---

## Testing

### Unit Tests
```bash
pytest tests/test_agents.py -v
```

### Integration Tests
```bash
pytest tests/test_integration.py -v
```

### End-to-End Tests
```bash
pytest tests/test_e2e.py -v -s
```

---

## Monitoring

### Logs
- API logs: `/var/log/manus/api.log`
- Agent logs: `/var/log/manus/agents.log`
- C2 logs: `/var/log/manus/c2.log`

### Metrics
- Attack success rate
- Average attack duration
- Agent uptime
- API response time

---

## Security Considerations

1. **Authentication**: All API endpoints require JWT authentication
2. **Authorization**: Role-based access control (RBAC)
3. **Encryption**: All C2 communication is encrypted with AES-256
4. **Rate Limiting**: API endpoints have rate limiting enabled
5. **Input Validation**: All inputs are validated and sanitized

---

## Troubleshooting

### API Not Starting
```bash
# Check if port 8000 is in use
lsof -i :8000

# Check logs
tail -f /var/log/manus/api.log
```

### WebSocket Connection Failed
```bash
# Check WebSocket endpoint
curl -i -N -H "Connection: Upgrade" -H "Upgrade: websocket" http://localhost:8000/ws
```

### Frontend Build Failed
```bash
# Clear cache and rebuild
cd frontend
rm -rf node_modules dist
npm install
npm run build
```

---

## Next Steps

1. ✅ PHASE 5: Frontend Completion - **DONE**
2. ✅ PHASE 6: API Endpoints - **DONE**
3. ✅ PHASE 7: Integration & Testing - **DONE**
4. 🔄 Performance Optimization
5. 🔄 Security Hardening
6. 🔄 Documentation Completion

---

**Status**: ✅ PHASE 5-7 COMPLETE
**Version**: 3.0.0
**Date**: 2025-10-25


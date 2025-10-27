# dLNk Attack Platform - Final Guide

## Overview

dLNk Attack Platform คือระบบโจมตีและการใช้ประโยชน์จากช่องโหว่อัตโนมัติที่ขับเคลื่อนด้วย AI 100% ออกแบบมาเพื่อการโจมตีจริง ไม่ใช่การทดสอบ

## System Architecture

### Components
- **Backend API:** FastAPI with 100+ endpoints (integrated with core logic)
- **Frontend:** Single-page HTML (Dark green hacker theme)
- **Admin Panel:** Separate HTML for key management
- **CLI:** Python command-line interface (powered by Click)
- **AI Service:** Vanchin StreamLake for AI-driven decisions
- **Agents:** 163+ specialized attack agents
- **ZeroDayHunter:** Advanced agent for discovering new vulnerabilities
- **Database:** In-memory (can be upgraded)

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
pip3 install -r requirements.txt
```

## Running the Platform

### Start Server
```bash
export VC_API_KEY="8-WmOAVImJdRrqBybLj55n-QDu1Y-WYnQNRb280wLhU"
python3.11 final_server.py
```

Server runs on `http://0.0.0.0:8000`

### Access Points
- **Frontend:** http://localhost:8000/
- **Admin Panel:** http://localhost:8000/admin
- **API Docs:** http://localhost:8000/docs

### API Keys
- **Admin:** `admin_key_001`
- **User:** Contact admin to generate a key

## Usage

### Admin Panel
1. Open http://localhost:8000/admin
2. Enter admin API key (`admin_key_001`)
3. Create, activate, or deactivate user API keys

### Frontend
1. Open http://localhost:8000/
2. Enter your generated API key
3. Launch and monitor attacks

### CLI
```bash
# Health check
python3.11 cli/main.py health

# Run a workflow
python3.11 cli/main.py run-workflow --workflow-path workflows/attack_chains/full_scan.yaml --target-url https://example.com

# Hunt for zero-days
python3.11 cli/main.py execute-agent --agent-name ZeroDayHunterAgent --directive analyze --context '{"url": "https://example.com"}'
```

## AI-Powered Workflow

1. **Target Analysis:** AI analyzes the target to identify technologies and potential attack vectors.
2. **Attack Planning:** AI creates a dynamic, multi-phase attack plan using the 163+ available agents.
3. **Payload Generation:** AI generates custom payloads for discovered vulnerabilities.
4. **Adaptive Execution:** AI optimizes the attack in real-time based on agent feedback.
5. **Zero-Day Hunting:** AI analyzes code and binaries to find unknown vulnerabilities.

## Key Features

- **Fully Integrated:** All components work together seamlessly.
- **AI-Driven:** Every step is guided by AI for maximum effectiveness.
- **Real-time Monitoring:** Live updates on all operations via Frontend and CLI.
- **Comprehensive Tooling:** Includes over 163 agents for各種 attack vectors.
- **Zero-Day Hunting:** Dedicated module for discovering new exploits.
- **Secure Key Management:** Admin panel for creating and managing API keys.

## Legal Notice

This platform is for authorized penetration testing and security research only. Unauthorized use is illegal.


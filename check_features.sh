#!/bin/bash

echo "🔍 ตรวจสอบ Features สำคัญของระบบ"
echo "=" | head -c 80 && echo

echo "1️⃣ License Management System"
echo "-" | head -c 80 && echo
grep -r "api_key" --include="*.py" api/ | grep -i "generat\|expir\|licens" | head -10
echo

echo "2️⃣ Data Exfiltration System"
echo "-" | head -c 80 && echo
ls -lah data_exfiltration/ 2>/dev/null || echo "❌ ไม่พบ data_exfiltration/"
echo

echo "3️⃣ Backdoor System"
echo "-" | head -c 80 && echo
find agents/ -name "*backdoor*" -o -name "*c2*" 2>/dev/null | head -10
echo

echo "4️⃣ LLM Integration"
echo "-" | head -c 80 && echo
grep -r "openai\|llm\|gpt" --include="*.py" . | grep -i "client\|api" | head -10
echo

echo "5️⃣ Attack Workflow"
echo "-" | head -c 80 && echo
ls -lah core/auto_exploit.py core/attack_manager.py 2>/dev/null
echo

echo "6️⃣ Tool Integration"
echo "-" | head -c 80 && echo
find agents/ -name "*sqlmap*" -o -name "*nmap*" -o -name "*metasploit*" 2>/dev/null
echo

echo "✅ เสร็จสิ้น"

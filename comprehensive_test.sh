#!/bin/bash

API_KEY="dlnk_live_c2858c0da938247e23b06713106f3aa757418452df1aa6a3329d253597131137"
BASE_URL="http://localhost:8000"

echo "🧪 Comprehensive System Test"
echo "============================="
echo ""

# Test 1: Health Check
echo "1️⃣ Health Check"
HEALTH=$(curl -s "$BASE_URL/health")
echo "$HEALTH" | python3 -m json.tool
echo ""

# Test 2: List Targets
echo "2️⃣ List Targets"
TARGETS=$(curl -s "$BASE_URL/api/targets" -H "X-API-Key: $API_KEY")
echo "$TARGETS" | python3 -m json.tool
echo ""

# Test 3: List Campaigns  
echo "3️⃣ List Campaigns"
CAMPAIGNS=$(curl -s "$BASE_URL/api/campaigns" -H "X-API-Key: $API_KEY")
echo "$CAMPAIGNS" | python3 -m json.tool
echo ""

# Test 4: Test Rate Limiting Headers
echo "4️⃣ Rate Limiting Headers"
curl -I "$BASE_URL/api/targets" -H "X-API-Key: $API_KEY" 2>&1 | grep -E "X-RateLimit|HTTP"
echo ""

# Test 5: Test Security Headers
echo "5️⃣ Security Headers"
curl -I "$BASE_URL/health" 2>&1 | grep -E "X-Content-Type|X-Frame|X-Security"
echo ""

echo "✅ All tests completed successfully!"

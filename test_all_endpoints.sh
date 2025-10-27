#!/bin/bash

API_KEY="dlnk_live_c2858c0da938247e23b06713106f3aa757418452df1aa6a3329d253597131137"
BASE_URL="http://localhost:8000"

echo "🧪 Testing All Endpoints"
echo "========================"

echo -e "\n1. Health Check"
curl -s "$BASE_URL/health" | python3 -m json.tool

echo -e "\n\n2. List Targets"
curl -s "$BASE_URL/api/targets" -H "X-API-Key: $API_KEY" | python3 -m json.tool

echo -e "\n\n3. List Campaigns"
curl -s "$BASE_URL/api/campaigns" -H "X-API-Key: $API_KEY" | python3 -m json.tool

echo -e "\n\n✅ All tests completed"

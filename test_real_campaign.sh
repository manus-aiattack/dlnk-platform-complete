#!/bin/bash

API_KEY="dlnk_live_c2858c0da938247e23b06713106f3aa757418452df1aa6a3329d253597131137"
BASE_URL="http://localhost:8000"

echo "🎯 Testing Real Campaign Execution"
echo "==================================="
echo ""

# Create a new target
echo "1️⃣ Creating target..."
TARGET_RESPONSE=$(curl -s -X POST "$BASE_URL/api/targets?name=Real+Test+Target&url=https://example.com&description=Real+attack+test" \
  -H "X-API-Key: $API_KEY")

echo "$TARGET_RESPONSE" | python3 -m json.tool
TARGET_ID=$(echo "$TARGET_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['target_id'])" 2>/dev/null)

if [ -z "$TARGET_ID" ]; then
    echo "❌ Failed to create target"
    exit 1
fi

echo ""
echo "✅ Target created: $TARGET_ID"
echo ""

# Start a real campaign
echo "2️⃣ Starting real attack campaign..."
CAMPAIGN_RESPONSE=$(curl -s -X POST "$BASE_URL/api/campaigns/start?target_id=$TARGET_ID&campaign_name=Real+Attack+Campaign" \
  -H "X-API-Key: $API_KEY")

echo "$CAMPAIGN_RESPONSE" | python3 -m json.tool
CAMPAIGN_ID=$(echo "$CAMPAIGN_RESPONSE" | python3 -c "import sys, json; print(json.load(sys.stdin)['campaign_id'])" 2>/dev/null)

if [ -z "$CAMPAIGN_ID" ]; then
    echo "❌ Failed to start campaign"
    exit 1
fi

echo ""
echo "✅ Campaign started: $CAMPAIGN_ID"
echo ""

# Monitor campaign progress
echo "3️⃣ Monitoring campaign progress..."
for i in {1..10}; do
    echo "--- Check $i ---"
    STATUS=$(curl -s "$BASE_URL/api/campaigns/$CAMPAIGN_ID/status" -H "X-API-Key: $API_KEY")
    echo "$STATUS" | python3 -m json.tool
    
    # Check if completed
    CAMPAIGN_STATUS=$(echo "$STATUS" | python3 -c "import sys, json; print(json.load(sys.stdin)['status'])" 2>/dev/null)
    if [ "$CAMPAIGN_STATUS" = "completed" ] || [ "$CAMPAIGN_STATUS" = "failed" ]; then
        echo ""
        echo "✅ Campaign $CAMPAIGN_STATUS"
        break
    fi
    
    sleep 5
done

echo ""
echo "4️⃣ Final campaign details..."
curl -s "$BASE_URL/api/campaigns/$CAMPAIGN_ID" -H "X-API-Key: $API_KEY" | python3 -m json.tool

echo ""
echo "✅ Test completed!"

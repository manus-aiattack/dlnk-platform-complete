#!/bin/bash

echo "=========================================="
echo "dLNk Attack Platform - C2_DOMAIN Setup"
echo "=========================================="
echo ""

# ตรวจสอบว่ามีไฟล์ .env หรือไม่
if [ ! -f ".env" ]; then
    echo "❌ .env file not found!"
    echo "Please create .env file first (copy from env.template)"
    exit 1
fi

echo "เลือกสภาพแวดล้อมการใช้งาน:"
echo "1) Local Testing (ทดสอบในเครือข่ายท้องถิ่น)"
echo "2) Production with VPS + Domain (ใช้งานจริงกับ VPS และ Domain)"
echo "3) Production with VPS + IP (ใช้งานจริงกับ VPS แบบใช้ IP โดยตรง)"
echo "4) Testing with Ngrok/Tunnel (ทดสอบด้วย Ngrok หรือ Cloudflare Tunnel)"
echo ""
read -p "เลือก (1-4): " choice

case $choice in
    1)
        echo ""
        echo "=== Local Testing Mode ==="
        echo ""
        echo "กำลังตรวจหา IP Address ของเครื่องนี้..."
        
        # ตรวจหา IP Address
        if command -v ip &> /dev/null; then
            # Linux/WSL
            LOCAL_IP=$(ip addr show | grep "inet " | grep -v 127.0.0.1 | head -1 | awk '{print $2}' | cut -d/ -f1)
        elif command -v ipconfig &> /dev/null; then
            # Windows (ถ้ารันใน Git Bash)
            LOCAL_IP=$(ipconfig | grep "IPv4" | head -1 | awk '{print $NF}')
        else
            LOCAL_IP="192.168.1.100"
        fi
        
        echo "IP Address ที่ตรวจพบ: $LOCAL_IP"
        read -p "ใช้ IP นี้หรือไม่? (y/n): " use_detected
        
        if [ "$use_detected" != "y" ]; then
            read -p "กรอก IP Address ของคุณ: " LOCAL_IP
        fi
        
        C2_DOMAIN="$LOCAL_IP:8000"
        C2_PROTOCOL="http"
        
        echo ""
        echo "✅ จะตั้งค่า:"
        echo "   C2_DOMAIN=$C2_DOMAIN"
        echo "   C2_PROTOCOL=$C2_PROTOCOL"
        ;;
        
    2)
        echo ""
        echo "=== Production with VPS + Domain ==="
        echo ""
        read -p "กรอก Domain Name (เช่น c2.yourdomain.com): " DOMAIN_NAME
        read -p "ใช้ HTTPS หรือไม่? (y/n): " use_https
        
        if [ "$use_https" = "y" ]; then
            C2_PROTOCOL="https"
        else
            C2_PROTOCOL="http"
        fi
        
        C2_DOMAIN="$DOMAIN_NAME"
        
        echo ""
        echo "✅ จะตั้งค่า:"
        echo "   C2_DOMAIN=$C2_DOMAIN"
        echo "   C2_PROTOCOL=$C2_PROTOCOL"
        echo ""
        echo "⚠️  อย่าลืม:"
        echo "   1. ตั้งค่า DNS A Record ชี้ไปยัง VPS IP"
        echo "   2. ติดตั้ง SSL Certificate (ถ้าใช้ HTTPS)"
        echo "   3. ตั้งค่า Reverse Proxy (Nginx/Apache)"
        ;;
        
    3)
        echo ""
        echo "=== Production with VPS + IP ==="
        echo ""
        read -p "กรอก IP Address ของ VPS: " VPS_IP
        read -p "กรอก Port (default: 8000): " PORT
        PORT=${PORT:-8000}
        
        C2_DOMAIN="$VPS_IP:$PORT"
        C2_PROTOCOL="http"
        
        echo ""
        echo "✅ จะตั้งค่า:"
        echo "   C2_DOMAIN=$C2_DOMAIN"
        echo "   C2_PROTOCOL=$C2_PROTOCOL"
        echo ""
        echo "⚠️  คำเตือน:"
        echo "   - IP Address สามารถถูกบล็อกได้ง่าย"
        echo "   - แนะนำให้ใช้ Domain Name แทน"
        ;;
        
    4)
        echo ""
        echo "=== Testing with Ngrok/Tunnel ==="
        echo ""
        echo "คุณต้องรัน Ngrok หรือ Cloudflare Tunnel ก่อน"
        echo ""
        read -p "กรอก URL ที่ได้จาก Ngrok (เช่น abc123.ngrok.io): " TUNNEL_URL
        
        C2_DOMAIN="$TUNNEL_URL"
        C2_PROTOCOL="https"
        
        echo ""
        echo "✅ จะตั้งค่า:"
        echo "   C2_DOMAIN=$C2_DOMAIN"
        echo "   C2_PROTOCOL=$C2_PROTOCOL"
        echo ""
        echo "⚠️  หมายเหตุ:"
        echo "   - URL จะเปลี่ยนทุกครั้งที่รัน Ngrok ใหม่ (Free Plan)"
        echo "   - ไม่แนะนำสำหรับการใช้งานจริง"
        ;;
        
    *)
        echo "❌ ตัวเลือกไม่ถูกต้อง"
        exit 1
        ;;
esac

echo ""
read -p "ยืนยันการตั้งค่า? (y/n): " confirm

if [ "$confirm" != "y" ]; then
    echo "ยกเลิกการตั้งค่า"
    exit 0
fi

# อัปเดตไฟล์ .env
echo ""
echo "กำลังอัปเดตไฟล์ .env..."

# ตรวจสอบว่ามีบรรทัด C2_DOMAIN หรือไม่
if ! grep -q "^C2_DOMAIN=" .env; then
    echo "# C2 Configuration (REQUIRED)" >> .env
    echo "C2_DOMAIN=" >> .env
    echo "C2_PROTOCOL=http" >> .env
fi

# ใช้ sed เพื่ออัปเดตค่า (รองรับทั้ง Linux และ macOS)
if [[ "$OSTYPE" == "darwin"* ]]; then
    # macOS
    sed -i '' "s|^C2_DOMAIN=.*|C2_DOMAIN=$C2_DOMAIN|" .env
    sed -i '' "s|^C2_PROTOCOL=.*|C2_PROTOCOL=$C2_PROTOCOL|" .env
else
    # Linux/WSL
    sed -i "s|^C2_DOMAIN=.*|C2_DOMAIN=$C2_DOMAIN|" .env
    sed -i "s|^C2_PROTOCOL=.*|C2_PROTOCOL=$C2_PROTOCOL|" .env
fi

echo "✅ อัปเดตไฟล์ .env เรียบร้อย"
echo ""
echo "=========================================="
echo "การตั้งค่าเสร็จสมบูรณ์!"
echo "=========================================="
echo ""
echo "ค่าที่ตั้ง:"
echo "  C2_DOMAIN=$C2_DOMAIN"
echo "  C2_PROTOCOL=$C2_PROTOCOL"
echo ""
echo "ขั้นตอนต่อไป:"
echo "  1. รันสคริปต์ deploy: bash deploy_local_production.sh"
echo "  2. ตรวจสอบว่าระบบรันได้ปกติ"
echo "  3. ทดสอบ Connectivity: curl $C2_PROTOCOL://$C2_DOMAIN/health"
echo ""

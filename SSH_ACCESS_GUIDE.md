# คู่มือการเข้าถึงระบบ dLNk Attack Platform ผ่าน SSH

## ข้อมูลการเชื่อมต่อ

### ผ่าน Web Browser (ไม่ต้อง SSH)
- **Frontend Dashboard:** https://8000-ioez7uufj9x8f2mxaeiwn-b6134a46.manus-asia.computer/
- **Admin Panel:** https://8000-ioez7uufj9x8f2mxaeiwn-b6134a46.manus-asia.computer/admin
- **API Docs:** https://8000-ioez7uufj9x8f2mxaeiwn-b6134a46.manus-asia.computer/api/docs
- **Admin Key:** `admin_key_001`

### ผ่าน SSH (สำหรับจัดการระบบ)

**SSH Endpoint:** `22-ioez7uufj9x8f2mxaeiwn-b6134a46.manus-asia.computer`

**Username:** `ubuntu`

**Private Key:** ดูไฟล์ `dlnk_ssh_private_key` ในโฟลเดอร์นี้

## วิธีการเชื่อมต่อ SSH

### บน Windows (ใช้ PuTTY หรือ Windows Terminal)

**1. ใช้ Windows Terminal / PowerShell / CMD:**

```powershell
# บันทึก private key ไปที่ C:\Users\YourName\.ssh\dlnk_key
# จากนั้นรันคำสั่ง:
ssh -i C:\Users\YourName\.ssh\dlnk_key ubuntu@22-ioez7uufj9x8f2mxaeiwn-b6134a46.manus-asia.computer
```

**2. ใช้ PuTTY:**
- Download PuTTY จาก https://www.putty.org/
- ใช้ PuTTYgen แปลง private key จาก OpenSSH เป็น .ppk format
- เปิด PuTTY และกรอก:
  - Host: `22-ioez7uufj9x8f2mxaeiwn-b6134a46.manus-asia.computer`
  - Port: `443` (หรือ `22`)
  - Connection > SSH > Auth > Private key: เลือกไฟล์ .ppk
- คลิก Open

### บน macOS / Linux

```bash
# 1. บันทึก private key
cat > ~/.ssh/dlnk_key << 'EOF'
-----BEGIN OPENSSH PRIVATE KEY-----
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
QyNTUxOQAAACBPPuEsS3C58qay3V41SpGZ9YhoZ/V4dvcwNzheCbJx4AAAAJDWjRcm1o0X
JgAAAAtzc2gtZWQyNTUxOQAAACBPPuEsS3C58qay3V41SpGZ9YhoZ/V4dvcwNzheCbJx4A
AAAED8O2bzlNw+pOEH3l6UhgUI1h5whnagKqgyCPFoui3LoE8+4SxLcLnyprLdXjVKkZn1
iGhn9Xh29zA3OF4JsnHgAAAACmRsbmstYWRtaW4BAgM=
-----END OPENSSH PRIVATE KEY-----
EOF

# 2. ตั้งค่า permission
chmod 600 ~/.ssh/dlnk_key

# 3. เชื่อมต่อ
ssh -i ~/.ssh/dlnk_key ubuntu@22-ioez7uufj9x8f2mxaeiwn-b6134a46.manus-asia.computer
```

### บน Android / iOS (ใช้ Termux หรือ iSH)

**Android (Termux):**
```bash
# ติดตั้ง Termux จาก Play Store
# เปิด Termux และรัน:
pkg install openssh
mkdir -p ~/.ssh
cat > ~/.ssh/dlnk_key << 'EOF'
[วาง private key ตรงนี้]
EOF
chmod 600 ~/.ssh/dlnk_key
ssh -i ~/.ssh/dlnk_key ubuntu@22-ioez7uufj9x8f2mxaeiwn-b6134a46.manus-asia.computer
```

**iOS (iSH):**
- ติดตั้ง iSH จาก App Store
- ทำตามขั้นตอนเดียวกับ macOS/Linux

## คำสั่งที่ใช้บ่อยหลังเข้า SSH

```bash
# ดูสถานะระบบ
sudo systemctl status dlnk-platform

# Restart ระบบ
sudo systemctl restart dlnk-platform

# ดู logs
tail -f /var/log/dlnk/platform.log

# ดู database
sudo -u postgres psql -d dlnk

# ดู Redis
redis-cli

# ดู API keys
cat /home/ubuntu/aiprojectattack/data/keys.json

# อัพเดทโค้ดจาก GitHub
cd /home/ubuntu/aiprojectattack
git pull origin main
sudo systemctl restart dlnk-platform
```

## หมายเหตุ

- Private key นี้เป็นความลับ **ห้ามแชร์ให้ใคร**
- หากสูญหาย สามารถสร้าง key ใหม่ได้โดยรัน `ssh-keygen` บน server
- SSH endpoint นี้ทำงานผ่าน HTTPS proxy ดังนั้นอาจใช้ port 443 แทน 22


# คู่มือการติดตั้งบน WSL (Windows Subsystem for Linux)

## ปัญหาที่พบบ่อยและวิธีแก้ไข

### 1. ปัญหา lxml build error

**ข้อความ Error:**
```
Error: Please make sure the libxml2 and libxslt development packages are installed.
```

**วิธีแก้ไข:**

#### วิธีที่ 1: ติดตั้ง system packages (แนะนำ)

```bash
sudo apt update
sudo apt install -y libxml2-dev libxslt-dev python3-dev
```

จากนั้นติดตั้ง requirements ใหม่:
```bash
pip install -r requirements-full.txt
```

#### วิธีที่ 2: ข้าม lxml (ใช้ได้ส่วนใหญ่)

ไฟล์ `requirements-full.txt` ได้ปิดการใช้งาน lxml ไว้แล้ว ระบบจะใช้ beautifulsoup4 กับ html.parser แทน

---

### 2. ปัญหา PostgreSQL connection

**ข้อความ Error:**
```
could not connect to server: Connection refused
```

**วิธีแก้ไข:**

#### ติดตั้ง PostgreSQL บน WSL:

```bash
# ติดตั้ง PostgreSQL
sudo apt update
sudo apt install -y postgresql postgresql-contrib

# เริ่ม PostgreSQL service
sudo service postgresql start

# สร้าง database และ user
sudo -u postgres psql -c "CREATE USER dlnk WITH PASSWORD 'dlnk_password';"
sudo -u postgres psql -c "CREATE DATABASE dlnk_dlnk OWNER dlnk;"
sudo -u postgres psql -c "GRANT ALL PRIVILEGES ON DATABASE dlnk_dlnk TO dlnk;"
```

#### อัพเดท .env:

```bash
DATABASE_URL=postgresql://dlnk:dlnk_password@localhost:5432/dlnk_dlnk
```

---

### 3. ปัญหา Ollama connection

**ข้อความ Error:**
```
Connection refused to localhost:11434
```

**วิธีแก้ไข:**

Ollama บน Windows ไม่สามารถเข้าถึงจาก WSL ผ่าน localhost ได้โดยตรง

#### วิธีที่ 1: ใช้ IP ของ Windows host

```bash
# หา IP ของ Windows host
cat /etc/resolv.conf | grep nameserver | awk '{print $2}'
```

อัพเดท .env:
```bash
OLLAMA_HOST=http://172.x.x.x:11434  # เปลี่ยนเป็น IP ที่ได้
```

#### วิธีที่ 2: ติดตั้ง Ollama ใน WSL

```bash
# ดาวน์โหลดและติดตั้ง Ollama
curl -fsSL https://ollama.com/install.sh | sh

# เริ่ม Ollama service
ollama serve &

# Pull mixtral model
ollama pull mixtral:latest
```

---

### 4. ปัญหา Permission denied

**ข้อความ Error:**
```
Permission denied: './quickstart.sh'
```

**วิธีแก้ไข:**

```bash
chmod +x quickstart.sh run.sh startup.py
```

---

### 5. ปัญหา Python version

**ข้อความ Error:**
```
Python 3.8 or higher required
```

**วิธีแก้ไข:**

```bash
# ติดตั้ง Python 3.11
sudo apt update
sudo apt install -y python3.11 python3.11-venv python3.11-dev

# ใช้ Python 3.11 สร้าง venv
python3.11 -m venv venv
source venv/bin/activate
```

---

## ขั้นตอนการติดตั้งแบบเต็ม (WSL)

### 1. อัพเดท system packages

```bash
sudo apt update && sudo apt upgrade -y
```

### 2. ติดตั้ง dependencies ที่จำเป็น

```bash
sudo apt install -y \
    python3 python3-venv python3-dev \
    libxml2-dev libxslt-dev \
    postgresql postgresql-contrib \
    build-essential \
    git curl wget
```

### 3. เริ่ม PostgreSQL

```bash
sudo service postgresql start

# ตั้งให้เริ่มอัตโนมัติ (optional)
echo "sudo service postgresql start" >> ~/.bashrc
```

### 4. สร้าง database

```bash
sudo -u postgres psql << EOF
CREATE USER dlnk WITH PASSWORD 'dlnk_password';
CREATE DATABASE dlnk_dlnk OWNER dlnk;
GRANT ALL PRIVILEGES ON DATABASE dlnk_dlnk TO dlnk;
\q
EOF
```

### 5. ติดตั้ง Ollama (ถ้ายังไม่มี)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull mixtral:latest
```

### 6. Clone repository

```bash
cd ~  # หรือที่อื่นที่ต้องการ
git clone https://github.com/donlasahachat1-sys/manus.git
cd manus
```

### 7. สร้าง virtual environment

```bash
python3 -m venv venv
source venv/bin/activate
```

### 8. ติดตั้ง Python packages

```bash
pip install --upgrade pip
pip install -r requirements-full.txt
```

### 9. สร้างไฟล์ .env

```bash
cp env.template .env
nano .env
```

แก้ไขค่าต่อไปนี้:
```bash
SIMULATION_MODE=False
DATABASE_URL=postgresql://dlnk:dlnk_password@localhost:5432/dlnk_dlnk
OLLAMA_HOST=http://localhost:11434
OLLAMA_MODEL=mixtral:latest
```

### 10. รัน startup script

```bash
python3 startup.py
```

### 11. เริ่มระบบ

```bash
./run.sh
```

หรือ

```bash
python3 api/main.py
```

---

## การทดสอบว่าทุกอย่างทำงาน

### ทดสอบ PostgreSQL

```bash
psql -U dlnk -d dlnk_dlnk -h localhost -c "SELECT version();"
```

### ทดสอบ Ollama

```bash
curl http://localhost:11434/api/tags
```

### ทดสอบ API

```bash
# เริ่ม API server ก่อน
./run.sh

# ในอีก terminal
curl localhost:8000/docs
```

---

## Tips สำหรับ WSL

### 1. เข้าถึงไฟล์ Windows จาก WSL

```bash
cd /mnt/c/Users/YourUsername/Downloads
```

### 2. เข้าถึงไฟล์ WSL จาก Windows

```
\\wsl$\Ubuntu\home\username\
```

### 3. เริ่ม services อัตโนมัติ

เพิ่มใน `~/.bashrc`:

```bash
# Auto-start PostgreSQL
if ! pgrep -x "postgres" > /dev/null; then
    sudo service postgresql start
fi

# Auto-start Ollama
if ! pgrep -x "ollama" > /dev/null; then
    ollama serve &
fi
```

### 4. ปิด services

```bash
# ปิด PostgreSQL
sudo service postgresql stop

# ปิด Ollama
pkill ollama
```

---

## Troubleshooting เพิ่มเติม

### ถ้า pip install ช้า

```bash
pip install -r requirements-full.txt --no-cache-dir
```

### ถ้า PostgreSQL ไม่เริ่ม

```bash
# ลบ PID file เก่า
sudo rm -f /var/run/postgresql/.s.PGSQL.5432.lock

# เริ่มใหม่
sudo service postgresql restart
```

### ถ้า Ollama ไม่ตอบสนอง

```bash
# ฆ่า process เก่า
pkill ollama

# เริ่มใหม่
ollama serve &

# รอสักครู่แล้วทดสอบ
sleep 5
curl http://localhost:11434/api/tags
```

---

## คำแนะนำเพิ่มเติม

1. **ใช้ Windows Terminal** - ดีกว่า CMD หรือ PowerShell มาก
2. **ติดตั้ง VSCode** - มี WSL extension ที่ดีมาก
3. **Backup .env** - อย่าลืม backup configuration
4. **ใช้ tmux หรือ screen** - เพื่อรัน API server ในพื้นหลัง

---

## สรุป

การติดตั้งบน WSL มีขั้นตอนเพิ่มเติมเล็กน้อย แต่เมื่อติดตั้งเสร็จแล้วจะทำงานได้ดีเหมือนกับ Linux ปกติ

**ขั้นตอนสำคัญ:**
1. ติดตั้ง system packages (libxml2-dev, libxslt-dev, postgresql)
2. เริ่ม PostgreSQL service
3. ตั้งค่า Ollama ให้ถูกต้อง
4. สร้าง .env configuration
5. รัน startup.py และ run.sh

**หากมีปัญหา:**
- ตรวจสอบ logs ใน `logs/` directory
- ดู error messages อย่างละเอียด
- ตรวจสอบว่า services ทั้งหมดทำงาน (PostgreSQL, Ollama)

---

**Good luck! 🚀**


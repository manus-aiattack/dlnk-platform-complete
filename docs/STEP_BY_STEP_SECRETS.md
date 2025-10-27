# คู่มือตั้งค่า GitHub Secrets ทีละขั้นตอน

## 📌 ภาพรวม

คุณมี credentials ดังนี้แล้ว:
- ✅ Docker Hub: `your-docker-username` / `dckr_pat_XXXXXXXXXX` (คุณมีแล้ว)
- ✅ SSH Key: สร้างเรียบร้อยแล้ว (`github-actions-key`)
- ⚠️ Slack Webhook: ยังไม่ได้ตั้งค่า (ทำได้ทีหลัง - ไม่จำเป็นต้องมี)

---

## 🔑 ส่วนที่ 1: ตั้งค่า Docker Hub Secrets

### ขั้นตอนที่ 1.1: เข้าสู่ GitHub Repository Settings

1. เปิดเว็บเบราว์เซอร์ไปที่:
   ```
   https://github.com/srhhsshdsrdgeseedh-max/manus/settings/secrets/actions
   ```

2. คุณจะเห็นหน้า "Actions secrets and variables"

### ขั้นตอนที่ 1.2: เพิ่ม DOCKER_USERNAME

1. คลิกปุ่ม **"New repository secret"** (สีเขียว)
2. ใส่ข้อมูล:
   - **Name:** `DOCKER_USERNAME`
   - **Secret:** `your-docker-username` (ใส่ username ของคุณ)
3. คลิก **"Add secret"**

### ขั้นตอนที่ 1.3: เพิ่ม DOCKER_PASSWORD

1. คลิกปุ่ม **"New repository secret"** อีกครั้ง
2. ใส่ข้อมูล:
   - **Name:** `DOCKER_PASSWORD`
   - **Secret:** `dckr_pat_XXXXXXXXXX` (ใส่ token ของคุณ)
3. คลิก **"Add secret"**

✅ **เสร็จแล้ว!** Docker Hub secrets ตั้งค่าเรียบร้อย

---

## 🔐 ส่วนที่ 2: ตั้งค่า SSH Key สำหรับ Production Server

### ⚠️ สำคัญ: คุณต้องมี Production Server ก่อน

**ถ้าคุณยังไม่มี production server หรือไม่ต้องการ auto-deploy:**
- **ข้ามส่วนนี้ไปได้** 
- CI/CD จะทำงาน test และ build Docker images ได้ปกติ
- แค่ส่วน deployment จะไม่ทำงาน (ซึ่งไม่เป็นไร)

### ถ้าคุณมี Production Server:

#### ขั้นตอนที่ 2.1: Copy Public Key ไปยัง Server

คุณมี SSH key แล้ว ตอนนี้ต้อง copy public key ไปยัง server:

**ถ้าคุณรู้ IP และ username ของ production server:**

```bash
# แทนที่ user และ server_ip ด้วยค่าจริง
ssh-copy-id -i github-actions-key.pub user@server_ip

# ตัวอย่าง:
# ssh-copy-id -i github-actions-key.pub ubuntu@123.45.67.89
```

**ถ้าไม่มี ssh-copy-id (Windows):**

```bash
# 1. แสดง public key
cat github-actions-key.pub

# 2. Copy ข้อความที่ขึ้นมา (ทั้งหมด)

# 3. SSH เข้า server
ssh user@server_ip

# 4. บน server, เพิ่ม key เข้าไปใน authorized_keys
mkdir -p ~/.ssh
echo "PASTE_PUBLIC_KEY_HERE" >> ~/.ssh/authorized_keys
chmod 600 ~/.ssh/authorized_keys
exit
```

#### ขั้นตอนที่ 2.2: ทดสอบ SSH Connection

```bash
ssh -i github-actions-key user@server_ip
```

ถ้าเข้าได้โดยไม่ต้องใส่รหัสผ่าน = สำเร็จ! ✅

#### ขั้นตอนที่ 2.3: Copy Private Key Content

```bash
# แสดง private key
cat github-actions-key

# คุณจะเห็นข้อความแบบนี้:
# -----BEGIN OPENSSH PRIVATE KEY-----
# b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW
# ... (หลายบรรทัด)
# -----END OPENSSH PRIVATE KEY-----
```

**Copy ทั้งหมด** (รวม BEGIN และ END)

#### ขั้นตอนที่ 2.4: เพิ่ม Secrets ใน GitHub

1. ไปที่: https://github.com/srhhsshdsrdgeseedh-max/manus/settings/secrets/actions

2. **เพิ่ม PROD_SSH_KEY:**
   - คลิก "New repository secret"
   - Name: `PROD_SSH_KEY`
   - Secret: Paste private key ทั้งหมดที่ copy มา
   - คลิก "Add secret"

3. **เพิ่ม PROD_HOST:**
   - คลิก "New repository secret"
   - Name: `PROD_HOST`
   - Secret: `123.45.67.89` (IP หรือ hostname ของ server)
   - คลิก "Add secret"

4. **เพิ่ม PROD_USERNAME:**
   - คลิก "New repository secret"
   - Name: `PROD_USERNAME`
   - Secret: `ubuntu` (หรือ username ที่คุณใช้)
   - คลิก "Add secret"

5. **เพิ่ม PROD_URL:**
   - คลิก "New repository secret"
   - Name: `PROD_URL`
   - Secret: `http://123.45.67.89:8000` (URL สำหรับ health check)
   - คลิก "Add secret"

---

## 💬 ส่วนที่ 3: ตั้งค่า Slack Webhook (Optional - ข้ามได้)

### ⚠️ ไม่จำเป็นต้องทำตอนนี้

Slack webhook ใช้สำหรับส่ง notification เมื่อ deployment เสร็จ

**คุณสามารถข้ามส่วนนี้ได้** และทำทีหลังเมื่อต้องการ

### ถ้าอยากตั้งค่าตอนนี้:

#### ขั้นตอนที่ 3.1: สร้าง Slack App

1. ไปที่: https://api.slack.com/apps
2. คลิก **"Create New App"**
3. เลือก **"From scratch"**
4. ใส่ชื่อ app: `GitHub Actions Notifier`
5. เลือก workspace ที่ต้องการ
6. คลิก **"Create App"**

#### ขั้นตอนที่ 3.2: เปิดใช้งาน Incoming Webhooks

1. ในหน้า app settings, ดูเมนูด้านซ้าย
2. คลิก **"Incoming Webhooks"**
3. เปิด toggle **"Activate Incoming Webhooks"** (เป็น ON)
4. เลื่อนลงล่าง คลิก **"Add New Webhook to Workspace"**
5. เลือก channel ที่ต้องการส่ง notification (เช่น #general)
6. คลิก **"Allow"**

#### ขั้นตอนที่ 3.3: Copy Webhook URL

1. คุณจะเห็น **Webhook URL** แบบนี้:
   ```
   https://hooks.slack.com/services/T00000000/B00000000/XXXXXXXXXXXXXXXXXXXX
   ```
2. **Copy URL ทั้งหมด**

#### ขั้นตอนที่ 3.4: เพิ่มใน GitHub Secrets

1. ไปที่: https://github.com/srhhsshdsrdgeseedh-max/manus/settings/secrets/actions
2. คลิก "New repository secret"
3. ใส่:
   - Name: `SLACK_WEBHOOK`
   - Secret: Paste webhook URL
4. คลิก "Add secret"

---

## ✅ สรุป: Secrets ที่ต้องมี

### Minimum (ต้องมีเพื่อให้ CI/CD ทำงาน):

- ✅ `DOCKER_USERNAME` = `your-docker-username`
- ✅ `DOCKER_PASSWORD` = `dckr_pat_XXXXXXXXXX`

**ด้วย 2 secrets นี้:**
- ✅ Tests จะ run
- ✅ Security scan จะ run
- ✅ Docker images จะ build และ push ได้
- ❌ Deployment จะไม่ทำงาน (แต่ไม่เป็นไร)

### Full (ถ้าต้องการ auto-deployment):

- ✅ `DOCKER_USERNAME`
- ✅ `DOCKER_PASSWORD`
- ✅ `PROD_HOST` (IP หรือ hostname ของ production server)
- ✅ `PROD_USERNAME` (SSH username)
- ✅ `PROD_SSH_KEY` (SSH private key ทั้งหมด)
- ✅ `PROD_URL` (URL สำหรับ health check)
- ⚪ `SLACK_WEBHOOK` (optional)

---

## 🧪 ทดสอบ CI/CD

### วิธีที่ 1: ทดสอบแบบง่าย (แนะนำ)

1. ไปที่: https://github.com/srhhsshdsrdgeseedh-max/manus/actions
2. คลิกที่ workflow **"CI/CD Pipeline"**
3. คลิกปุ่ม **"Run workflow"** (ด้านขวา)
4. เลือก branch: `main`
5. คลิก **"Run workflow"** (สีเขียว)

### วิธีที่ 2: Push commit ใหม่

```bash
cd /mnt/c/projecattack/manus

# สร้าง commit ว่างๆ เพื่อ trigger CI/CD
git commit --allow-empty -m "Test CI/CD pipeline"
git push origin main
```

### ดูผลลัพธ์:

1. ไปที่: https://github.com/srhhsshdsrdgeseedh-max/manus/actions
2. คลิกที่ workflow run ล่าสุด
3. ดู logs ของแต่ละ job

**ผลที่คาดหวัง (ถ้ามีแค่ Docker secrets):**
- ✅ Test job: PASS
- ✅ Security Scan job: PASS
- ✅ Docker Build job: PASS
- ⚠️ Deploy job: SKIP (เพราะไม่มี production secrets)

---

## 🔧 Troubleshooting

### ปัญหา: Docker build ล้มเหลว

**Error:** `Error: Cannot authenticate to Docker Hub`

**แก้ไข:**
1. ตรวจสอบว่า `DOCKER_USERNAME` และ `DOCKER_PASSWORD` ถูกต้อง
2. ลองทดสอบ login ใน local:
   ```bash
   docker login -u your-docker-username
   # ใส่ password: dckr_pat_XXXXXXXXXX
   ```
3. ถ้า login ไม่ได้ = token หมดอายุ ต้องสร้างใหม่

### ปัญหา: Deployment ล้มเหลว

**Error:** `Permission denied (publickey)`

**แก้ไข:**
1. ตรวจสอบว่า public key อยู่ใน server แล้ว
2. ทดสอบ SSH connection:
   ```bash
   ssh -i github-actions-key user@server_ip
   ```
3. ตรวจสอบว่า private key ใน GitHub Secrets ถูกต้อง

### ปัญหา: Tests ล้มเหลว

**แก้ไข:**
1. ดู error logs ใน Actions tab
2. ตรวจสอบว่า dependencies ครบ
3. ลอง run tests ใน local:
   ```bash
   pytest tests/ -v
   ```

---

## 📞 ขั้นตอนถัดไป

### ถ้าคุณตั้งค่าแค่ Docker secrets (แนะนำสำหรับเริ่มต้น):

1. ✅ ตั้งค่า `DOCKER_USERNAME` และ `DOCKER_PASSWORD`
2. ✅ ทดสอบ workflow (วิธีที่ 1 ด้านบน)
3. ✅ ตรวจสอบว่า tests และ docker build ผ่าน
4. 📋 ทีหลังค่อยเพิ่ม production secrets เมื่อพร้อม deploy

### ถ้าคุณมี production server พร้อมแล้ว:

1. ✅ ตั้งค่า Docker secrets
2. ✅ Setup SSH key บน production server
3. ✅ ตั้งค่า production secrets ทั้งหมด
4. ✅ ทดสอบ full pipeline
5. ✅ Deploy to production!

---

## 🎯 Quick Reference

### ตรวจสอบ Secrets ที่ตั้งค่าแล้ว:

ไปที่: https://github.com/srhhsshdsrdgeseedh-max/manus/settings/secrets/actions

คุณควรเห็น:
- ✅ DOCKER_USERNAME
- ✅ DOCKER_PASSWORD
- (Optional) PROD_HOST
- (Optional) PROD_USERNAME
- (Optional) PROD_SSH_KEY
- (Optional) PROD_URL
- (Optional) SLACK_WEBHOOK

### ดู Workflow Runs:

https://github.com/srhhsshdsrdgeseedh-max/manus/actions

### ดู Docker Images:

https://hub.docker.com/u/your-docker-username

---

**สรุป:** เริ่มจากตั้งค่า Docker secrets ก่อน (2 ตัว) แล้วทดสอบ ส่วนอื่นค่อยทำทีหลังได้! 🚀


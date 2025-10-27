# GitHub Secrets Setup Guide for CI/CD

## 📋 Overview

ไฟล์ CI/CD workflow (`.github/workflows/ci-cd.yml`) ได้ถูก push ไปยัง GitHub เรียบร้อยแล้ว 

ตอนนี้คุณต้อง**ตั้งค่า GitHub Secrets** เพื่อให้ CI/CD pipeline ทำงานได้อย่างสมบูรณ์

---

## 🔑 Secrets ที่ต้องตั้งค่า

### 1. Docker Hub Credentials (Required for Docker Build)

| Secret Name | Description | Example |
|:---|:---|:---|
| `DOCKER_USERNAME` | Docker Hub username | `your-dockerhub-username` |
| `DOCKER_PASSWORD` | Docker Hub password or access token | `dckr_pat_xxxxx` |

**วิธีสร้าง Docker Hub Access Token:**
1. ไปที่ https://hub.docker.com/settings/security
2. คลิก "New Access Token"
3. ตั้งชื่อ: `GitHub Actions`
4. Copy token ที่ได้

### 2. Production Server Credentials (Required for Deployment)

| Secret Name | Description | Example |
|:---|:---|:---|
| `PROD_HOST` | Production server IP or hostname | `123.45.67.89` หรือ `server.example.com` |
| `PROD_USERNAME` | SSH username | `ubuntu` หรือ `root` |
| `PROD_SSH_KEY` | SSH private key (entire key) | `-----BEGIN OPENSSH PRIVATE KEY-----\n...` |
| `PROD_URL` | Production URL for health check | `https://api.example.com` |

**วิธีสร้าง SSH Key:**
```bash
# สร้าง SSH key pair
ssh-keygen -t ed25519 -C "github-actions" -f github-actions-key

# Copy public key ไปยัง production server
ssh-copy-id -i github-actions-key.pub user@server

# Copy private key content สำหรับ GitHub Secret
cat github-actions-key
```

### 3. Notification (Optional)

| Secret Name | Description | Example |
|:---|:---|:---|
| `SLACK_WEBHOOK` | Slack webhook URL for notifications | `https://hooks.slack.com/services/T00/B00/xxx` |

**วิธีสร้าง Slack Webhook:**
1. ไปที่ https://api.slack.com/apps
2. สร้าง app ใหม่หรือเลือก app ที่มีอยู่
3. เปิด "Incoming Webhooks"
4. สร้าง webhook URL ใหม่
5. Copy URL

---

## 🔧 วิธีตั้งค่า Secrets ใน GitHub

### ขั้นตอนที่ 1: เข้าสู่ Repository Settings

1. ไปที่ repository: https://github.com/srhhsshdsrdgeseedh-max/manus
2. คลิก **Settings** (ด้านบนขวา)
3. ในเมนูด้านซ้าย คลิก **Secrets and variables** → **Actions**

### ขั้นตอนที่ 2: เพิ่ม Secrets

1. คลิกปุ่ม **New repository secret**
2. ใส่ **Name** (ตามตารางด้านบน)
3. ใส่ **Value** (ค่าจริงของ secret)
4. คลิก **Add secret**
5. ทำซ้ำสำหรับทุก secret ที่ต้องการ

### ขั้นตอนที่ 3: ตรวจสอบ Secrets

หลังจากเพิ่มครบแล้ว คุณควรเห็น secrets ดังนี้:

**Required (สำหรับ Docker Build):**
- ✅ DOCKER_USERNAME
- ✅ DOCKER_PASSWORD

**Required (สำหรับ Deployment):**
- ✅ PROD_HOST
- ✅ PROD_USERNAME
- ✅ PROD_SSH_KEY
- ✅ PROD_URL

**Optional:**
- ⚪ SLACK_WEBHOOK (ถ้าต้องการ notifications)

---

## 🚀 ทดสอบ CI/CD Pipeline

### วิธีที่ 1: Push Commit ใหม่

```bash
# สร้างการเปลี่ยนแปลงเล็กน้อย
echo "# Test CI/CD" >> README.md
git add README.md
git commit -m "Test CI/CD pipeline"
git push origin main
```

### วิธีที่ 2: Manual Trigger

1. ไปที่ **Actions** tab ใน GitHub
2. เลือก workflow "CI/CD Pipeline"
3. คลิก **Run workflow**
4. เลือก branch `main`
5. คลิก **Run workflow**

### วิธีที่ 3: Create Pull Request

1. สร้าง branch ใหม่
2. ทำการเปลี่ยนแปลง
3. Push และสร้าง Pull Request
4. CI/CD จะ run ทดสอบอัตโนมัติ

---

## 📊 ดู Workflow Runs

1. ไปที่ **Actions** tab: https://github.com/srhhsshdsrdgeseedh-max/manus/actions
2. คลิกที่ workflow run ที่ต้องการดู
3. คลิกที่แต่ละ job เพื่อดู logs

**Jobs ที่จะ run:**
- ✅ **Test** - Run unit และ integration tests
- ✅ **Security Scan** - Scan vulnerabilities ด้วย Trivy และ Bandit
- ✅ **Docker Build** - Build และ push Docker images
- ✅ **Deploy** - Deploy ไปยัง production (เฉพาะ main branch)

---

## ⚠️ หมายเหตุสำคัญ

### Security Best Practices

1. **ไม่เคย commit secrets ลงใน code**
   - ใช้ GitHub Secrets เท่านั้น
   - ตรวจสอบไฟล์ก่อน commit

2. **Rotate secrets เป็นระยะ**
   - เปลี่ยน tokens และ keys เป็นประจำ
   - อัพเดทใน GitHub Secrets

3. **จำกัด permissions**
   - ใช้ read-only tokens ถ้าเป็นไปได้
   - ใช้ SSH keys ที่มี permissions จำกัด

4. **Monitor workflow runs**
   - ตรวจสอบ logs เป็นประจำ
   - ดู security alerts

### Deployment Considerations

1. **Staging Environment**
   - แนะนำให้มี staging environment ก่อน production
   - แก้ไข workflow ให้ deploy ไป staging ก่อน

2. **Rollback Plan**
   - เตรียม rollback procedure
   - เก็บ backup ก่อน deploy

3. **Health Checks**
   - ตรวจสอบว่า health check endpoint ทำงาน
   - ปรับ timeout ตามความเหมาะสม

---

## 🔍 Troubleshooting

### Docker Build ล้มเหลว

**ปัญหา:** `Error: Cannot connect to Docker daemon`

**แก้ไข:**
- ตรวจสอบ DOCKER_USERNAME และ DOCKER_PASSWORD
- ตรวจสอบว่า Docker Hub account active
- ลองสร้าง access token ใหม่

### Deployment ล้มเหลว

**ปัญหา:** `Permission denied (publickey)`

**แก้ไข:**
- ตรวจสอบว่า SSH key ถูกต้อง
- ตรวจสอบว่า public key อยู่ใน `~/.ssh/authorized_keys` บน server
- ตรวจสอบ permissions ของ SSH key

### Tests ล้มเหลว

**ปัญหา:** `ModuleNotFoundError` หรือ `ImportError`

**แก้ไข:**
- ตรวจสอบ requirements.txt
- อัพเดท dependencies
- ตรวจสอบ Python version

---

## 📞 Support

หากมีปัญหาหรือคำถาม:
- ดู workflow logs ใน Actions tab
- ตรวจสอบ GitHub Actions documentation
- ติดต่อทีมพัฒนา

---

## ✅ Checklist

ก่อนที่ CI/CD จะทำงานได้เต็มรูปแบบ ตรวจสอบว่า:

**Setup:**
- [ ] ตั้งค่า DOCKER_USERNAME
- [ ] ตั้งค่า DOCKER_PASSWORD
- [ ] ตั้งค่า PROD_HOST
- [ ] ตั้งค่า PROD_USERNAME
- [ ] ตั้งค่า PROD_SSH_KEY
- [ ] ตั้งค่า PROD_URL
- [ ] (Optional) ตั้งค่า SLACK_WEBHOOK

**Verification:**
- [ ] ทดสอบ Docker Hub login
- [ ] ทดสอบ SSH connection ไปยัง production server
- [ ] ทดสอบ health check endpoint
- [ ] Run workflow ทดสอบ
- [ ] ตรวจสอบ logs ว่าไม่มี errors

**Production Ready:**
- [ ] Staging environment พร้อม (ถ้ามี)
- [ ] Backup procedures พร้อม
- [ ] Rollback plan พร้อม
- [ ] Monitoring alerts ตั้งค่าแล้ว
- [ ] Team รับทราบ deployment process

---

**Last Updated:** October 25, 2024  
**CI/CD Status:** ✅ Workflow file pushed to GitHub  
**Next Step:** ⚙️ Configure GitHub Secrets


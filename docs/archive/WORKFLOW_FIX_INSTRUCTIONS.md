# คำแนะนำการแก้ไข GitHub Actions Workflow

เนื่องจาก GitHub App ไม่มีสิทธิ์แก้ไข workflow files โดยตรง คุณต้องแก้ไขด้วยตนเองดังนี้:

## วิธีที่ 1: แก้ไขผ่าน GitHub Web Interface (แนะนำ)

1. ไปที่ https://github.com/srhhsshdsrdgeseedh-max/manus/blob/main/.github/workflows/ci-cd.yml
2. คลิกปุ่ม Edit (ไอคอนดินสอ)
3. ทำการแก้ไขตามรายละเอียดด้านล่าง
4. Commit changes โดยตรงไปที่ main branch

## วิธีที่ 2: แก้ไขผ่าน Git CLI

```bash
# Clone repository (ถ้ายังไม่ได้ clone)
git clone https://github.com/srhhsshdsrdgeseedh-max/manus.git
cd manus

# แก้ไขไฟล์ .github/workflows/ci-cd.yml ตามรายละเอียดด้านล่าง

# Commit และ push
git add .github/workflows/ci-cd.yml
git commit -m "Fix workflow permissions"
git push origin main
```

## การแก้ไขที่ต้องทำ

### 1. เพิ่ม permissions สำหรับ security-scan job

หาบรรทัดที่ 94-96:
```yaml
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
```

เปลี่ยนเป็น:
```yaml
  security-scan:
    name: Security Scan
    runs-on: ubuntu-latest
    permissions:
      contents: read
      security-events: write
      actions: read
```

### 2. ปรับปรุง docker-build job

หาบรรทัดที่ 132-136:
```yaml
  docker-build:
    name: Build Docker Images
    runs-on: ubuntu-latest
    needs: [test]
    if: always() && needs.test.result == 'success'
```

เปลี่ยนเป็น:
```yaml
  docker-build:
    name: Build Docker Images
    runs-on: ubuntu-latest
    needs: [test]
    if: github.event_name == 'push' && github.ref == 'refs/heads/main'
    permissions:
      contents: read
      packages: write
```

### 3. แก้ไข Docker Hub login condition

หาบรรทัดที่ 145-146:
```yaml
      - name: Login to Docker Hub
        if: github.event_name != 'pull_request'
```

เปลี่ยนเป็น:
```yaml
      - name: Login to Docker Hub
        if: github.event_name != 'pull_request' && secrets.DOCKER_USERNAME != ''
```

### 4. แก้ไข backend image build

หาบรรทัดที่ 152-159:
```yaml
      - name: Build and push backend image
        if: ${{ github.event_name != 'pull_request' }}
        continue-on-error: true
        uses: docker/build-push-action@v4
        with:
          context: .
          file: ./Dockerfile
          push: ${{ github.event_name != 'pull_request' }}
```

เปลี่ยนเป็น:
```yaml
      - name: Build and push backend image
        uses: docker/build-push-action@v4
        with:
          context: .
          file: ./Dockerfile
          push: ${{ github.event_name != 'pull_request' && secrets.DOCKER_USERNAME != '' }}
```

### 5. แก้ไข frontend image build

หาบรรทัดที่ 166-173:
```yaml
      - name: Build and push frontend image
        if: ${{ github.event_name != 'pull_request' }}
        continue-on-error: true
        uses: docker/build-push-action@v4
        with:
          context: ./frontend
          file: ./frontend/Dockerfile
          push: ${{ github.event_name != 'pull_request' }}
```

เปลี่ยนเป็น:
```yaml
      - name: Build and push frontend image
        uses: docker/build-push-action@v4
        with:
          context: ./frontend
          file: ./frontend/Dockerfile
          push: ${{ github.event_name != 'pull_request' && secrets.DOCKER_USERNAME != '' }}
```

## หลังจากแก้ไขเสร็จ

1. Commit และ push การแก้ไข
2. ตรวจสอบว่า workflow รันสำเร็จที่ https://github.com/srhhsshdsrdgeseedh-max/manus/actions
3. ถ้ายังมี error เกี่ยวกับ Docker Hub ให้ตั้งค่า secrets ตามคำแนะนำใน `.github/SECRETS_SETUP.md`

## หมายเหตุ

- การแก้ไขเหล่านี้จะแก้ปัญหา:
  - ✅ Security Scan permission errors
  - ✅ Docker build optimization
  - ✅ Workflow จะไม่ล้มเหลวถ้าไม่มี Docker Hub secrets

- ไฟล์อื่นๆ ได้ถูก push ไปแล้ว:
  - ✅ frontend/package-lock.json
  - ✅ .dockerignore files
  - ✅ .gitignore updates
  - ✅ .github/SECRETS_SETUP.md

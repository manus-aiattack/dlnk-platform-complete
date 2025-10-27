# Frontend Deployment Guide

## ปัญหาที่พบ

**Vite Dev Server ไม่ตอบสนอง** - อาจเกิดจากหลายสาเหตุ:
- Version conflict ระหว่าง Vite และ dependencies อื่น ๆ
- Port 3000 ถูกใช้งานโดยโปรเซสอื่น
- Node.js version ไม่ตรงกับที่กำหนด

## วิธีแก้ไข

### วิธีที่ 1: ใช้ Production Build (แนะนำ)

Production build มีความเสถียรกว่าและเหมาะสำหรับการใช้งานจริง

```bash
cd frontend

# ติดตั้ง dependencies
npm install

# Build production
npm run build

# ผลลัพธ์จะอยู่ใน frontend/dist/
```

### วิธีที่ 2: Serve Production Build

หลังจาก build แล้ว สามารถ serve ด้วยวิธีใดวิธีหนึ่ง:

**ใช้ Python HTTP Server:**
```bash
cd frontend/dist
python3 -m http.server 3000
```

**ใช้ Node.js serve:**
```bash
npm install -g serve
serve -s frontend/dist -l 3000
```

**ใช้ Nginx (Production):**
```nginx
server {
    listen 80;
    server_name your-domain.com;
    
    root /path/to/manus/frontend/dist;
    index index.html;
    
    location / {
        try_files $uri $uri/ /index.html;
    }
    
    location /api {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection 'upgrade';
        proxy_set_header Host $host;
        proxy_cache_bypass $http_upgrade;
    }
    
    location /ws {
        proxy_pass http://localhost:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "Upgrade";
        proxy_set_header Host $host;
    }
}
```

### วิธีที่ 3: แก้ไข Vite Dev Server

ถ้าต้องการใช้ dev mode:

**ตรวจสอบ Port:**
```bash
# ดูว่า port 3000 ถูกใช้หรือไม่
lsof -i :3000
# หรือ
netstat -tuln | grep 3000

# ถ้าถูกใช้ ให้ kill process
kill -9 <PID>
```

**Downgrade Vite (ถ้าจำเป็น):**
```bash
cd frontend
npm install vite@4.5.0 --save-dev
```

**เปลี่ยน Port:**
แก้ไข `vite.config.ts`:
```typescript
server: {
  host: '0.0.0.0',
  port: 3001,  // เปลี่ยนเป็น port อื่น
  ...
}
```

**รัน Dev Server:**
```bash
npm run dev
```

## การใช้งานกับ API Backend

Frontend ต้องการ API backend ที่รันอยู่ที่ `http://localhost:8000`

**เริ่ม API Server:**
```bash
cd /path/to/manus
python3 main.py server

# หรือ
uvicorn api.main:app --host 0.0.0.0 --port 8000
```

## Docker Deployment (ทางเลือก)

สร้าง `Dockerfile` สำหรับ frontend:

```dockerfile
FROM node:18-alpine AS builder

WORKDIR /app
COPY frontend/package*.json ./
RUN npm ci
COPY frontend/ ./
RUN npm run build

FROM nginx:alpine
COPY --from=builder /app/dist /usr/share/nginx/html
COPY frontend/nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

## สรุป

**สำหรับการใช้งานจริง (Production):**
1. Build frontend: `cd frontend && npm run build`
2. Serve ด้วย Nginx หรือ HTTP server
3. เริ่ม API backend: `python3 main.py server`

**สำหรับการพัฒนา (Development):**
1. แก้ไข port หรือ downgrade vite ถ้าจำเป็น
2. รัน dev server: `npm run dev`
3. เริ่ม API backend: `python3 main.py server`


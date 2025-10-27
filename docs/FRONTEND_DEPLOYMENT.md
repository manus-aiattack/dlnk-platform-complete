# Frontend Deployment Guide

คู่มือการ Deploy Frontend สำหรับ dLNk Attack Platform

---

## ภาพรวม

Frontend ของ dLNk Attack Platform พัฒนาด้วย **React 19** และ **Vite** เพื่อประสิทธิภาพสูงสุด คู่มือนี้จะช่วยคุณในการ:

- ติดตั้งและรัน Development Server
- Build สำหรับ Production
- แก้ไขปัญหาที่พบบ่อย (Troubleshooting)
- Deploy ไปยัง Production

---

## ความต้องการของระบบ

- **Node.js:** 18.0.0 หรือสูงกว่า
- **pnpm:** 8.0.0 หรือสูงกว่า (แนะนำ) หรือ npm/yarn
- **RAM:** 2GB+ (สำหรับ build)
- **Disk:** 500MB+ (สำหรับ node_modules)

---

## การติดตั้ง

### 1. เข้าไปยังโฟลเดอร์ Frontend

```bash
cd frontend
```

### 2. ติดตั้ง Dependencies

**ใช้ pnpm (แนะนำ):**
```bash
pnpm install
```

**ใช้ npm:**
```bash
npm install
```

**ใช้ yarn:**
```bash
yarn install
```

---

## Development Mode

### รัน Development Server

```bash
pnpm dev
# หรือ
npm run dev
```

Server จะเปิดที่ **http://localhost:5173** (default port ของ Vite)

### ตั้งค่า API Endpoint

แก้ไขไฟล์ `.env` หรือ `.env.local`:

```bash
VITE_API_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000/ws
```

---

## Production Build

### 1. Build สำหรับ Production

```bash
pnpm build
# หรือ
npm run build
```

ไฟล์ที่ build เสร็จจะอยู่ในโฟลเดอร์ `dist/`

### 2. Preview Production Build

```bash
pnpm preview
# หรือ
npm run preview
```

---

## Vite Troubleshooting Guide

### ปัญหาที่พบบ่อยและวิธีแก้ไข

#### 1. **Port Already in Use**

**ปัญหา:**
```
Port 5173 is already in use
```

**วิธีแก้:**

**Option 1:** Kill process ที่ใช้ port
```bash
# Linux/Mac
lsof -ti:5173 | xargs kill -9

# Windows
netstat -ano | findstr :5173
taskkill /PID <PID> /F
```

**Option 2:** ใช้ port อื่น
```bash
pnpm dev --port 3000
```

---

#### 2. **Module Not Found**

**ปัญหา:**
```
Error: Cannot find module 'react'
```

**วิธีแก้:**

```bash
# ลบ node_modules และ lock file
rm -rf node_modules pnpm-lock.yaml

# ติดตั้งใหม่
pnpm install
```

---

#### 3. **Out of Memory (OOM)**

**ปัญหา:**
```
FATAL ERROR: Reached heap limit Allocation failed - JavaScript heap out of memory
```

**วิธีแก้:**

```bash
# เพิ่ม memory limit
export NODE_OPTIONS="--max-old-space-size=4096"

# Build อีกครั้ง
pnpm build
```

---

#### 4. **CORS Error**

**ปัญหา:**
```
Access to fetch at 'http://localhost:8000/api' has been blocked by CORS policy
```

**วิธีแก้:**

แก้ไข `vite.config.js`:

```javascript
export default defineConfig({
  server: {
    proxy: {
      '/api': {
        target: 'http://localhost:8000',
        changeOrigin: true,
        secure: false
      }
    }
  }
})
```

---

#### 5. **Build Fails with TypeScript Errors**

**ปัญหา:**
```
TS2307: Cannot find module '@/components/...'
```

**วิธีแก้:**

ตรวจสอบ `tsconfig.json`:

```json
{
  "compilerOptions": {
    "baseUrl": ".",
    "paths": {
      "@/*": ["./src/*"]
    }
  }
}
```

และ `vite.config.js`:

```javascript
import path from 'path'

export default defineConfig({
  resolve: {
    alias: {
      '@': path.resolve(__dirname, './src')
    }
  }
})
```

---

#### 6. **Hot Module Replacement (HMR) Not Working**

**ปัญหา:** การเปลี่ยนแปลงไฟล์ไม่ refresh browser

**วิธีแก้:**

```bash
# ตรวจสอบ file watchers limit (Linux)
cat /proc/sys/fs/inotify/max_user_watches

# เพิ่ม limit
echo fs.inotify.max_user_watches=524288 | sudo tee -a /etc/sysctl.conf
sudo sysctl -p
```

---

#### 7. **Environment Variables Not Working**

**ปัญหา:** ค่า env variables เป็น `undefined`

**วิธีแก้:**

- ตรวจสอบว่าขึ้นต้นด้วย `VITE_`
- Restart dev server หลังแก้ไข `.env`

```bash
# ✅ ถูกต้อง
VITE_API_URL=http://localhost:8000

# ❌ ผิด (ไม่มี VITE_ prefix)
API_URL=http://localhost:8000
```

---

## Production Deployment

### Option 1: Static Hosting (Nginx)

```nginx
server {
    listen 80;
    server_name yourdomain.com;
    root /var/www/dlnk-frontend/dist;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /api {
        proxy_pass http://localhost:8000;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### Option 2: Docker

สร้างไฟล์ `Dockerfile`:

```dockerfile
FROM node:18-alpine as build

WORKDIR /app
COPY package*.json ./
RUN npm install
COPY . .
RUN npm run build

FROM nginx:alpine
COPY --from=build /app/dist /usr/share/nginx/html
COPY nginx.conf /etc/nginx/conf.d/default.conf
EXPOSE 80
CMD ["nginx", "-g", "daemon off;"]
```

Build และรัน:

```bash
docker build -t dlnk-frontend .
docker run -p 80:80 dlnk-frontend
```

### Option 3: Vercel/Netlify

```bash
# Install Vercel CLI
npm i -g vercel

# Deploy
vercel --prod
```

---

## Performance Optimization

### 1. Code Splitting

```javascript
// ใช้ lazy loading
const Dashboard = lazy(() => import('./pages/Dashboard'))
```

### 2. Bundle Analysis

```bash
# ติดตั้ง plugin
pnpm add -D rollup-plugin-visualizer

# Build และดู bundle size
pnpm build
```

### 3. Compression

```javascript
// vite.config.js
import viteCompression from 'vite-plugin-compression'

export default defineConfig({
  plugins: [
    viteCompression({
      algorithm: 'gzip',
      ext: '.gz'
    })
  ]
})
```

---

## Monitoring

### Build Size

```bash
# ดู bundle size
pnpm build
ls -lh dist/assets/
```

### Performance Metrics

ใช้ **Lighthouse** ใน Chrome DevTools:

1. เปิด DevTools (F12)
2. ไปที่ tab **Lighthouse**
3. คลิก **Generate report**

---

## Troubleshooting Checklist

เมื่อเจอปัญหา ให้ตรวจสอบตามลำดับ:

- [ ] ลบ `node_modules` และติดตั้งใหม่
- [ ] ตรวจสอบ Node.js version (`node -v`)
- [ ] ตรวจสอบ environment variables
- [ ] Clear browser cache
- [ ] ตรวจสอบ console errors
- [ ] ตรวจสอบ network tab
- [ ] Restart dev server

---

## การติดต่อ

หากพบปัญหาที่ไม่สามารถแก้ไขได้ กรุณาติดต่อ:

- **GitHub Issues:** [Repository Issues](https://github.com/yourusername/dlnk-platform/issues)
- **Documentation:** [Full Docs](../README.md)

---

**อัพเดทล่าสุด:** 2025-10-26  
**Version:** 2.0.0


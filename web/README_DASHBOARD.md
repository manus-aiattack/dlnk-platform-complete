# dLNk HACK Dashboard

Modern web interface for the dLNk Predator Framework with dLNk HACK branding.

## Features

✨ **Beautiful UI/UX**
- Gemini-inspired design
- Dark theme with neon accents
- Responsive layout
- Smooth animations

🎯 **6 Main Functions**
1. **ลิ้งเป้าหมาย** - Target specification and reconnaissance
2. **ZERODAY (นาน)** - Zero-day vulnerability hunting
3. **โจมตี CVE ทั้งหมด** - CVE-based attacks
4. **ความสามารถทั้งหมด** - Full 62+ agents capabilities
5. **อัตโนมัติทั้งหมด 100%** - Fully automated AI-driven attacks
6. **สร้างคีย์ (admin)** - API key generation

🔐 **Security**
- API key authentication
- Session management
- Secure forms

## Quick Start

### Method 1: Python HTTP Server (Recommended)

```bash
cd web
python3 server.py
```

Then open: http://localhost:8080/dashboard_dlnk.html

### Method 2: Direct File Access

Simply double-click `dashboard_dlnk.html` to open in your browser.

### Method 3: Integrate with Framework

Add to your main API server:

```python
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

app = FastAPI()
app.mount("/dashboard", StaticFiles(directory="web"), name="dashboard")
```

## Default Credentials

**API Key:** Any non-empty string (for demo)

In production, integrate with the License Service:
- `DLNK-TRIAL-xxxxx` - Trial license
- `DLNK-BASIC-xxxxx` - Basic license
- `DLNK-PRO-xxxxx` - Professional license
- `DLNK-ENT-xxxxx` - Enterprise license

## Screenshots

### Login Screen
- ASCII art logo "dLNk HACK"
- API key input
- Clean authentication

### Main Dashboard
- 6 action cards
- Tips section
- Status indicators
- Modern layout

### Modal Forms
- Target specification
- Zero-day hunting
- CVE attacks
- Full capabilities
- Auto mode
- Key generation

## Customization

### Change Colors

Edit the CSS variables in `dashboard_dlnk.html`:

```css
/* Primary color (green) */
#00ff88

/* Background colors */
#0a0e27 (dark blue)
#1a1f3a (lighter blue)

/* Accent colors */
#ff3b30 (red for logout)
#ff9800 (orange for warnings)
```

### Change Logo

Replace the ASCII art in the `.logo-ascii` section:

```html
<div class="logo-ascii">
    YOUR ASCII ART HERE
</div>
```

### Add More Functions

1. Add a new action card in the `.action-grid`
2. Create a corresponding modal
3. Add form submission handler

## Integration with Backend

### API Endpoints

The dashboard expects these endpoints:

```
POST /api/attack/target
POST /api/attack/zeroday
POST /api/attack/cve
POST /api/attack/full
POST /api/attack/auto
POST /api/license/generate
```

### Example Integration

```javascript
async function submitTarget(e) {
    e.preventDefault();
    const formData = new FormData(e.target);
    
    const response = await fetch('/api/attack/target', {
        method: 'POST',
        headers: {
            'Authorization': `Bearer ${localStorage.getItem('apiKey')}`,
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({
            target: formData.get('target'),
            attack_type: formData.get('attack_type')
        })
    });
    
    const result = await response.json();
    console.log(result);
}
```

## Browser Compatibility

✅ Chrome/Edge (Recommended)
✅ Firefox
✅ Safari
⚠️ IE11 (Not supported)

## Mobile Support

The dashboard is fully responsive and works on:
- 📱 Mobile phones
- 📱 Tablets
- 💻 Laptops
- 🖥️ Desktops

## Tips

1. **API Key Storage**: Keys are stored in localStorage
2. **Session Persistence**: Login persists across page reloads
3. **Modal Shortcuts**: Click outside modal to close
4. **Form Validation**: All forms have built-in validation

## Troubleshooting

### Dashboard won't load
- Check if the file path is correct
- Try using the Python server method
- Check browser console for errors

### API Key not working
- Make sure you're using a valid key format
- Check if the License Service is running
- Verify the key hasn't expired

### Forms not submitting
- Check browser console for errors
- Verify API endpoints are accessible
- Check CORS settings if using separate backend

## Production Deployment

### 1. Enable HTTPS

```bash
# Use nginx as reverse proxy
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://localhost:8080;
    }
}
```

### 2. Configure API Backend

Update the API endpoints in the JavaScript code to point to your production API.

### 3. Set Up Authentication

Integrate with your License Service for proper API key validation.

## License

Part of the dLNk Predator Framework - Enterprise Edition

---

**Created by:** dLNk HACK Team
**Version:** 1.0.0
**Last Updated:** 2024-10-22

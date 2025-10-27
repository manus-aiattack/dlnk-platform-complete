#!/usr/bin/env python3
"""
dLNk HACK Dashboard Server
Simple HTTP server for the web dashboard
"""
import http.server
import socketserver
import os

PORT = 8080
DIRECTORY = os.path.dirname(os.path.abspath(__file__))

class MyHTTPRequestHandler(http.server.SimpleHTTPRequestHandler):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, directory=DIRECTORY, **kwargs)
    
    def end_headers(self):
        self.send_header('Cache-Control', 'no-store, no-cache, must-revalidate')
        self.send_header('Expires', '0')
        super().end_headers()

if __name__ == '__main__':
    with socketserver.TCPServer(("", PORT), MyHTTPRequestHandler) as httpd:
        print(f"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║              dLNk HACK Dashboard Server                      ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝

🚀 Server started successfully!

📍 Access the dashboard at:
   → http://localhost:{PORT}/dashboard_dlnk.html

🔑 Default API Key: DLNK-DEMO-KEY-12345

⚠️  Press Ctrl+C to stop the server

""")
        try:
            httpd.serve_forever()
        except KeyboardInterrupt:
            print("\n\n✅ Server stopped.")

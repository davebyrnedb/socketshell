import asyncio
import websockets
import os
import sys
import pty
import json
import termios
import fcntl
import struct
import socket
import signal
import warnings
import datetime
import time
import platform
import hashlib
import shutil
import argparse

##vars
SERVER_URL = "wss://[CONTROLLER_ADDRESS]:[PORT]/agent"
TOKEN_PATH = "/etc/socketshell/agent.token"
GUID_PATH = "/etc/socketshell/agent.guid"
PID_PATH = "/etc/socketshell/agent.pid"
SHELL_START_DIR = None

###################################
### DO NOT EDIT BELOW THIS LINE ###
AGENT_VER = "1.0.0"
START_DIR = SHELL_START_DIR or os.path.expanduser("~")

##env
warnings.filterwarnings("ignore", category=DeprecationWarning)

##upload session vars
uploading_file = None
uploading_path = None
uploading_fp = None
uploading_md5 = None
upload_chunk_index = 0

##daemonize
def daemonize():
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)

    sys.stdin.flush()
    sys.stdout.flush()
    sys.stderr.flush()

    with open('/dev/null', 'rb', 0) as f:
        os.dup2(f.fileno(), sys.stdin.fileno())
    with open('/dev/null', 'ab', 0) as f:
        os.dup2(f.fileno(), sys.stdout.fileno())
        os.dup2(f.fileno(), sys.stderr.fileno())

    with open(PID_PATH, "w") as f:
        f.write(str(os.getpid()))

##logger
def init_logger(name="agent"):
    log_path = f"/etc/socketshell/logs/{name}.log"

    def log(*args, console=False):
        timestamp = datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        msg = f"[{timestamp}] [{name.upper()}] " + " ".join(str(a) for a in args)

        try:
            os.makedirs("/etc/socketshell/logs", exist_ok=True)
            with open(log_path, "a") as f:
                f.write(msg + "\n")
        except Exception as e:
            print(f"[{timestamp}] [{name.upper()}] [!] Logging failure: {e}", file=sys.stderr)

        if console:
            print(msg)

    return log

##load registration token from disk
def load_saved_token():
    try:
        with open(TOKEN_PATH, "r") as f:
            return f.read().strip()
    except:
        return None

##collect agent system metadata
def collect_system_metadata():
    try:
        metadata = {
            "os": "Unknown",
            "kernel": f"{platform.release()} {platform.machine()}",
            "cpu_cores": os.cpu_count() or 'N/A',
        }

        try:
            with open("/etc/os-release") as f:
                for line in f:
                    if line.startswith("PRETTY_NAME="):
                        metadata["os"] = line.strip().split("=")[1].strip('"')
                        break
        except:
            pass

        try:
            ram_bytes = os.sysconf('SC_PAGE_SIZE') * os.sysconf('SC_PHYS_PAGES')
            metadata["ram_gb"] = round(ram_bytes / (1024 ** 3), 1)
        except:
            metadata["ram_gb"] = 'N/A'
        try:
            total, used, free = shutil.disk_usage("/")
            metadata["disk_root_gb"] = {
                "total": round(total / (1024**3), 1),
                "used": round(used / (1024**3), 1),
                "free": round(free / (1024**3), 1)
            }
        except:
            metadata["disk_root_gb"] = {}

        metadata["uptime"] = get_uptime()
        metadata["version"] = AGENT_VER
        return metadata
    except Exception as e:
        log(f"[!] [ERROR] Failed to collect system metadata: {e}")
        return {}

##return formatted uptime
def get_uptime():
    try:
        with open("/proc/uptime") as f:
            seconds = float(f.readline().split()[0])
            mins, secs = divmod(int(seconds), 60)
            hours, mins = divmod(mins, 60)
            days, hours = divmod(hours, 24)
            parts = []
            if days > 0: parts.append(f"{days}d")
            if hours > 0: parts.append(f"{hours}h")
            if mins > 0: parts.append(f"{mins}m")
            return ' '.join(parts) or f"{int(seconds)}s"
    except:
        return "N/A"

##first time registration flow
async def exec_registration_flow(registration_token):
    if not args.force_register and os.path.exists(TOKEN_PATH) and os.path.exists(GUID_PATH):
        log("[REG] Agent already appears to be registered. Aborting. Use --force-register to override.", console=True)
        return

    hostname = os.uname().nodename
    metadata = collect_system_metadata()

    payload = {
        "type": "register_request",
        "registration_token": registration_token,
        "ip_local": get_local_ip(),
        "hostname": hostname,
        "metadata": metadata
    }

    try:
        async with websockets.connect(SERVER_URL, ping_interval=None, ping_timeout=None) as ws:
            await ws.send(json.dumps(payload))
            log("[REG] Registration request sent to controller")

            try:
                response = await ws.recv()
                resp = json.loads(response)
                if resp.get("type") == "register_approved":
                    checkin_token = resp.get("checkin_token")
                    if checkin_token:
                        log(f"[REG] Registration approved! Token: {checkin_token}", console=True)
                        try:
                            os.makedirs(os.path.dirname(TOKEN_PATH), exist_ok=True)
                            with open(TOKEN_PATH, "w") as f:
                                f.write(checkin_token)
                            log(f"[REG] Agent check-in token saved to {TOKEN_PATH}")
                        except Exception as e:
                            log(f"[REG] Error saving agent check-in token to {TOKEN_PATH}: {e}")
                        guid = resp.get("guid")
                        if guid:
                            try:
                                os.makedirs(os.path.dirname(GUID_PATH), exist_ok=True)
                                with open(GUID_PATH, "w") as f:
                                    f.write(guid)
                                log(f"[REG] Controller-assigned GUID: {guid} saved to {GUID_PATH}")
                            except Exception as e:
                                log(f"[REG] Error saving agent GUID: {e}")
                else:
                    log("[REG] Registration failed, rejected or unexpected response recieved from controller", console=True)
            except Exception as e:
                log(f"[REG] Error during registration: {e}", console=True)
    except (ConnectionRefusedError, ConnectionResetError, OSError) as e:
        log(f"[REG] Could not connect to controller at {SERVER_URL}: {str(e) or type(e).__name__}", console=True)

##push metadata updates to controller
async def push_metadata_updates(ws):
    while True:
        try:
            await asyncio.sleep(60)
            updated_meta = collect_system_metadata()
            await ws.send(json.dumps({
                "type": "metadata_update",
                "metadata": updated_meta
            }))
            log("[o] Metadata update sent to controller")
        except Exception as e:
            log(f"[!] Failed to send metadata update: {e}")
            break

##agent run flow checkin
async def exec_run_flow(token):
    try:
        with open(GUID_PATH, "r") as f:
            agent_guid = f.read().strip()
    except Exception as e:
        log(f"[RUN] Error: Could not read agent GUID from {GUID_PATH}: {e}", console=True)
        return

    backoff = 5

    if not token:
        token = load_saved_token()
        if not token:
            log("[RUN] Error: No token provided and no saved token found", console=True)
            return

    while True:
        try:
            log(f"[o] Attempting to connect to {SERVER_URL}")
            async with websockets.connect(SERVER_URL, ping_interval=None, ping_timeout=None) as ws:
                log("[o] Connected to controller OK!")
                await ws.send(json.dumps({
                    "type": "checkin",
                    "checkin_token": token,
                    "guid": agent_guid,
                    "ip_local": get_local_ip(),
                    "hostname": os.uname().nodename,
                    "metadata": collect_system_metadata()
                }))
                response = await ws.recv()
                resp = json.loads(response)

                if resp.get("type") == "checkin_accepted":
                    log("[o] Check-in successful. Starting agent loop...")
                    backoff = 5
                    await agent_main_loop(ws, agent_guid)
                else:
                    log("[!] Error: Check-in rejected by controller.", console=True)
        except Exception as e:
            log(f"[!] Error: General connection error: {e}", console=True)

        log(f"[o] Reconnecting in {backoff} seconds...")
        await asyncio.sleep(backoff)
        backoff = min(backoff * 2, 60)

##main agent loop after run_flow
async def agent_main_loop(ws, agent_guid):
    heartbeat = {"last": time.time()}

    while True:
        log("Spawning bash PTY...")
        try:
            os.chdir(START_DIR)
            log(f"Changed working directory to {START_DIR}")
        except Exception as e:
            log(f"[!] Failed to change shell start directory: {e}")
        master_fd, slave_fd = pty.openpty()
        bash_pid = os.fork()

        if bash_pid == 0:
            os.setsid()
            os.dup2(slave_fd, 0)
            os.dup2(slave_fd, 1)
            os.dup2(slave_fd, 2)
            if hasattr(termios, 'TIOCSCTTY'):
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)
            os.environ['TERM'] = 'xterm'
            os.execvp("/bin/bash", ["/bin/bash", "-i"])
        else:
            os.close(slave_fd)
            log("Initializing components...")
            async def read_from_pty():
                log("Initialized read_from_pty")
                loop = asyncio.get_running_loop()
                while True:
                    try:
                        data = await loop.run_in_executor(None, os.read, master_fd, 1024)
                        if not data:
                            break
                        await ws.send(json.dumps({
                            "type": "output",
                            "data": data.decode(errors="ignore")
                        }))
                    except Exception as e:
                        log(f"[!] Error: Read PTY error: {e}")
                        break

            async def recv_input():
                log("Initialized recv_input")
                try:
                    async for message in ws:
                        heartbeat["last"] = time.time()
                        if isinstance(message, bytes):
                            await handle_upload_chunk(ws, message)
                            continue

                        payload = json.loads(message)
                        if payload.get("type") == "input":
                            os.write(master_fd, payload.get("data").encode())
                        elif payload.get("type") == "signal":
                            if payload.get("signal") == "interrupt":
                                os.killpg(os.getpgid(bash_pid), 2)
                            elif payload.get("signal") == "disconnect_cleanup":
                                log("SIGNAL: disconnect_cleanup")
                                os.killpg(os.getpgid(bash_pid), signal.SIGKILL)
                        elif payload.get("type") == "resize":
                            cols = payload.get("cols", 80)
                            rows = payload.get("rows", 24)
                            winsize = struct.pack("HHHH", rows, cols, 0, 0)
                            fcntl.ioctl(master_fd, termios.TIOCSWINSZ, winsize)
                        elif payload.get("type") == "list_dir":
                            await handle_list_dir(ws, payload)
                        elif payload.get("type") == "upload_start":
                            log(f"Received upload_start for {payload.get('filename')}")
                            await start_file_upload(ws, payload)
                        elif payload.get("type") == "upload_done":
                            await finish_file_upload(ws, payload)
                        elif payload.get("type") == "download_file":
                            log(f"Download request received for: {payload.get('path')}")
                            asyncio.create_task(handle_download_file(ws, payload))
                except Exception as e:
                    log(f"[!] Error: recv_input error: {e}")

            async def monitor_ws():
                log("Initialized monitor_ws")
                while True:
                    now = time.time()
                    if ws.closed:
                        log("Websocket closed, forcing bash cleanup.")
                        os.killpg(os.getpgid(bash_pid), signal.SIGKILL)
                        break
                    if now - heartbeat["last"] > 5:
                        log("No heartbeat from controller in 5 seconds, forcing bash cleanup.")
                        os.killpg(os.getpgid(bash_pid), signal.SIGKILL)
                        break
                    await asyncio.sleep(1)

            pty_task = asyncio.create_task(read_from_pty())
            recv_task = asyncio.create_task(recv_input())
            monitor_task = asyncio.create_task(monitor_ws())
            metadata_task = asyncio.create_task(push_metadata_updates(ws))

            done, pending = await asyncio.wait(
                [pty_task, recv_task, monitor_task, metadata_task],
                return_when=asyncio.FIRST_COMPLETED
            )

            for task in pending:
                task.cancel()
                try:
                    await task
                except:
                    pass

            try:
                os.killpg(os.getpgid(bash_pid), signal.SIGKILL)
            except:
                pass

            os.close(master_fd)

            await ws.send(json.dumps({
                "type": "output",
                "data": "\r\n[!] Shell exited or connection lost. Restarting session...\r\n"
            }))

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

async def handle_list_dir(ws, payload):
    path = payload.get("path", ".")
    try:
        entries = sorted(os.listdir(path))
        files = [{"name": entry, "is_dir": os.path.isdir(os.path.join(path, entry))} for entry in entries]
        await ws.send(json.dumps({"type": "dir_listing", "path": path, "entries": files}))
    except Exception as e:
        await ws.send(json.dumps({"type": "dir_listing", "path": path, "error": str(e)}))

##download file handler
async def handle_download_file(ws, payload):
    path = payload.get("path", "")
    if not os.path.isfile(path):
        await ws.send(json.dumps({
            "type": "file_download",
            "filename": os.path.basename(path),
            "error": "File not found."
        }))
        return

    try:
        chunk_size = 512 * 1024
        total_size = os.path.getsize(path)
        total_parts = (total_size + chunk_size - 1) // chunk_size
        filename = os.path.basename(path)

        with open(path, "rb") as f:
            for index in range(total_parts):
                chunk = f.read(chunk_size)
                import base64
                encoded = base64.b64encode(chunk).decode()

                await ws.send(json.dumps({
                    "type": "file_chunk",
                    "filename": filename,
                    "index": index,
                    "total": total_parts,
                    "data": encoded
                }))

                if index % 4 == 0:
                    await asyncio.sleep(0)

        await ws.send(json.dumps({
            "type": "file_done",
            "filename": filename
        }))

    except Exception as e:
        await ws.send(json.dumps({
            "type": "file_download",
            "filename": os.path.basename(path),
            "error": str(e)
        }))

async def start_file_upload(ws, payload):
    global uploading_file, uploading_path, uploading_fp, uploading_md5, upload_chunk_index
    try:
        upload_chunk_index = 0

        uploading_path = payload.get("path", "/")
        uploading_file = payload.get("filename", "upload.dat")
        full_path = os.path.join(uploading_path, uploading_file)
        os.makedirs(os.path.dirname(full_path), exist_ok=True)
        uploading_fp = open(full_path, "wb")

        uploading_md5 = hashlib.md5()

        await ws.send(json.dumps({
            "type": "upload_ack",
            "filename": uploading_file
        }))
        log(f"Upload initialized: {uploading_file} → {full_path}")
    except Exception as e:
        log(f"[!] Failed to init upload: {e}")

async def handle_upload_chunk(ws, chunk):
    global uploading_fp, uploading_md5, upload_chunk_index

    log(f"Received binary upload chunk, index: {upload_chunk_index + 1}")

    if uploading_fp and uploading_md5:
        try:
            uploading_fp.write(chunk)
            uploading_md5.update(chunk)
            upload_chunk_index += 1
            await ws.send(json.dumps({
                "type": "upload_chunk_ack",
                "index": upload_chunk_index
            }))
        except Exception as e:
            log(f"[!] Error writing upload chunk: {e}")
    else:
        log("[!] Upload chunk received before upload_start.")

async def finish_file_upload(ws, payload):
    global uploading_fp, uploading_md5, uploading_file
    if uploading_fp:
        try:
            uploading_fp.flush()
            uploading_fp.close()
            md5_hash = uploading_md5.hexdigest() if uploading_md5 else "unknown"

            await ws.send(json.dumps({
                "type": "upload_complete",
                "filename": uploading_file,
                "md5": md5_hash
            }))
            log(f"[+] Upload complete: {uploading_file}, MD5: {md5_hash}")
        except Exception as e:
            log(f"[!] Error finalizing upload: {e}")
        finally:
            uploading_fp = None
            uploading_md5 = None

if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SocketShell Agent – Remote Linux Shell Agent",
        epilog="Examples:\n\nRegister a new agent, with the controllers secret key:\n  ./agent --register --registration_token=MySecret\n\nRun the agent:\n  ./agent --run\n\n",
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--register', action='store_true', help="Register this agent with the controller. Requires --registration_token.")
    parser.add_argument('--run', action='store_true', help="Run agent, connect to controller and initiate remote shell.")
    parser.add_argument('--registration_token', type=str, help="Secret key defined in controller. One-time token used during registration to generate check-in token")
    parser.add_argument('--token', type=str, help="Explicitly provide check-in token instead of reading from default path (/etc/socketshell/agent.token)")
    parser.add_argument('--force-register', action='store_true', help="Force registration even if token/guid already exist")
    parser.add_argument('--stop', action='store_true', help='Stop the running daemonized daemon')
    args = parser.parse_args()

    log = init_logger(name="agent")

    ##daemonize in --run mode
    if args.run:
        log("SocketShell agent starting...", console=True)
        log("Review logs at /etc/socketshell/logs/agent.log for agent activity!", console=True)
        daemonize()

    if args.stop:
        try:
            with open(PID_PATH, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)
            print(f"Stopped agent daemon (PID {pid})")
            os.remove(PID_PATH)
        except Exception as e:
            print(f"Failed to stop agent: {e}")
        sys.exit(0)


    async def main():
        if args.register:
            await exec_registration_flow(args.registration_token)
        elif args.run:
            await exec_run_flow(args.token)
        else:
            print("Error: Must specify --register or --run")

    asyncio.run(main())

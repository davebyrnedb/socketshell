import signal
import datetime
import asyncio
import websockets
import json
import uuid
import time
import ssl
import hashlib
import argparse
import sys
import os

##vars
SECRET_TOKEN = "YOUR-SECRET-KEY"
USE_SSL = True
SSL_PORT = 4434
NON_SSL_PORT = 8084
CERT_PEM_PATH = "/path/to/cert.pem"
CERT_KEY_PATH = "/path/to/key.pem"
PID_PATH = "/etc/socketshell/controller.pid"
WHITELIST_PATH = "agent_whitelist.json"

##registers
agents = {}
sessions = {}
agent_sessions = {}

##args
parser = argparse.ArgumentParser()
parser.add_argument("--allow-temporary", action="store_true", help="Allow non-whitelisted agents to check in temporarily")
parser.add_argument("--stop", action="store_true", help="Stop the running daemonized controller")
args = parser.parse_args()

##logger
def init_logger(name="controller"):
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

log = init_logger(name="controller")

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

##agent keepalive
async def ping_agent_periodically(agent_id, websocket):
    try:
        while True:
            await asyncio.sleep(3)
            if websocket.closed:
                break
            await websocket.send(json.dumps({"type": "ping"}))
    except Exception as e:
        log(f"[!] Ping to agent {agent_id} failed or agent disconnected: {e}")

##forward payload to browser session mapped to agent_id
async def forward_to_browser(agent_id, payload):
    browser_ws = agent_sessions.get(agent_id)
    if browser_ws:
        try:
            await browser_ws.send(json.dumps(payload))
            return True
        except Exception as e:
            log(f"[!] Failed to forward {payload.get('type')} to browser: {e}")
    return False

##agent controller endpoint
async def handle_agent(websocket, path):
    log(f"[o] New inbound agent connection from {websocket.remote_address}")
    agent_id = None

    def load_whitelist():
        try:
            with open("agent_whitelist.json", "r") as f:
                return json.load(f)
        except:
            return {}

    def save_whitelist(data):
        with open("agent_whitelist.json", "w") as f:
            json.dump(data, f, indent=2)

    try:
        async for message in websocket:
            if isinstance(message, bytes):
                browser_ws = agent_sessions.get(agent_id)
                if browser_ws:
                    await browser_ws.send(message)
                continue

            payload = json.loads(message)

            if not agent_id:
                if payload.get("type") == "register_request":
                    log(f"[REG] Agent registration request recieved")
                    if payload.get("registration_token") != SECRET_TOKEN:
                        log("[!] Invalid registration token!")
                        await websocket.send(json.dumps({"type": "register_failed"}))
                        await websocket.close()
                        return

                    generated_guid = str(uuid.uuid4())
                    hostname = payload.get("hostname", "unknown")
                    ip_local = payload.get("ip_local", "unknown")
                    ip_remote = websocket.remote_address[0]
                    checkin_token = hashlib.sha256((generated_guid + hostname + SECRET_TOKEN).encode()).hexdigest()
                    whitelist = load_whitelist()

                    whitelist[generated_guid] = {
                        "hostname": hostname,
                        "checkin_token": checkin_token,
                        "ip_local": ip_local,
                        "ip_remote": ip_remote,
                        "registered_at": datetime.datetime.now(datetime.timezone.utc).isoformat()
                    }
                    save_whitelist(whitelist)
                    log(f"[R] Agent {hostname} added to whitelist as {generated_guid}")
                    await websocket.send(json.dumps({
                        "type": "register_approved",
                        "checkin_token": checkin_token,
                        "guid": generated_guid
                    }))
                    log("Registration accepted!")
                    await websocket.close()
                    return

                elif payload.get("type") == "checkin":
                    guid = payload.get("guid")
                    token = payload.get("checkin_token")
                    whitelist = load_whitelist()
                    entry = whitelist.get(guid)
                    agent_id = payload.get("guid")
                    hostname = payload.get("hostname", "unknown")
                    ip = payload.get("ip_local", "unknown")
                    ip_remote = websocket.remote_address[0]

                    log(f"[C] Agent check-in request received from {hostname} ({guid})")

                    if not entry:
                        if args.allow_temporary:
                            log(f"[~] [TEMP] Accepting unregistered agent '{hostname}' ({guid}) from {ip_remote}")
                        else:
                            log(f"[!] Unknown GUID '{guid}' from {ip_remote}")
                            await websocket.send(json.dumps({"type": "checkin_denied", "reason": "unknown_guid"}))
                            await websocket.close()
                            return
                    elif entry.get("checkin_token") != token:
                        log(f"[!] Token mismatch for GUID '{guid}' from {ip_remote}")
                        await websocket.send(json.dumps({"type": "checkin_denied", "reason": "token_mismatch"}))
                        await websocket.close()
                        return
                    agents[agent_id] = {
                        "websocket": websocket,
                        "hostname": hostname,
                        "ip": ip,
                        "last_seen": time.time(),
                        "metadata": payload.get("metadata", {})
                    }
                    await websocket.send(json.dumps({"type": "checkin_accepted"}))
                    log(f"[+] Agent check-in accepted: {hostname} ({ip} - {ip_remote})")
                    log(f"[+] Agent {hostname} ready for remote shell")
                    asyncio.create_task(ping_agent_periodically(agent_id, websocket))
                else:
                    log("[!] Invalid agent registration")
                    await websocket.close()
                    return
            else:
                if payload.get("type") == "output":
                    log("[AGENT_RX] :", repr(payload.get("data", ""))[:250])
                    browser_ws = agent_sessions.get(agent_id)
                    if browser_ws and sessions.get(browser_ws) == agent_id:
                        try:
                            await browser_ws.send(json.dumps({
                                "type": "output",
                                "data": payload.get("data", "")
                            }))
                        except Exception as e:
                            log(f"[!] Error sending to browser: {e}")
                elif payload.get("type") == "dir_listing":
                    if await forward_to_browser(agent_id, payload):
                        log(f"[AGENT_RX] < dir_listing for path: {payload.get('path')}")
                elif payload.get("type") == "file_chunk":
                    if await forward_to_browser(agent_id, payload):
                        log(f"[AGENT_RX] < file_chunk {payload.get('index')} of {payload.get('total')} for {payload.get('filename')}")
                elif payload.get("type") == "file_done":
                    if await forward_to_browser(agent_id, payload):
                        log(f"[AGENT_RX] < file_done for {payload.get('filename')}")
                elif payload.get("type") == "upload_ack":
                    if await forward_to_browser(agent_id, payload):
                        log(f"[AGENT_RX] < upload_ack for {payload.get('filename')}")
                elif payload.get("type") == "upload_complete":
                    if await forward_to_browser(agent_id, payload):
                        log(f"[AGENT_RX] < upload_complete for file: {payload.get('filename')}")
                elif payload.get("type") == "file_download":
                    if await forward_to_browser(agent_id, payload):
                        log(f"[AGENT_RX] < file_download for file: {payload.get('filename')}")
                elif payload.get("type") == "upload_chunk_ack":
                    if await forward_to_browser(agent_id, payload):
                        log(f"[AGENT_RX] < upload_chunk_ack for file: {payload.get('filename')}")
                elif payload.get("type") == "metadata_update":
                    if agent_id in agents:
                        agents[agent_id]["metadata"] = payload.get("metadata", {})
                        agents[agent_id]["last_seen"] = time.time()
                        log(f"[?] Metadata update recieved for agent {agent_id}")
    except Exception as e:
        log(f"[!] Agent disconnected or error: {e}")
    finally:
        browser_ws = agent_sessions.get(agent_id)
        if browser_ws:
            try:
                await browser_ws.send(json.dumps({"type": "agent_disconnect", "agent_id": agent_id}))
            except Exception as e:
                log(f"[!] Failed to notify browser of agent disconnect: {e}")
        if agent_id:
            agents.pop(agent_id, None)
            agent_sessions.pop(agent_id, None)
            for ws in list(sessions):
                if sessions.get(ws) == agent_id:
                    sessions.pop(ws, None)

##browser controller endpoint
async def handle_browser(websocket, path):
    log("[FROM_BROWSER] RX: New session detected!")
    try:
        async for message in websocket:
            if isinstance(message, bytes):
                agent_id = sessions.get(websocket)
                if agent_id and agent_id in agents:
                    agent_ws = agents[agent_id]["websocket"]
                    await agent_ws.send(message)
                continue

            payload = json.loads(message)

            if payload.get("type") == "list_agents":
                await websocket.send(json.dumps({
                    "type": "agent_list",
                    "agents": [
                        {
                            "agent_id": aid,
                            "hostname": info["hostname"],
                            "metadata": info.get("metadata", {})
                        }
                        for aid, info in agents.items()
                    ]
                }))
            elif payload.get("type") == "connect_agent":
                agent_id = payload.get("agent_id")
                log(f"[FROM_BROWSER] RX: Connection request to agent {agent_id}")
                if agent_id:
                    sessions[websocket] = agent_id
                    agent_sessions[agent_id] = websocket
                    log(f"Connected frontend to agent {agent_id}")
                else:
                    log("[FROM_BROWSER] connect_agent received with missing agent_id")
            elif payload.get("type") == "input":
                agent_id = sessions.get(websocket)
                if agent_id and agent_id in agents:
                    agent_ws = agents[agent_id]["websocket"]
                    await agent_ws.send(json.dumps({
                        "type": "input",
                        "data": payload.get("data", "")
                    }))
            elif payload.get("type") == "signal":
                agent_id = sessions.get(websocket)
                if agent_id and agent_id in agents:
                    agent_ws = agents[agent_id]["websocket"]
                    await agent_ws.send(json.dumps({
                        "type": "signal",
                        "signal": payload.get("signal", "")
                    }))
            elif payload.get("type") == "resize":
                agent_id = sessions.get(websocket)
                if agent_id and agent_id in agents:
                    cols = payload.get("cols", 80)
                    rows = payload.get("rows", 24)
                    agent_ws = agents[agent_id]["websocket"]
                    await agent_ws.send(json.dumps({
                        "type": "resize",
                        "cols": cols,
                        "rows": rows
                    }))
                    log(f"[FROM_BROWSER] RX: Terminal resize: {cols} x {rows}")
            elif payload.get("type") == "list_dir":
                agent_id = sessions.get(websocket)
                if agent_id and agent_id in agents:
                    agent_ws = agents[agent_id]["websocket"]
                    path = payload.get("path", "/")
                    await agent_ws.send(json.dumps({
                        "type": "list_dir",
                        "path": path
                    }))
                    log(f"[FROM_BROWSER] RX: Get directory listing: {path}")
            elif payload.get("type") == "download_file":
                agent_id = sessions.get(websocket)
                if agent_id and agent_id in agents:
                    agent_ws = agents[agent_id]["websocket"]
                    await agent_ws.send(json.dumps({
                        "type": "download_file",
                        "path": payload.get("path", "/")
                    }))
                    log(f"[FROM_BROWSER] RX: Download request for {payload.get('path')}")
            elif payload.get("type") == "upload_start":
                agent_id = sessions.get(websocket)
                if agent_id and agent_id in agents:
                    agent_ws = agents[agent_id]["websocket"]
                    await agent_ws.send(json.dumps(payload))
                    log(f"[FROM_BROWSER] RX: Upload initiated for {payload.get('filename')}")
            elif payload.get("type") == "upload_done":
                agent_id = sessions.get(websocket)
                if agent_id and agent_id in agents:
                    agent_ws = agents[agent_id]["websocket"]
                    await agent_ws.send(json.dumps(payload))
                    log(f"[FROM_BROWSER] RX: Completed file upload: {payload.get('filename')}")

    except Exception as e:
        log(f"[!] [FROM_BROWSER] RX: Session disconnected or error: {e}")
    finally:
        agent_id = sessions.pop(websocket, None)
        if agent_id:
            agent_sessions.pop(agent_id, None)

##connection endpoint handler
async def handle_connection(websocket, path):
    if path == "/browser":
        await handle_browser(websocket, path)
    elif path == "/agent":
        await handle_agent(websocket, path)
    else:
        log(f"[!] Unknown path: {path}")
        await websocket.close()

##initialize websocket server
async def main():
    if USE_SSL:
        ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ssl_context.load_cert_chain(certfile=CERT_PEM_PATH, keyfile=CERT_KEY_PATH)
        server = await websockets.serve(
            handle_connection, "0.0.0.0", SSL_PORT, ssl=ssl_context, ping_interval=None
        )
    else:
        server = await websockets.serve(
            handle_connection, "0.0.0.0", NON_SSL_PORT, ping_interval=None
        )
    await server.wait_closed()

##run
if __name__ == "__main__":
    if args.stop:
        try:
            with open(PID_PATH, "r") as f:
                pid = int(f.read().strip())
            os.kill(pid, signal.SIGTERM)
            print(f"Stopped controller daemon (PID {pid})")
            os.remove(PID_PATH)
        except Exception as e:
            print(f"Failed to stop controller: {e}")
        sys.exit(0)

    log("SocketShell Controller starting...", console=True)

    if USE_SSL:
        log("SSL mode enabled", console=True)
    else:
        log("Non-SSL mode enabled - Functionality will be limited", console=True)

    log("Review logs at /etc/socketshell/logs/controller.log for controller and agent activity!", console=True)

    daemonize()
    asyncio.run(main())

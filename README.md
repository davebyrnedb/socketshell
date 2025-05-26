# SocketShell

**Linux Remote Shell Aggregator – Secure. Lightweight. Fast.**

SocketShell is a multi reverse-shell style remote access system, websocket based python implementation, with a HTML/JS Xterm centralised controller frontend. Designed to allow a large number of remote linux agents to register and connect to a centralised controller, to be accessed & controlled from a single web frontend.

---

## 🔧 Features

- Reverse WebSocket connections (no inbound port requirements to agents)
- Controller-centric Websocket Multiplexing Topology
- SSL/WSS enabled (required for some features)
- Controller enforced agent GUID whitelist w/whitelist management tool
- Secure file upload/download with chunking
- Remote directory browser with editable path
- Agent metadata collection (CPU, RAM, uptime, disk)
- xterm.js web frontend with persistent shell
- Realtime Shell I/O
- Terminal Resize Support
- Agent Live Search/Filtering
- Fully async, low resource footprint
- And many more...

---

## 🖥️ System Requirements

- Operating System: CentOS 7+, RHEL 7+, Ubuntu 18.04+, Debian 9+
- GLIBC 2.14 or greater
- Python 3.7 or greater
- Python Packages: Websockets
- Suitable web server for hosting frontend (Apache, Nginx. No PHP required.)

---

## 🗂 Complete Repo & File Layout

```
/etc/socketshell/
├── install-agent.sh		# Installer for agent components
├── install-controller.sh	# Installer for controller components
├── agent.py			# Agent script that connects to the controller
├── controller.py		# Controller that mediates between agents and frontend
├── whitelistctl.py		# Tool to manage and manipulate the agent whitelist
├── index.html			# Web-based frontend served via HTTPS
├── logs/			# Auto-generated runtime logs
└── agent_whitelist.json	# Auto-generated whitelist of registered agents
```

---

## 🚀 Quickstart Guide

### 0. Preface

Both roles are included in this repo, Agent (agent.py & install-agent.sh) and Controller (controller.py, whitelistctl.py, index.html & install-controller.sh). It is expected that you would deploy these to different endpoints. The separate install scripts are provided for convenience, but ultimately agent.py will be your remote payload. The controller components will be deployed on a trusted/secure device that you control.

### 1. Clone the Repository

```bash
git clone https://github.com/davebyrnedb/socketshell.git
cd socketshell
```

### 2.a Controller Install

```bash
chmod +x install-controller.sh
sudo ./install-controller.sh
```

This will copy `controller.py`, `whitelistctl.py` and `index.html` to `/etc/socketshell/`.

### 2.b Configure Controller

Modifying `controller.py` you will need to modify at least SECRET_TOKEN, CERT_PEM_PATH and CERT_KEY_PATH. The certificate must be valid for the FQDN you are designating for the WSS Server. This does not pertain to the XTerm Frontend.

```bash
##vars
SECRET_TOKEN = ""
USE_SSL = True
SSL_PORT = 4434
NON_SSL_PORT = 8084
CERT_PEM_PATH = "/path/to/cert.pem"
CERT_KEY_PATH = "/path/to/key.pem"
PID_PATH = "/etc/socketshell/controller.pid"
WHITELIST_PATH = "agent_whitelist.json"
```

NOTE: You may edit WS/WSS ports, and even enable/disable SSL mode. The latter is not recommended.

### 2.c Start Controller

```bash
sudo python3 /etc/socketshell/controller.py
```

### 3.a Agent Install

```bash
chmod +x install-agent.sh
sudo ./install-agent.sh
```

This will copy `agent.py` to `/etc/socketshell/`.

### 3.b Configure Agent

Modifying `agent.py` you will need to modify at least SERVER_URL. This is the WSS Server's FQDN and port configured earlier.

```bash
##vars
SERVER_URL = "wss://[CONTROLLER_ADDRESS]:[PORT]/agent"
TOKEN_PATH = "/etc/socketshell/agent.token"
GUID_PATH = "/etc/socketshell/agent.guid"
PID_PATH = "/etc/socketshell/agent.pid"
SHELL_START_DIR = None
```

### 3.c Register Agent to Controller

```bash
sudo python3 /etc/socketshell/agent.py --register --registration_token="YourSecretToken"
```

### 3.d Start Agent

```bash
sudo python3 /etc/socketshell/agent.py --run
```

NOTE: "registration_token" is defined within controller.py

### 4. Host Frontend over HTTPS

For all features to be available (many terminal operations require HTTPS and hence WSS (Secure Websockets)) you must host the frontend single HTML file on a suitable webserver on a valid FQDN with a valid SSL Certificate. The frontend HTML does not need to be local to the controller, but to avoid XSS limitations, it should be on the same domain as your WSS server address (controller websocket server). For simplicity, it is recommended to host the frontend on the same machine as the websocket controller server.

### 5. Configure Frontend HTML/JS

On lines 99-100, you will need to edit the FQDN and PORT of the websocket server/controller endpoint:

```
const serverIP = "[FQDN_OF_WSS_SERVER]";
const serverPort = "[PORT_OF_WSS_SERVER]";
```

### 6. Access Web Interface & Agent Operation

Open a browser to:

```
https://[FRONTEND-FQDN]/
```

All registered and active agents will appear in the top bar, live search will filter these, you can also scroll left/right if the number of agents overflows the container. session.

Clicking an agent button will:
- Eestablish a secure websocket reverse shell
- Display the remote system file browser
- Display the remote systems latest metadata

---

## 🛡️ Whitelist Management Tool

The whitelist control utility is useful for visualising which agents are whitelisted, their IP's and their assigned GUID's. It's operation is relatively simple, and the command line args are shown below. Manual modification of the `agent_whitelist.json` is also possible.

```bash
--list			List all whitelisted agents (with guid, local IP and remote IP)
--show			Show details of a specific agent (expects --show {GUID})
--delete		Delete a specific agent from whitelist
--prune-dupes		Remove duplicate hostnames (keeps latest entry)
```

---

## ⌨️ Agent CLI Options

```bash
--register		Register with controller (requires --registration_token, optional --force-register)
--registration_token	Token defined on controller used during registration
--force-register	Re-register even if token already exists (if controller loses whitelist, force agent to discard local tokens and re-register)
--run			Start reverse shell and connect to controller (daemonized process)
--stop			Stops the previously started daemonized agent process
--token			Manually specify a check-in token (optional, rarely needed if manually generating or modifying checkin tokens)
```

---

## ⌨️ Controller CLI Options

```bash
--allow-temporary	Allow non-whitelisted agents to check in temporarily (Run with no whitelist, agents can simply be started in --run mode without registering)
--stop			Stops the previously started daemonized agent process
```

---

## 🔧 Future Considerations/Plans

- Provide more universal binary executable for both agent and controller components. This already works with PyInstaller, but requires more work on Controller to allow for externalized configuration parameters
- Migrate whitelist away from JSON plaintext. Most likely encrypted SQLite DB.
- Move --run and --stop operations away from the python scripts, and use systemd service control.

---

## 📸 Screenshots

Coming soon :)

---

## 🛡️ Security

- Agents make **outbound-only** connections using encrypted secure `wss://`
- Controller and frontend require TLS (HTTPS/WebSocket Secure) (Can be run without, but at great feature loss)
- Agents are whitelisted and authenticated via controller governed token system

---

## 📃 License

MIT License – free to use, modify, and distribute.

---

## ✍️ Credits

Built by [Dave Byrne](https://github.com/davebyrnedb)  
Designed for individuals managing large secure Linux environments

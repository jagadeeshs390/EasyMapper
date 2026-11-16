# EasyMapper 🌐🔍

**EasyMapper** is a modern, containerized WebUI for **Nmap** designed for network reconnaissance and security risk intelligence. It provides real-time verbose scan output streaming, dynamic Nmap command generation, port vulnerability risk classification (Low, Medium, High, Critical), and theoretical attack vector analysis with defensive hardening guides.

---

## ✨ Features

- **Live Verbose UI Streaming**: Watch Nmap discover ports and execute scripts line-by-line in real-time via Server-Sent Events (SSE).
- **Configurable Scan Profiles**:
  - **Quick Port Scan**: Scans top 100 most common ports rapidly (`-T4 -F -v`).
  - **Standard Service Scan**: Scans top 1000 ports with service version detection (`-T4 -sV -v`).
  - **OS & Service Detection**: Identifies target operating system and service banners (`-T4 -sV -O -v`).
  - **Aggressive Scan**: Full reconnaissance with OS detection, version scanning, and traceroute (`-T4 -A -v`).
  - **Vulnerability Script Scan**: Executes Nmap's vulnerability detection scripts (`--script=vuln`).
  - **Full 65,535 Port Scan**: Exhaustive TCP port sweep (`-p- -sV -v`).
  - **Pingless Scan**: Bypasses host discovery for targets that block ICMP ping (`-Pn`).
- **Dynamic Command Preview**: Displays the exact `nmap` command constructed based on target, profile, and advanced flags.
- **Port Purpose & Security Risk Ratings**:
  - Automatically classifies exposed ports into **Low**, **Medium**, **High**, or **Critical** risk levels.
  - Explains the purpose and standard role of each open port.
- **Theoretical Exploitability & Threat Vectors**:
  - Dedicated "Exploitation & Risk Info" drawer for each open port explaining theoretical attack vectors (e.g. credential sniffing, anonymous access, brute forcing, RCE risks).
  - Practical defensive hardening and remediation checklists to secure the host.
- **Safe Architecture**:
  - Strict input validation against command injection.
  - Containerized deployment running on `python:3.11-slim` with Nmap pre-installed.

---

## 🚀 Quickstart with Docker

### 1. Build the Docker Image

From the `easymapper` directory:

```bash
docker build -t easymapper:latest .
```

### 2. Run the Container

Run the container with network raw socket capabilities (required for OS detection and SYN scanning):

```bash
docker run -d \
  --name easymapper \
  -p 8000:8000 \
  --cap-add=NET_RAW \
  --cap-add=NET_ADMIN \
  --restart unless-stopped \
  easymapper:latest
```

*Note: `--cap-add=NET_RAW --cap-add=NET_ADMIN` grants the container permissions to craft raw packets required for Nmap OS fingerprinting (`-O`) and SYN scans.*

### 3. Using Docker Compose (Alternative)

```bash
docker compose up -d
```

### 4. Access the WebUI

Open your browser and navigate to:
```
http://localhost:8000
```

---

## 📁 Project Structure

```
easymapper/
├── Dockerfile                  # Container definition with Nmap and Python 3.11
├── docker-compose.yml          # Compose specification with NET_RAW capabilities
├── requirements.txt            # FastAPI, Uvicorn, Jinja2, Pydantic
├── .dockerignore
├── README.md                   # Documentation and usage guide
└── app/
    ├── main.py                 # FastAPI backend, async Nmap runner & SSE streaming
    ├── port_kb.py              # Knowledge base of ports, risks, exploit vectors & fixes
    ├── templates/
    │   └── index.html          # Modern, responsive WebUI with dark mode & live console
    └── static/                 # Static assets directory
```

---

## 🔒 Security & Usage Notice

EasyMapper is intended strictly for authorized network inventory, defensive security auditing, and educational threat modeling. Only scan networks, domains, and systems you own or have explicit authorization to assess.

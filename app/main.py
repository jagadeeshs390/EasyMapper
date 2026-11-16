import asyncio
import json
import os
import re
import uuid
import xml.etree.ElementTree as ET
from typing import AsyncGenerator

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, field_validator

from app.port_kb import get_port_security_info

app = FastAPI(title="EasyMapper", description="Modern Dockerized Nmap WebUI & Security Analyzer")

# Templates and static setup
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
templates = Jinja2Templates(directory=os.path.join(BASE_DIR, "templates"))
app.mount("/static", StaticFiles(directory=os.path.join(BASE_DIR, "static")), name="static")

SCAN_PRESETS = {
    "quick": {
        "name": "Quick Port Scan",
        "description": "Scans top 100 most common ports rapidly.",
        "flags": ["-T4", "-F", "-v"]
    },
    "standard": {
        "name": "Standard Service & Version Scan",
        "description": "Scans top 1000 ports with service version detection.",
        "flags": ["-T4", "-sV", "-v"]
    },
    "os_detect": {
        "name": "OS & Service Detection Scan",
        "description": "Determines target operating system, open ports, and running service versions.",
        "flags": ["-T4", "-sV", "-O", "-v"]
    },
    "aggressive": {
        "name": "Aggressive Scan (-A)",
        "description": "Enables OS detection, version scanning, script scanning, and traceroute.",
        "flags": ["-T4", "-A", "-v"]
    },
    "vuln": {
        "name": "Vulnerability Script Scan",
        "description": "Runs Nmap's vulnerability detection scripts against open services.",
        "flags": ["-T4", "-sV", "--script=vuln", "-v"]
    },
    "full": {
        "name": "Full Port Scan (All 65535 Ports)",
        "description": "Exhaustive sweep across all 65,535 TCP ports with version detection.",
        "flags": ["-T4", "-p-", "-sV", "-v"]
    },
    "pingless": {
        "name": "Fast Pingless Service Scan (-Pn)",
        "description": "Bypasses host discovery (useful for targets blocking ICMP ping).",
        "flags": ["-Pn", "-T4", "-sV", "-v"]
    }
}


class ScanRequest(BaseModel):
    target: str
    scan_type: str = "standard"
    skip_ping: bool = False
    custom_ports: str = ""

    @field_validator("target")
    @classmethod
    def validate_target(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Target cannot be empty.")
        # Allow valid IPv4, IPv6, or domain names / hostnames
        domain_or_ip_regex = r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9-_]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}|localhost|(?:\d{1,3}\.){3}\d{1,3}|(?:[0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|(?:[0-9a-fA-F]{1,4}:)*:[0-9a-fA-F]{1,4}$"
        if not re.match(domain_or_ip_regex, cleaned):
            raise ValueError("Target must be a valid domain name, hostname, or IP address.")
        if len(cleaned) > 253:
            raise ValueError("Target hostname/IP is too long.")
        return cleaned

    @field_validator("scan_type")
    @classmethod
    def validate_scan_type(cls, v: str) -> str:
        if v not in SCAN_PRESETS:
            raise ValueError(f"Scan type must be one of: {', '.join(SCAN_PRESETS.keys())}")
        return v

    @field_validator("custom_ports")
    @classmethod
    def validate_custom_ports(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            return ""
        # Validates port specifications like "80,443", "1-1000", "80,443,8000-8080"
        if not re.match(r"^[0-9,\-]+$", cleaned):
            raise ValueError("Custom ports may only contain numbers, commas, and hyphens (e.g. '80,443,8000-8080').")
        return cleaned


def build_nmap_command(req: ScanRequest, output_xml_path: str = "") -> list[str]:
    """Build the argument list for subprocess execution."""
    preset = SCAN_PRESETS[req.scan_type]
    cmd = ["nmap"]
    
    # Base flags from preset
    for flag in preset["flags"]:
        if flag not in cmd:
            cmd.append(flag)

    # Optional skip ping flag
    if req.skip_ping and "-Pn" not in cmd:
        cmd.append("-Pn")

    # Custom ports if specified
    if req.custom_ports:
        # If -p- or -F is present from preset, remove or override
        cmd = [c for c in cmd if c not in ("-p-", "-F")]
        cmd.extend(["-p", req.custom_ports])

    # XML output for structured parsing
    if output_xml_path:
        cmd.extend(["-oX", output_xml_path])

    # Target
    cmd.append(req.target)
    return cmd


def parse_nmap_xml(xml_path: str) -> dict:
    """Parse Nmap XML output into a rich structured report."""
    if not os.path.exists(xml_path) or os.path.getsize(xml_path) == 0:
        return {"status": "error", "error": "No output XML generated from scan."}

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
    except Exception as e:
        return {"status": "error", "error": f"Failed to parse Nmap XML: {str(e)}"}

    report = {
        "status": "success",
        "hosts": [],
        "scan_stats": {
            "elapsed": root.find("runstats/finished").attrib.get("elapsed", "0") if root.find("runstats/finished") is not None else "0",
            "summary": root.find("runstats/finished").attrib.get("summary", "") if root.find("runstats/finished") is not None else ""
        }
    }

    for host_el in root.findall("host"):
        status_el = host_el.find("status")
        state = status_el.attrib.get("state", "unknown") if status_el is not None else "unknown"

        # Addresses
        addresses = []
        for addr in host_el.findall("address"):
            addresses.append({
                "addr": addr.attrib.get("addr", ""),
                "type": addr.attrib.get("addrtype", "")
            })

        # Hostnames
        hostnames = []
        for hn in host_el.findall("hostnames/hostname"):
            hostnames.append(hn.attrib.get("name", ""))

        # OS Detection
        os_matches = []
        for osm in host_el.findall("os/osmatch"):
            os_matches.append({
                "name": osm.attrib.get("name", ""),
                "accuracy": osm.attrib.get("accuracy", "0")
            })

        # Ports
        open_ports = []
        for port_el in host_el.findall("ports/port"):
            port_id = port_el.attrib.get("portid", "")
            proto = port_el.attrib.get("protocol", "tcp")
            
            p_state_el = port_el.find("state")
            p_state = p_state_el.attrib.get("state", "unknown") if p_state_el is not None else "unknown"

            if p_state != "open":
                continue

            svc_el = port_el.find("service")
            svc_name = svc_el.attrib.get("name", "unknown") if svc_el is not None else "unknown"
            svc_product = svc_el.attrib.get("product", "") if svc_el is not None else ""
            svc_version = svc_el.attrib.get("version", "") if svc_el is not None else ""
            svc_extrainfo = svc_el.attrib.get("extrainfo", "") if svc_el is not None else ""

            # Script output (vulns, banners)
            scripts = []
            for sc in port_el.findall("script"):
                scripts.append({
                    "id": sc.attrib.get("id", ""),
                    "output": sc.attrib.get("output", "")
                })

            # Retrieve rich security intelligence and exploitability info
            sec_info = get_port_security_info(port_id, svc_name)

            open_ports.append({
                "port": port_id,
                "protocol": proto,
                "state": p_state,
                "service": svc_name,
                "product": svc_product,
                "version": svc_version,
                "extrainfo": svc_extrainfo,
                "scripts": scripts,
                "security": sec_info
            })

        report["hosts"].append({
            "state": state,
            "addresses": addresses,
            "hostnames": hostnames,
            "os_matches": os_matches[:3],  # Top 3 OS matches
            "open_ports": open_ports,
            "open_port_count": len(open_ports)
        })

    return report


@app.get("/", response_class=HTMLResponse)
async def index(request: Request):
    """Render EasyMapper dashboard."""
    return templates.TemplateResponse(
        request=request,
        name="index.html",
        context={
            "request": request,
            "presets": SCAN_PRESETS
        }
    )


@app.post("/api/preview-command")
async def preview_command(req: ScanRequest):
    """Return the exact nmap command string that will be executed."""
    cmd_list = build_nmap_command(req)
    return {
        "command": " ".join(cmd_list),
        "cmd_list": cmd_list
    }


@app.get("/api/scan/stream")
async def stream_scan(
    target: str,
    scan_type: str = "standard",
    skip_ping: bool = False,
    custom_ports: str = ""
):
    """
    Live stream Nmap execution stdout and return structured scan results
    via Server-Sent Events (SSE).
    """
    try:
        validated_req = ScanRequest(
            target=target,
            scan_type=scan_type,
            skip_ping=skip_ping,
            custom_ports=custom_ports
        )
    except Exception as validation_err:
        async def err_gen():
            yield f"event: error\ndata: {json.dumps({'error': str(validation_err)})}\n\n"
        return StreamingResponse(err_gen(), media_type="text/event-stream")

    scan_uuid = str(uuid.uuid4())
    xml_path = f"/tmp/easymapper_{scan_uuid}.xml"
    cmd = build_nmap_command(validated_req, output_xml_path=xml_path)
    cmd_display = " ".join([c for c in cmd if not c.startswith("/tmp/easymapper_") and c != "-oX"])

    async def event_generator() -> AsyncGenerator[str, None]:
        # Send initial scan info event
        init_payload = {
            "uuid": scan_uuid,
            "command": cmd_display,
            "target": validated_req.target,
            "scan_type": SCAN_PRESETS[validated_req.scan_type]["name"]
        }
        yield f"event: start\ndata: {json.dumps(init_payload)}\n\n"

        try:
            # Spawn asynchronous Nmap process
            process = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.STDOUT
            )

            # Stream output live line-by-line
            while True:
                line = await process.stdout.readline()
                if not line:
                    break
                text = line.decode("utf-8", errors="replace")
                data = json.dumps({"line": text})
                yield f"event: log\ndata: {data}\n\n"

            # Wait for exit
            await process.wait()

            # Parse XML output for rich results
            results = parse_nmap_xml(xml_path)
            results["command"] = cmd_display
            results["target"] = validated_req.target
            yield f"event: result\ndata: {json.dumps(results)}\n\n"

        except Exception as e:
            err_data = json.dumps({"error": f"Execution error: {str(e)}"})
            yield f"event: error\ndata: {err_data}\n\n"

        finally:
            # Clean up temporary XML file
            if os.path.exists(xml_path):
                try:
                    os.remove(xml_path)
                except OSError:
                    pass
            yield f"event: end\ndata: {json.dumps({'message': 'Scan finished.'})}\n\n"

    return StreamingResponse(
        event_generator(),
        media_type="text/event-stream",
        headers={
            "Cache-Control": "no-cache",
            "Connection": "keep-alive",
            "X-Accel-Buffering": "no"
        }
    )

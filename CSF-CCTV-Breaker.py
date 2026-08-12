#!/usr/bin/env python3
"""
CSF-CCTV-Breaker
================
A CCTV / IP-camera / DVR security auditing tool built for authorized
penetration testing and internal security assessments.

Author  : Cyber Squad Forge (CSF) Research
Platform: Kali Linux (Python 3.9+)

LEGAL / ETHICAL NOTICE
-----------------------
This tool actively probes network devices, attempts authentication, and
reports on exposed video streams. Running it against any device, network,
or organization without explicit written authorization is illegal in most
jurisdictions (e.g. under the U.S. Computer Fraud and Abuse Act, UK
Computer Misuse Act, or Pakistan's PECA 2016) and is an unacceptable
invasion of privacy where cameras may capture private spaces.

Only run this against:
  - Systems you own, OR
  - Systems you have documented, written authorization to test.

The tool will refuse to proceed until the operator explicitly confirms
authorization at runtime.

Dependencies:
    pip install rich requests --break-system-packages
"""

import argparse
import ipaddress
import json
import os
import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime

import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from rich.console import Console
from rich.panel import Panel
from rich.progress import (BarColumn, Progress, SpinnerColumn,
                            TextColumn, TimeElapsedColumn)
from rich.table import Table
from rich import box

requests.packages.urllib3.disable_warnings()  # noqa: self-signed cam certs

console = Console()

TOOL_NAME = "CSF-CCTV-Breaker"
TOOL_VERSION = "1.0"

# ---------------------------------------------------------------------------
# Default port set covering common CCTV / DVR / NVR / IP camera services
# ---------------------------------------------------------------------------
DEFAULT_PORTS = {
    80: "HTTP",
    443: "HTTPS",
    554: "RTSP",
    8000: "Hikvision/DVR Admin",
    8080: "HTTP-Alt",
    8899: "IoT/Camera Alt",
    37777: "Dahua DVR/NVR",
    34567: "Legacy DVR (TVT/CP Plus)",
}

# ---------------------------------------------------------------------------
# Vendor fingerprint signatures (Server headers / RTSP banners)
# ---------------------------------------------------------------------------
VENDOR_SIGNATURES = {
    "hikvision": ["hikvision", "app-webs", "dnvrs-webs"],
    "dahua": ["dahua", "dh-", "dvrdvs"],
    "cp plus": ["cp plus", "cpplus"],
    "tvt": ["tvt", "nvms"],
    "axis": ["axis"],
    "foscam": ["foscam"],
    "reolink": ["reolink"],
    "uniview": ["uniview", "uniview"],
}

# ---------------------------------------------------------------------------
# Common default credential pairs (public, manufacturer-documented defaults)
# ---------------------------------------------------------------------------
DEFAULT_CREDENTIALS = [
    ("admin", "admin"),
    ("admin", "12345"),
    ("admin", "123456"),
    ("admin", "admin123"),
    ("admin", "1234"),
    ("admin", ""),
    ("admin", "password"),
    ("admin", "888888"),
    ("admin", "9999"),
    ("root", "root"),
    ("root", "pass"),
    ("root", "12345"),
    ("root", "vizxv"),
    ("service", "service"),
    ("user", "user"),
    ("guest", "guest"),
    ("default", "default"),
    ("supervisor", "supervisor"),
]

# Common unauthenticated RTSP stream paths to probe
COMMON_RTSP_PATHS = [
    "/",
    "/live",
    "/live/ch0",
    "/live/ch00_0",
    "/h264",
    "/h264/ch1/main/av_stream",
    "/cam/realmonitor?channel=1&subtype=0",
    "/Streaming/Channels/101",
    "/Streaming/Channels/1",
    "/onvif1",
    "/media/video1",
]


# ---------------------------------------------------------------------------
# Banner
# ---------------------------------------------------------------------------
def print_banner():
    banner = r"""
  _____   _____    _______            _____    _____   _______  __      __ 
 / ____| / ____|  |  _____|          / ____|  / ____| |__   __| \ \    / / 
| |      | (___   | |__      _____  | |      | |         | |     \ \  / /  
| |       \___ \  |  __|    |_____| | |      | |         | |      \ \/ /   
| |____   ____) | | |               | |____  | |____     | |       \  /    
 \_____| |_____/  |_|                \_____|  \_____|    |_|        \/     

        C S F - C C T V - B R E A K E R   v{ver}
        Cyber Squad Forge :: Offensive IoT / CCTV Audit Framework
""".format(ver=TOOL_VERSION)
    console.print(banner, style="bold red")
    console.print(
        Panel.fit(
            "[bold yellow]Authorized Security Testing Tool[/bold yellow]\n"
            "[white]Use only against systems you own or are explicitly "
            "authorized in writing to test.[/white]",
            border_style="red",
        )
    )


def require_authorization(auto_yes: bool):
    """Hard gate: refuse to run unless the operator confirms authorization."""
    if auto_yes:
        console.print(
            "[yellow][!] --i-have-authorization flag supplied. "
            "Proceeding under operator's declared authorization.[/yellow]"
        )
        return
    console.print(
        "\n[bold red]LEGAL CONFIRMATION REQUIRED[/bold red]\n"
        "Do you have explicit, documented, written authorization to test "
        "every host in the target range you are about to scan? (yes/no)"
    )
    answer = input("> ").strip().lower()
    if answer not in ("yes", "y"):
        console.print("[red]Authorization not confirmed. Exiting.[/red]")
        sys.exit(1)


# ---------------------------------------------------------------------------
# Target expansion
# ---------------------------------------------------------------------------
def expand_targets(target: str):
    """Expand a CIDR, single IP, or hyphenated range into a list of IPs."""
    targets = []
    try:
        if "/" in target:
            net = ipaddress.ip_network(target, strict=False)
            targets = [str(ip) for ip in net.hosts()]
        elif "-" in target:
            # e.g. 192.168.1.1-254
            base, end = target.rsplit(".", 1)[0], target.rsplit(".", 1)[1]
            start_last, end_last = end.split("-")
            for i in range(int(start_last), int(end_last) + 1):
                targets.append(f"{base}.{i}")
        else:
            ipaddress.ip_address(target)  # validation
            targets = [target]
    except ValueError as e:
        console.print(f"[red]Invalid target specification '{target}': {e}[/red]")
        sys.exit(1)
    return targets


# ---------------------------------------------------------------------------
# Port scanning
# ---------------------------------------------------------------------------
def scan_port(ip: str, port: int, timeout: float) -> bool:
    """Return True if the TCP port is open."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            result = s.connect_ex((ip, port))
            return result == 0
    except (socket.timeout, socket.gaierror, OSError):
        return False


# ---------------------------------------------------------------------------
# Banner grabbing / fingerprinting
# ---------------------------------------------------------------------------
def grab_http_banner(ip: str, port: int, timeout: float) -> dict:
    """Attempt an HTTP(S) GET and capture headers for fingerprinting."""
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{ip}:{port}/"
    try:
        resp = requests.get(url, timeout=timeout, verify=False)
        return {
            "url": url,
            "status_code": resp.status_code,
            "server_header": resp.headers.get("Server", ""),
            "www_authenticate": resp.headers.get("WWW-Authenticate", ""),
        }
    except requests.exceptions.RequestException:
        return {}


def grab_rtsp_banner(ip: str, port: int, timeout: float) -> dict:
    """Send an RTSP OPTIONS request and parse the raw response headers."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            req = (
                f"OPTIONS rtsp://{ip}:{port}/ RTSP/1.0\r\n"
                f"CSeq: 1\r\n"
                f"User-Agent: {TOOL_NAME}\r\n\r\n"
            )
            s.sendall(req.encode())
            data = s.recv(2048).decode(errors="ignore")
            headers = {}
            for line in data.split("\r\n"):
                if ":" in line:
                    k, _, v = line.partition(":")
                    headers[k.strip().lower()] = v.strip()
            status_line = data.split("\r\n")[0] if data else ""
            return {"status_line": status_line, "headers": headers, "raw": data}
    except (socket.timeout, ConnectionRefusedError, OSError):
        return {}


def fingerprint_vendor(http_banner: dict, rtsp_banner: dict) -> str:
    """Match known vendor strings against gathered banners."""
    blob = " ".join(
        [
            http_banner.get("server_header", ""),
            http_banner.get("www_authenticate", ""),
            rtsp_banner.get("raw", ""),
        ]
    ).lower()

    for vendor, sigs in VENDOR_SIGNATURES.items():
        if any(sig in blob for sig in sigs):
            return vendor.title()
    return "Unknown"


# ---------------------------------------------------------------------------
# Credential auditing
# ---------------------------------------------------------------------------
def check_default_creds_http(ip: str, port: int, timeout: float) -> list:
    """Try default credential pairs against the HTTP admin interface."""
    scheme = "https" if port == 443 else "http"
    url = f"{scheme}://{ip}:{port}/"
    found = []
    for user, pw in DEFAULT_CREDENTIALS:
        for auth_cls in (HTTPBasicAuth, HTTPDigestAuth):
            try:
                resp = requests.get(
                    url, auth=auth_cls(user, pw), timeout=timeout, verify=False
                )
                if resp.status_code == 200:
                    found.append({"user": user, "pass": pw, "method": auth_cls.__name__})
                    break  # no need to try digest if basic already worked
            except requests.exceptions.RequestException:
                continue
        if found:
            break  # stop at first working credential pair for this host
    return found


def check_rtsp_auth(ip: str, port: int, path: str, user: str, pw: str, timeout: float):
    """Send an RTSP DESCRIBE with Basic auth embedded and inspect the reply."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(timeout)
            s.connect((ip, port))
            import base64

            creds_b64 = base64.b64encode(f"{user}:{pw}".encode()).decode()
            req = (
                f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                f"CSeq: 2\r\n"
                f"Authorization: Basic {creds_b64}\r\n"
                f"Accept: application/sdp\r\n"
                f"User-Agent: {TOOL_NAME}\r\n\r\n"
            )
            s.sendall(req.encode())
            data = s.recv(2048).decode(errors="ignore")
            return "200 OK" in data
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


def check_unauth_rtsp_paths(ip: str, port: int, timeout: float) -> list:
    """Probe common RTSP paths without credentials; flag ones that respond 200."""
    accessible = []
    for path in COMMON_RTSP_PATHS:
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.settimeout(timeout)
                s.connect((ip, port))
                req = (
                    f"DESCRIBE rtsp://{ip}:{port}{path} RTSP/1.0\r\n"
                    f"CSeq: 3\r\n"
                    f"Accept: application/sdp\r\n"
                    f"User-Agent: {TOOL_NAME}\r\n\r\n"
                )
                s.sendall(req.encode())
                data = s.recv(1024).decode(errors="ignore")
                if "200 OK" in data:
                    accessible.append(f"rtsp://{ip}:{port}{path}")
        except (socket.timeout, ConnectionRefusedError, OSError):
            continue
    return accessible


# ---------------------------------------------------------------------------
# Per-host assessment pipeline
# ---------------------------------------------------------------------------
def assess_host(ip: str, ports: dict, timeout: float, skip_creds: bool, delay: float) -> dict:
    """Run the full discovery -> fingerprint -> audit pipeline on one host."""
    host_result = {
        "ip": ip,
        "open_ports": {},
        "vendor": "Unknown",
        "weak_credentials": [],
        "exposed_rtsp_streams": [],
    }

    open_ports = {}
    for port, label in ports.items():
        if scan_port(ip, port, timeout):
            open_ports[port] = label
        time.sleep(delay)  # gentle rate limiting to avoid hammering devices

    if not open_ports:
        return None  # nothing open on this host, skip it entirely

    host_result["open_ports"] = open_ports

    http_banner, rtsp_banner = {}, {}
    for port in open_ports:
        if port in (80, 443, 8000, 8080):
            http_banner = grab_http_banner(ip, port, timeout) or http_banner
        if port == 554:
            rtsp_banner = grab_rtsp_banner(ip, port, timeout) or rtsp_banner

    host_result["vendor"] = fingerprint_vendor(http_banner, rtsp_banner)
    host_result["http_banner"] = http_banner
    host_result["rtsp_banner"] = rtsp_banner

    if not skip_creds:
        for port in open_ports:
            if port in (80, 443, 8000, 8080):
                creds = check_default_creds_http(ip, port, timeout)
                if creds:
                    for c in creds:
                        c["port"] = port
                    host_result["weak_credentials"].extend(creds)

        if 554 in open_ports:
            # Unauthenticated stream exposure check
            host_result["exposed_rtsp_streams"] = check_unauth_rtsp_paths(
                ip, 554, timeout
            )
            # Default-credential RTSP check on a small representative path set
            for user, pw in DEFAULT_CREDENTIALS[:6]:
                if check_rtsp_auth(ip, 554, "/", user, pw, timeout):
                    host_result["weak_credentials"].append(
                        {"user": user, "pass": pw, "method": "RTSP-Basic", "port": 554}
                    )
                    break

    return host_result


# ---------------------------------------------------------------------------
# Reporting
# ---------------------------------------------------------------------------
def generate_json_report(results: list, out_path: str, meta: dict):
    payload = {"meta": meta, "results": results}
    with open(out_path, "w") as f:
        json.dump(payload, f, indent=2)


def generate_html_report(results: list, out_path: str, meta: dict):
    rows = ""
    for host in results:
        creds_str = (
            "<br>".join(
                f"{c['user']}:{c['pass']} ({c.get('method','')}, port {c.get('port','')})"
                for c in host["weak_credentials"]
            )
            or "None found"
        )
        streams_str = "<br>".join(host["exposed_rtsp_streams"]) or "None found"
        ports_str = ", ".join(f"{p}/{l}" for p, l in host["open_ports"].items())

        row_class = "risk-high" if (host["weak_credentials"] or host["exposed_rtsp_streams"]) else "risk-low"

        rows += f"""
        <tr class="{row_class}">
            <td>{host['ip']}</td>
            <td>{host['vendor']}</td>
            <td>{ports_str}</td>
            <td>{creds_str}</td>
            <td>{streams_str}</td>
        </tr>"""

    html = f"""<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>{TOOL_NAME} Report</title>
<style>
    body {{ font-family: 'Segoe UI', Arial, sans-serif; background:#0d1117; color:#e6edf3; padding:30px; }}
    h1 {{ color:#ff4d4d; }}
    .meta {{ color:#9da7b3; margin-bottom:20px; }}
    table {{ border-collapse: collapse; width:100%; }}
    th, td {{ border:1px solid #30363d; padding:10px; text-align:left; vertical-align:top; }}
    th {{ background:#161b22; color:#ff4d4d; }}
    .risk-high {{ background:#2d1414; }}
    .risk-low {{ background:#141d14; }}
    .footer {{ margin-top:30px; color:#6e7681; font-size:0.85em; }}
</style>
</head>
<body>
    <h1>{TOOL_NAME} :: Assessment Report</h1>
    <div class="meta">
        Scan started: {meta['scan_start']}<br>
        Scan finished: {meta['scan_end']}<br>
        Target scope: {meta['target']}<br>
        Hosts with findings: {len(results)}
    </div>
    <table>
        <tr>
            <th>IP Address</th>
            <th>Vendor</th>
            <th>Open Ports</th>
            <th>Weak / Default Credentials</th>
            <th>Exposed RTSP Streams (unauthenticated)</th>
        </tr>
        {rows}
    </table>
    <div class="footer">
        Generated by {TOOL_NAME} v{TOOL_VERSION} — Cyber Squad Forge.<br>
        For use only against explicitly authorized targets.
    </div>
</body>
</html>"""
    with open(out_path, "w") as f:
        f.write(html)


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def parse_args():
    parser = argparse.ArgumentParser(
        prog=TOOL_NAME,
        description="CCTV / IP camera / DVR security auditing tool (authorized use only).",
    )
    parser.add_argument(
        "-t", "--target", required=True,
        help="Target IP, CIDR range (e.g. 192.168.1.0/24), or range (e.g. 192.168.1.1-254)",
    )
    parser.add_argument(
        "-p", "--ports", default=None,
        help="Comma-separated list of ports to scan (default: built-in CCTV port set)",
    )
    parser.add_argument(
        "--threads", type=int, default=25,
        help="Number of concurrent worker threads (default: 25)",
    )
    parser.add_argument(
        "--timeout", type=float, default=2.0,
        help="Per-connection socket timeout in seconds (default: 2.0)",
    )
    parser.add_argument(
        "--delay", type=float, default=0.0,
        help="Delay in seconds between individual port probes per host, for gentler scanning (default: 0)",
    )
    parser.add_argument(
        "--skip-creds", action="store_true",
        help="Skip credential auditing and RTSP stream exposure checks; discovery/fingerprinting only.",
    )
    parser.add_argument(
        "--output-dir", default="./csf_cctv_reports",
        help="Directory to write JSON/HTML reports into (default: ./csf_cctv_reports)",
    )
    parser.add_argument(
        "--i-have-authorization", action="store_true",
        help="Skip the interactive confirmation prompt (still requires you to actually have authorization).",
    )
    return parser.parse_args()


def main():
    print_banner()
    args = parse_args()
    require_authorization(args.i_have_authorization)

    ports = DEFAULT_PORTS
    if args.ports:
        custom_ports = [int(p.strip()) for p in args.ports.split(",")]
        ports = {p: DEFAULT_PORTS.get(p, "Custom") for p in custom_ports}

    targets = expand_targets(args.target)
    console.print(f"[cyan][*] Expanded target scope: {len(targets)} host(s)[/cyan]")

    os.makedirs(args.output_dir, exist_ok=True)
    scan_start = datetime.utcnow().isoformat() + "Z"

    results = []
    with Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("{task.completed}/{task.total}"),
        TimeElapsedColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Scanning hosts...", total=len(targets))
        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = {
                executor.submit(
                    assess_host, ip, ports, args.timeout, args.skip_creds, args.delay
                ): ip
                for ip in targets
            }
            for future in as_completed(futures):
                ip = futures[future]
                try:
                    res = future.result()
                    if res:
                        results.append(res)
                except Exception as e:
                    console.print(f"[red][!] Error assessing {ip}: {e}[/red]")
                progress.advance(task)

    scan_end = datetime.utcnow().isoformat() + "Z"
    meta = {
        "tool": TOOL_NAME,
        "version": TOOL_VERSION,
        "target": args.target,
        "scan_start": scan_start,
        "scan_end": scan_end,
        "hosts_scanned": len(targets),
        "hosts_with_open_ports": len(results),
    }

    # --- Summary table ---
    table = Table(title="CSF-CCTV-Breaker :: Results Summary", box=box.SQUARE, show_lines=True)
    table.add_column("IP", style="bold cyan")
    table.add_column("Vendor", style="magenta")
    table.add_column("Open Ports", style="yellow")
    table.add_column("Weak Creds", style="bold red")
    table.add_column("Open RTSP Streams", style="bold red")

    for host in results:
        ports_str = ", ".join(str(p) for p in host["open_ports"])
        creds_str = (
            ", ".join(f"{c['user']}:{c['pass']}" for c in host["weak_credentials"])
            or "-"
        )
        streams_str = str(len(host["exposed_rtsp_streams"])) if host["exposed_rtsp_streams"] else "-"
        table.add_row(host["ip"], host["vendor"], ports_str, creds_str, streams_str)

    console.print(table)

    json_path = os.path.join(args.output_dir, "csf_cctv_report.json")
    html_path = os.path.join(args.output_dir, "csf_cctv_report.html")
    generate_json_report(results, json_path, meta)
    generate_html_report(results, html_path, meta)

    console.print(
        Panel.fit(
            f"[green]Reports written:[/green]\n"
            f"  JSON: {json_path}\n"
            f"  HTML: {html_path}",
            border_style="green",
        )
    )


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[red][!] Scan interrupted by user.[/red]")
        sys.exit(1)

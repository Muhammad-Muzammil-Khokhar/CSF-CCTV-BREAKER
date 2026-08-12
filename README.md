# CSF-CCTV-Breaker

**Authorized CCTV / IP-Camera / DVR Security Auditing Tool**
Built by [Cyber Squad Forge](https://github.com/Muhammad-Muzammil-Khokhar) Research — Kali Linux, Python 3.9+

CSF-CCTV-Breaker discovers, fingerprints, and audits CCTV/DVR/NVR/IP-camera devices on a network range for common misconfigurations: exposed admin/RTSP ports, default manufacturer credentials, and unauthenticated live-stream access. It produces clean JSON and HTML reports for client-facing security assessments.

> ⚠️ **This tool is for authorized security testing only.** See [Legal & Ethical Notice](#legal--ethical-notice) below.

---

## Features

- **Target expansion** — single IP, CIDR range, or hyphenated range (`192.168.1.1-254`)
- **Fast concurrent port scanning** across common CCTV/DVR/NVR ports (HTTP, HTTPS, RTSP, Hikvision, Dahua, legacy TVT/CP Plus, etc.)
- **Vendor fingerprinting** via HTTP/RTSP banner signatures (Hikvision, Dahua, CP Plus, TVT, Axis, Foscam, Reolink, Uniview)
- **Default credential auditing** against HTTP admin interfaces (Basic & Digest auth) using publicly documented manufacturer defaults
- **Unauthenticated RTSP stream detection** across common vendor stream paths
- **Rich terminal UI** — live progress bars and a results summary table
- **JSON + HTML reporting**, with high/low risk highlighting
- **Hard authorization gate** — refuses to scan until the operator confirms written authorization (or passes `--i-have-authorization`)
- Configurable thread count, timeout, and inter-probe delay for gentler scanning of sensitive IoT devices

## Installation

```bash
git clone https://github.com/Muhammad-Muzammil-Khokhar/CSF-CCTV-BREAKER.git
```
```bash
cd CSF-CCTV-BREAKER
```
```bash
pip install rich requests --break-system-packages
```

## Usage

```bash
python3 CSF-CCTV-Breaker.py -t 192.168.1.0/24
```

You will be prompted to confirm you have explicit, documented authorization to test the target scope before any scanning begins.

### CLI Options

| Flag | Description | Default |
|---|---|---|
| `-t`, `--target` | Target IP, CIDR, or range (`192.168.1.1-254`) | required |
| `-p`, `--ports` | Comma-separated list of ports to scan | built-in CCTV port set |
| `--threads` | Concurrent worker threads | 25 |
| `--timeout` | Per-connection socket timeout (s) | 2.0 |
| `--delay` | Delay between probes per host, for gentler scanning (s) | 0 |
| `--skip-creds` | Discovery/fingerprinting only — skip credential & stream checks | off |
| `--output-dir` | Directory for JSON/HTML reports | `./csf_cctv_reports` |
| `--i-have-authorization` | Skip the interactive confirmation prompt | off |

### Example

```bash
python3 CSF-CCTV-Breaker.py -t 10.0.0.0/24 --threads 40 --delay 0.1 --output-dir ./reports
```

## Output

Each run writes two reports to the output directory:

- `csf_cctv_report.json` — machine-readable findings (open ports, vendor, weak credentials, exposed streams)
- `csf_cctv_report.html` — client-ready report with risk highlighting

## Legal & Ethical Notice

This tool actively probes network devices, attempts authentication, and reports on exposed video streams. Running it against any device, network, or organization **without explicit written authorization is illegal** in most jurisdictions (e.g. the U.S. Computer Fraud and Abuse Act, UK Computer Misuse Act, Pakistan's PECA 2016) and is a serious invasion of privacy where cameras may capture private spaces.

**Only run this tool against:**
- Systems you own, **or**
- Systems you have documented, written authorization to test.

The tool will refuse to proceed until the operator explicitly confirms authorization at runtime.

## Author

**Cyber Squad Forge (CSF) Research**
Cybersecurity & Research Academy, Karachi

## License

Specify a license (e.g. MIT) before publishing, or mark the repo private if it's for internal/client use only.

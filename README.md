# netscan.py

A single-file, cross-platform network scanner with an interactive ANSI menu. Auto-detects your local network ranges — no IP input required. Built for both daily home/lab network inventory and authorized penetration testing recon.

---

## Features

- **Zero config** — auto-detects all active interfaces and subnets on startup
- **Interactive menu** — ANSI-colored, keyboard-driven interface
- **Capability-aware** — detects available tools at runtime, hides/dims options that require missing dependencies
- **Multiple scan profiles** — Quick, Standard, Full Recon, Custom
- **Environment modes** — Home Network, Lab/Test, Authorized Engagement (with auto audit trail)
- **Rich output** — terminal table + export to JSON, CSV, TXT, HTML, XML
- **Cross-platform** — macOS and Linux

---

## Requirements

- Python 3.8+

### Optional (unlock extra features)

| Package | Feature unlocked |
|---|---|
| `nmap` binary | Full Recon profile (OS detection, service versions, scripts) |
| `python-nmap` | Python interface to nmap |
| `scapy` | ARP sweep — MAC address + vendor detection |
| `netifaces` | More reliable interface/subnet detection |

The script runs with zero optional dependencies — missing tools are detected at startup and unavailable options are hidden or shown with install hints.

---

## Installation

```bash
# Clone or download netscan.py — no install required
chmod +x netscan.py

# Optional: install extras for full capability
pip install python-nmap scapy netifaces

# macOS
brew install nmap

# Linux (Debian/Ubuntu)
sudo apt install nmap

# Linux (RHEL/CentOS)
sudo yum install nmap
```

---

## Usage

```bash
# Standard launch (interactive menu)
python3 netscan.py

# Full capability: raw ICMP ping + ARP sweep (requires root)
sudo python3 netscan.py
```

The script never auto-scans on launch. All actions are user-initiated from the menu.

---

## Menu Overview

```
╔══════════════════════════════════════╗
║        NETSCAN  v1.0                 ║
║  Capabilities: nmap ✓  scapy ✓       ║
╚══════════════════════════════════════╝

MAIN MENU
  [1] Select Environment
  [2] Select Interface / Network
  [3] Select Scan Profile
  [4] Run Scan
  [5] View Last Results
  [6] Export Results
  [7] About / Capability Status
  [0] Exit
```

### Environments

| Environment | Default Profile | nmap Timing | Notes |
|---|---|---|---|
| Home Network | Quick | T3 | Low noise, safe for home gear |
| Lab / Test | Standard | T4 | Moderate, isolated environment |
| Authorized Engagement | Full Recon | T4/T5 | Full nmap, auto-saves all outputs, audit trail |

### Scan Profiles

| Profile | Method | Requires | Speed | Noise |
|---|---|---|---|---|
| Quick | ICMP ping + ARP sweep | stdlib (scapy optional) | ~5s/subnet | Low |
| Standard | Quick + TCP connect top 20 ports | stdlib only | ~30s/subnet | Medium |
| Full Recon | `nmap -A` OS/service/script detection | nmap + python-nmap | ~2–5 min/subnet | High |
| Custom | User-defined ports, timing, flags | varies | varies | varies |

Standard scan covers these ports: `21, 22, 23, 25, 53, 80, 110, 139, 143, 443, 445, 3306, 3389, 5900, 8080, 8443, 8888, 9200, 27017, 6379`

### Export Formats

`JSON` `CSV` `TXT` `HTML` `XML (nmap-compatible)`

Files are named: `netscan_<subnet>_<YYYY-MM-DD>_<HHMMSS>.<ext>`  
Example: `netscan_192.168.1.0-24_2026-05-22_143022.json`

In **Authorized Engagement** mode, all five formats are saved automatically after every scan.

---

## Host Data Collected

| Field | Source |
|---|---|
| IP Address | scan result |
| Hostname | reverse DNS |
| MAC Address | ARP table / nmap |
| Vendor | OUI lookup (bundled ~120-prefix table, no API call) |
| OS Guess | nmap OS detection (Full Recon only) |
| Open Ports + Services | port scan / nmap |
| Response Time (ms) | ping RTT |
| Status | alive / filtered / closed |

---

## Architecture

Single-file Python script, class-based internally.

| Class | Responsibility |
|---|---|
| `CapabilityDetector` | Probes for nmap, scapy, python-nmap, netifaces at startup |
| `NetworkDiscovery` | Auto-detects interfaces and subnets (netifaces → ifconfig → ip addr) |
| `NetworkScanner` | Scanning engine — ping sweep, port scan, full recon, custom scan |
| `MenuEngine` | Interactive ANSI menu, dynamically built from capability profile |
| `OutputManager` | Terminal table + all export formats |

---

## Running Tests

```bash
python3 -m unittest discover -s tests -p "test_netscan.py" -v
```

27 tests covering: OUI lookup, capability detection, interface discovery, ICMP checksum, port parsing, TCP connect, and all export formats.

---

## Constraints

- Authorized use only. Do not scan networks you do not own or have explicit written permission to test.
- Engagement mode requires explicit environment selection — it is not the default.
- No auto-scan on launch.
- Timestamped audit trail is mandatory in Engagement mode.

---

## Platform Notes

- **macOS** — uses `netstat -rn` + `ifconfig` for interface detection. ICMP requires sudo; falls back to subprocess `ping` silently if not root.
- **Linux** — uses `ip route` + `ip addr`. ARP via scapy or `/proc/net/arp`. May require sudo for raw socket operations.
- Privilege detection is automatic via `os.geteuid()`. No crash or prompt if not root — graceful fallback only.

---

## License

MIT

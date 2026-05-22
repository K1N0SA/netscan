#!/usr/bin/env python3
"""netscan.py — Cross-platform network scanner. Auto-detects subnets. Menu-driven.

Usage
  python3 netscan.py             Launch interactive menu
  sudo python3 netscan.py        Full capability (raw ICMP + ARP sweep)

Optional dependencies (enable extra features)
  pip install python-nmap       Full Recon profile (nmap -A)
  pip install scapy             ARP sweep + MAC/vendor detection
  pip install netifaces         Reliable interface detection

Install nmap binary
  macOS:  brew install nmap
  Linux:  apt install nmap  /  yum install nmap
"""

__version__ = "1.0.0"

import csv
import ipaddress
import json
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional

# ── ANSI ──────────────────────────────────────────────────────────────────────
RESET   = "\033[0m";  BOLD  = "\033[1m";  DIM    = "\033[2m"
RED     = "\033[31m"; GREEN = "\033[32m"; YELLOW = "\033[33m"
BLUE    = "\033[34m"; CYAN  = "\033[36m"; WHITE  = "\033[37m"
MAGENTA = "\033[35m"

# ── Data model ────────────────────────────────────────────────────────────────
@dataclass
class Host:
    ip: str
    hostname: str = ""
    mac: str = ""
    vendor: str = ""
    os_guess: str = ""
    open_ports: list = field(default_factory=list)
    services: dict = field(default_factory=dict)
    rtt_ms: float = 0.0
    status: str = "alive"

@dataclass
class ScanResult:
    subnet: str
    profile: str
    environment: str
    started_at: str
    finished_at: str = ""
    hosts: list = field(default_factory=list)

# ── OUI vendor table (~120 common vendor prefixes, compiled from IEEE public data) ──
OUI_TABLE: dict = {
    "00:00:0C": "Cisco",       "00:11:85": "Cisco",       "00:13:60": "Cisco",
    "00:14:A9": "Cisco",       "00:16:C7": "Cisco",       "00:17:59": "Cisco",
    "00:18:B9": "Cisco",       "00:19:30": "Cisco",       "00:1A:E2": "Cisco",
    "00:1B:54": "Cisco",       "00:1C:57": "Cisco",       "00:1D:A2": "Cisco",
    "00:1E:49": "Cisco",       "00:1F:9E": "Cisco",       "00:21:1B": "Cisco",
    "00:22:55": "Cisco",       "00:23:04": "Cisco",       "00:24:14": "Cisco",
    "2C:54:2D": "Cisco",       "DC:EB:94": "Cisco",       "F8:72:EA": "Cisco",
    "00:1D:7E": "Cisco Linksys","00:23:69": "Cisco Linksys","C0:C1:C0": "Cisco Linksys",
    "00:0C:E5": "Cisco Meraki","88:15:44": "Cisco Meraki","AC:17:C8": "Cisco Meraki",
    "E0:55:3D": "Cisco Meraki","0C:8D:DB": "Cisco Meraki","34:56:FE": "Cisco Meraki",
    "00:05:69": "VMware",      "00:0C:29": "VMware",      "00:50:56": "VMware",
    "00:1C:42": "Parallels",   "00:03:FF": "Microsoft",   "00:0D:3A": "Microsoft",
    "00:15:5D": "Microsoft",   "28:18:78": "Microsoft",
    "00:1C:BF": "Apple",       "00:23:32": "Apple",       "A4:5E:60": "Apple",
    "F0:18:98": "Apple",       "3C:15:C2": "Apple",       "00:17:F2": "Apple",
    "00:1E:C2": "Apple",       "00:25:00": "Apple",       "28:37:37": "Apple",
    "AC:BC:32": "Apple",
    "00:1B:21": "Intel",       "00:21:6A": "Intel",       "8C:EC:4B": "Intel",
    "00:1A:A0": "Dell",        "00:14:22": "Dell",        "14:18:77": "Dell",
    "B8:AC:6F": "Dell",        "18:03:73": "Dell",        "18:66:DA": "Dell",
    "24:B6:FD": "Dell",        "34:17:EB": "Dell",        "F0:4D:A2": "Dell",
    "00:16:76": "HP",          "00:17:A4": "HP",          "3C:D9:2B": "HP",
    "D4:85:64": "HP",          "00:1C:C4": "HP",          "FC:15:B4": "HP",
    "00:26:99": "Juniper",     "00:90:69": "Juniper",     "2C:6B:F5": "Juniper",
    "00:09:5B": "Netgear",     "00:0F:B5": "Netgear",     "00:14:6C": "Netgear",
    "00:18:4D": "Netgear",     "20:4E:7F": "Netgear",     "A0:21:B7": "Netgear",
    "00:50:BA": "D-Link",      "00:0F:3D": "D-Link",      "00:11:95": "D-Link",
    "00:15:E9": "D-Link",      "1C:7E:E5": "D-Link",      "28:10:7B": "D-Link",
    "00:1A:2B": "Ubiquiti",    "04:18:D6": "Ubiquiti",    "24:A4:3C": "Ubiquiti",
    "44:D9:E7": "Ubiquiti",    "68:72:51": "Ubiquiti",    "DC:9F:DB": "Ubiquiti",
    "F0:9F:C2": "Ubiquiti",    "80:2A:A8": "Ubiquiti",
    "B8:27:EB": "Raspberry Pi","DC:A6:32": "Raspberry Pi","E4:5F:01": "Raspberry Pi",
    "28:CD:C1": "Raspberry Pi","D8:3A:DD": "Raspberry Pi",
    "00:17:88": "Philips Hue", "EC:B5:FA": "Philips",
    "00:04:4B": "Nvidia",
    "00:1A:11": "Google",      "94:EB:2C": "Google",      "F4:F5:D8": "Google",
    "00:17:EF": "Lenovo",      "18:A9:05": "Lenovo",      "54:EE:75": "Lenovo",
    "00:0D:60": "IBM",         "00:11:25": "IBM",         "08:00:69": "IBM",
    "08:00:20": "Sun Microsystems",
    "B4:FB:E4": "ASUSTek",     "00:0E:A6": "ASUSTek",     "00:11:D8": "ASUSTek",
    "00:22:15": "ASUSTek",     "1C:87:2C": "ASUSTek",     "F4:6D:04": "ASUSTek",
    "10:02:B5": "Samsung",     "00:07:AB": "Samsung",     "00:12:FB": "Samsung",
    "00:26:E9": "Belkin",      "94:44:52": "Belkin",      "EC:1A:59": "Belkin",
    "00:13:EF": "Motorola",    "58:BC:27": "Motorola",
}

def oui_lookup(mac: str) -> str:
    if not mac:
        return ""
    prefix = mac.upper().replace("-", ":")[0:8]
    return OUI_TABLE.get(prefix, "")

# ── CapabilityDetector ────────────────────────────────────────────────────────
class CapabilityDetector:
    def __init__(self):
        self.has_nmap        = shutil.which("nmap") is not None
        self.has_python_nmap = self._check_import("nmap")
        self.has_scapy       = self._check_import("scapy")
        self.has_netifaces   = self._check_import("netifaces")
        self.is_root         = (os.geteuid() == 0) if hasattr(os, "geteuid") else False

    def _check_import(self, name: str) -> bool:
        try:
            __import__(name)
            return True
        except ImportError:
            return False

    def full_recon_available(self) -> bool:
        return self.has_nmap and self.has_python_nmap

    def arp_available(self) -> bool:
        return self.has_scapy and self.is_root

    def summary(self) -> list:
        items = [
            f"nmap {'✓' if self.has_nmap else '✗'}",
            f"python-nmap {'✓' if self.has_python_nmap else '✗'}",
            f"scapy {'✓' if self.has_scapy else '✗'}",
            f"root {'✓' if self.is_root else '✗'}",
        ]
        return items

# ── NetworkDiscovery ──────────────────────────────────────────────────────────
class NetworkDiscovery:
    def __init__(self, has_netifaces: bool):
        self._has_netifaces = has_netifaces

    def get_interfaces(self) -> list:
        if self._has_netifaces:
            return self._netifaces_discovery()
        if sys.platform == "darwin":
            return self._macos_discovery()
        return self._linux_discovery()

    def _netifaces_discovery(self) -> list:
        import netifaces
        interfaces = []
        for name in netifaces.interfaces():
            addrs = netifaces.ifaddresses(name)
            if netifaces.AF_INET not in addrs:
                continue
            for addr in addrs[netifaces.AF_INET]:
                ip      = addr.get("addr", "")
                netmask = addr.get("netmask", "")
                if ip and netmask and not ip.startswith("127."):
                    try:
                        net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                        interfaces.append({"name": name, "ip": ip, "cidr": str(net)})
                    except ValueError:
                        pass
        return interfaces

    def _macos_discovery(self) -> list:
        interfaces = []
        try:
            out = subprocess.check_output(["ifconfig"], text=True, stderr=subprocess.DEVNULL)
            current = None
            for line in out.splitlines():
                m = re.match(r'^(\w[\w.:]+):', line)
                if m:
                    current = m.group(1)
                m = re.search(r'inet (\d+\.\d+\.\d+\.\d+) netmask (0x[0-9a-f]+)', line)
                if m and current:
                    ip       = m.group(1)
                    mask_int = int(m.group(2), 16)
                    netmask  = socket.inet_ntoa(struct.pack(">I", mask_int))
                    if not ip.startswith("127."):
                        try:
                            net = ipaddress.IPv4Network(f"{ip}/{netmask}", strict=False)
                            interfaces.append({"name": current, "ip": ip, "cidr": str(net)})
                        except ValueError:
                            pass
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return interfaces

    def _linux_discovery(self) -> list:
        interfaces = []
        try:
            out = subprocess.check_output(["ip", "addr"], text=True, stderr=subprocess.DEVNULL)
            current = None
            for line in out.splitlines():
                m = re.match(r'^\d+: (\w+):', line)
                if m:
                    current = m.group(1)
                m = re.search(r'inet (\d+\.\d+\.\d+\.\d+/\d+)', line)
                if m and current:
                    cidr = m.group(1)
                    ip   = cidr.split("/")[0]
                    if not ip.startswith("127."):
                        try:
                            net = ipaddress.IPv4Network(cidr, strict=False)
                            interfaces.append({"name": current, "ip": ip, "cidr": str(net)})
                        except ValueError:
                            pass
        except (subprocess.SubprocessError, FileNotFoundError):
            pass
        return interfaces


# ── NetworkScanner ────────────────────────────────────────────────────────────
class NetworkScanner:
    STANDARD_PORTS = [
        21, 22, 23, 25, 53, 80, 110, 139, 143, 443,
        445, 3306, 3389, 5900, 8080, 8443, 8888, 9200, 27017, 6379,
    ]
    _SERVICE_MAP = {
        21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp", 53: "dns",
        80: "http", 110: "pop3", 139: "netbios", 143: "imap",
        443: "https", 445: "smb", 3306: "mysql", 3389: "rdp",
        5900: "vnc", 8080: "http-alt", 8443: "https-alt",
        8888: "http-alt", 9200: "elasticsearch", 27017: "mongodb",
        6379: "redis",
    }

    def __init__(self, caps):
        self._caps = caps

    # ── Ping sweep ────────────────────────────────────────────────────────────
    def ping_sweep(self, subnet: str, callback=None) -> list:
        from concurrent.futures import ThreadPoolExecutor
        network = ipaddress.IPv4Network(subnet, strict=False)
        results = []
        lock = threading.Lock()

        def _probe(ip: str):
            alive, rtt = self._ping(ip)
            if alive:
                host = Host(ip=ip, rtt_ms=rtt)
                self._resolve_hostname(host)
                if self._caps.arp_available():
                    self._arp_mac(host)
                with lock:
                    results.append(host)
            if callback:
                callback(ip, alive)

        with ThreadPoolExecutor(max_workers=50) as pool:
            pool.map(_probe, [str(h) for h in network.hosts()])

        return sorted(results, key=lambda h: ipaddress.IPv4Address(h.ip))

    def _ping(self, ip: str) -> tuple:
        if self._caps.is_root:
            try:
                return self._raw_ping(ip)
            except (PermissionError, OSError):
                pass
        return self._subprocess_ping(ip)

    def _raw_ping(self, ip: str) -> tuple:
        import select
        ICMP_ECHO = 8
        sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        sock.settimeout(1.0)
        ident = os.getpid() & 0xFFFF
        header = struct.pack("bbHHh", ICMP_ECHO, 0, 0, ident, 1)
        data   = b"netscan"
        csum   = self._icmp_checksum(header + data)
        header = struct.pack("bbHHh", ICMP_ECHO, 0, csum, ident, 1)
        start  = time.time()
        try:
            sock.sendto(header + data, (ip, 0))
            r, _, _ = select.select([sock], [], [], 1.0)
            if r:
                rtt = (time.time() - start) * 1000
                return True, round(rtt, 2)
        except Exception:
            pass
        finally:
            sock.close()
        return False, 0.0

    def _icmp_checksum(self, data: bytes) -> int:
        s = 0
        for i in range(0, len(data), 2):
            if i + 1 < len(data):
                s += (data[i] << 8) + data[i + 1]
            else:
                s += data[i]
        s = (s >> 16) + (s & 0xFFFF)
        s += (s >> 16)
        return ~s & 0xFFFF

    def _subprocess_ping(self, ip: str) -> tuple:
        if sys.platform == "win32":
            cmd = ["ping", "-n", "1", ip]
        elif sys.platform == "darwin":
            cmd = ["ping", "-c", "1", "-t", "1", ip]
        else:
            cmd = ["ping", "-c", "1", "-W", "1", ip]
        try:
            start  = time.time()
            result = subprocess.run(
                cmd,
                capture_output=True, text=True, timeout=3,
            )
            rtt = (time.time() - start) * 1000
            return result.returncode == 0, round(rtt, 2)
        except (subprocess.TimeoutExpired, FileNotFoundError):
            return False, 0.0

    def _resolve_hostname(self, host) -> None:
        try:
            host.hostname = socket.gethostbyaddr(host.ip)[0]
        except (socket.herror, socket.gaierror):
            host.hostname = ""

    def _arp_mac(self, host) -> None:
        try:
            from scapy.layers.l2 import ARP, Ether
            from scapy.sendrecv import srp
            pkt = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=host.ip)
            ans, _ = srp(pkt, timeout=1, verbose=False)
            if ans:
                host.mac    = ans[0][1].hwsrc
                host.vendor = oui_lookup(host.mac)
        except Exception:
            pass

    # ── Port scan ─────────────────────────────────────────────────────────────
    def port_scan(self, hosts: list, ports: list = None) -> list:
        if ports is None:
            ports = self.STANDARD_PORTS
        for host in hosts:
            for port in ports:
                if self._tcp_connect(host.ip, port):
                    host.open_ports.append(port)
                    host.services[port] = self._service_name(port)
        return hosts

    def _tcp_connect(self, ip: str, port: int, timeout: float = 0.5) -> bool:
        sock = None
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            return result == 0
        except Exception:
            return False
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass

    def _service_name(self, port: int) -> str:
        return self._SERVICE_MAP.get(port, "unknown")

    def _parse_port_spec(self, spec: str) -> list:
        ports = []
        for part in spec.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports

    # ── Full recon (nmap) ─────────────────────────────────────────────────────
    def full_recon(self, subnet: str, timing: str = "T4", callback=None) -> list:
        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, arguments=f"-{timing} -A --open")
        hosts = []
        for ip in nm.all_hosts():
            h = Host(ip=ip)
            h.hostname = nm[ip].hostname()
            h.status   = nm[ip].state()
            if nm[ip].get("osmatch"):
                h.os_guess = nm[ip]["osmatch"][0]["name"]
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto]:
                    info = nm[ip][proto][port]
                    if info["state"] == "open":
                        h.open_ports.append(port)
                        h.services[port] = info.get("name", "")
            if callback:
                callback(ip, True)
            hosts.append(h)
        return hosts

    # ── Custom scan ───────────────────────────────────────────────────────────
    def custom_scan(self, subnet: str, ports: str, timing: str = "T3", flags: str = "") -> list:
        if not self._caps.full_recon_available():
            try:
                parsed = self._parse_port_spec(ports)
            except ValueError as exc:
                raise ValueError(f"Invalid port specification {ports!r}: {exc}") from exc
            found  = self.ping_sweep(subnet)
            return self.port_scan(found, ports=parsed)
        import nmap
        nm = nmap.PortScanner()
        nm.scan(hosts=subnet, ports=ports, arguments=f"-{timing} {flags}".strip())
        hosts = []
        for ip in nm.all_hosts():
            h = Host(ip=ip)
            h.hostname = nm[ip].hostname()
            for proto in nm[ip].all_protocols():
                for port in nm[ip][proto]:
                    info = nm[ip][proto][port]
                    if info["state"] == "open":
                        h.open_ports.append(port)
                        h.services[port] = info.get("name", "")
            hosts.append(h)
        return hosts


# ── OutputManager ─────────────────────────────────────────────────────────────
class OutputManager:
    def print_table(self, result: ScanResult) -> None:
        print(f"\n  {BOLD}{CYAN}Scan Results — {result.subnet}{RESET}")
        print(f"  {DIM}Profile: {result.profile}  |  Environment: {result.environment}{RESET}")
        print(f"  {DIM}Started: {result.started_at}  |  Finished: {result.finished_at}{RESET}")
        print(f"  Hosts found: {BOLD}{GREEN}{len(result.hosts)}{RESET}\n")

        if not result.hosts:
            print(f"  {DIM}No live hosts found.{RESET}\n")
            return

        w_ip   = max(15, max(len(h.ip)             for h in result.hosts))
        w_host = max(20, max(len(h.hostname[:20])   for h in result.hosts))
        w_vend = max(12, max(len(h.vendor[:12])     for h in result.hosts))
        w_os   = max(16, max(len(h.os_guess[:16])   for h in result.hosts))

        hdr = (f"  {BOLD}{'IP':<{w_ip}}  {'Hostname':<{w_host}}  "
               f"{'MAC':<17}  {'Vendor':<{w_vend}}  "
               f"{'OS':<{w_os}}  {'Ports':<24}  RTT{RESET}")
        sep = "  " + "─" * (w_ip + w_host + 17 + w_vend + w_os + 44)
        print(hdr)
        print(sep)

        for h in result.hosts:
            ports_str = ",".join(str(p) for p in h.open_ports[:6])
            if len(h.open_ports) > 6:
                ports_str += f"+{len(h.open_ports) - 6}"
            print(f"  {GREEN}{h.ip:<{w_ip}}{RESET}  "
                  f"{DIM}{h.hostname[:w_host]:<{w_host}}{RESET}  "
                  f"{DIM}{h.mac:<17}{RESET}  "
                  f"{h.vendor[:w_vend]:<{w_vend}}  "
                  f"{DIM}{h.os_guess[:w_os]:<{w_os}}{RESET}  "
                  f"{CYAN}{ports_str:<24}{RESET}  "
                  f"{DIM}{h.rtt_ms:.1f}{RESET}")
        print()

    def export(self, result: ScanResult, fmt: str, output_dir: str = ".") -> str:
        safe = result.subnet.replace("/", "-").replace(".", "-")
        ts   = datetime.now().strftime("%Y-%m-%d_%H%M%S")
        path = os.path.join(output_dir, f"netscan_{safe}_{ts}.{fmt}")
        dispatch = {
            "json": self._write_json,
            "csv":  self._write_csv,
            "txt":  self._write_txt,
            "html": self._write_html,
            "xml":  self._write_xml,
        }
        writer = dispatch.get(fmt)
        if writer is None:
            raise ValueError(f"Unsupported export format: {fmt!r}. Choose from: {list(dispatch)}")
        writer(result, path)
        return path

    def _write_json(self, result: ScanResult, path: str) -> None:
        data = {
            "subnet": result.subnet, "profile": result.profile,
            "environment": result.environment,
            "started_at": result.started_at, "finished_at": result.finished_at,
            "host_count": len(result.hosts),
            "hosts": [
                {"ip": h.ip, "hostname": h.hostname, "mac": h.mac,
                 "vendor": h.vendor, "os_guess": h.os_guess,
                 "open_ports": h.open_ports, "services": h.services,
                 "rtt_ms": h.rtt_ms, "status": h.status}
                for h in result.hosts
            ],
        }
        with open(path, "w") as f:
            json.dump(data, f, indent=2)

    def _write_csv(self, result: ScanResult, path: str) -> None:
        with open(path, "w", newline="") as f:
            w = csv.writer(f)
            w.writerow(["IP", "Hostname", "MAC", "Vendor", "OS", "Open Ports", "RTT(ms)", "Status"])
            for h in result.hosts:
                w.writerow([h.ip, h.hostname, h.mac, h.vendor, h.os_guess,
                             ";".join(str(p) for p in h.open_ports), h.rtt_ms, h.status])

    def _write_txt(self, result: ScanResult, path: str) -> None:
        with open(path, "w") as f:
            f.write(f"NETSCAN REPORT\nSubnet: {result.subnet}\n"
                    f"Profile: {result.profile}  Environment: {result.environment}\n"
                    f"Started: {result.started_at}  Finished: {result.finished_at}\n"
                    f"Hosts: {len(result.hosts)}\n{'=' * 72}\n\n")
            for h in result.hosts:
                f.write(f"{h.ip}\n")
                if h.hostname:  f.write(f"  Hostname: {h.hostname}\n")
                if h.mac:       f.write(f"  MAC: {h.mac}  Vendor: {h.vendor}\n")
                if h.os_guess:  f.write(f"  OS: {h.os_guess}\n")
                if h.open_ports:
                    ports = ", ".join(f"{p}/{h.services.get(p,'?')}" for p in h.open_ports)
                    f.write(f"  Ports: {ports}\n")
                f.write(f"  RTT: {h.rtt_ms}ms\n\n")

    def _write_html(self, result: ScanResult, path: str) -> None:
        import html as _html
        rows = ""
        for h in result.hosts:
            ports = ", ".join(f"{p}/{_html.escape(h.services.get(p,''))}" for p in h.open_ports)
            rows += (f"<tr><td>{_html.escape(h.ip)}</td><td>{_html.escape(h.hostname)}</td>"
                     f"<td>{_html.escape(h.mac)}</td>"
                     f"<td>{_html.escape(h.vendor)}</td><td>{_html.escape(h.os_guess)}</td>"
                     f"<td>{ports}</td><td>{h.rtt_ms}</td></tr>\n")
        html = (f'<!DOCTYPE html>\n<html><head><meta charset="utf-8">\n'
                f'<title>NETSCAN — {result.subnet}</title>\n'
                f'<style>body{{font-family:monospace;background:#0d1117;color:#e6edf3;padding:2rem}}'
                f'h1{{color:#58a6ff}}table{{border-collapse:collapse;width:100%}}'
                f'th{{background:#161b22;color:#58a6ff;padding:8px 12px;text-align:left}}'
                f'td{{padding:6px 12px;border-bottom:1px solid #21262d}}'
                f'tr:hover td{{background:#161b22}}.meta{{color:#8b949e;font-size:.9rem}}'
                f'</style></head><body>\n'
                f'<h1>NETSCAN Report</h1>\n'
                f'<p class="meta">Subnet: <b>{result.subnet}</b> | Profile: {result.profile} | '
                f'Environment: {result.environment}<br>'
                f'Started: {result.started_at} | Finished: {result.finished_at} | '
                f'Hosts: <b>{len(result.hosts)}</b></p>\n'
                f'<table><tr><th>IP</th><th>Hostname</th><th>MAC</th><th>Vendor</th>'
                f'<th>OS</th><th>Ports</th><th>RTT(ms)</th></tr>\n'
                f'{rows}</table></body></html>')
        with open(path, "w") as f:
            f.write(html)

    def _write_xml(self, result: ScanResult, path: str) -> None:
        from xml.sax.saxutils import quoteattr
        host_blocks = ""
        for h in result.hosts:
            ports_xml = "".join(
                f'      <port protocol="tcp" portid="{p}">'
                f'<state state="open"/><service name={quoteattr(h.services.get(p, ""))}/></port>\n'
                for p in h.open_ports
            )
            mac_tag = (f'<address addr={quoteattr(h.mac)} addrtype="mac" vendor={quoteattr(h.vendor)}/>'
                       if h.mac else "")
            hn_tag  = f'<hostname name={quoteattr(h.hostname)}/>' if h.hostname else ""
            os_tag  = (f'<os><osmatch name={quoteattr(h.os_guess)} accuracy="90"/></os>'
                       if h.os_guess else "")
            host_blocks += (f'  <host>\n'
                            f'    <address addr="{h.ip}" addrtype="ipv4"/>\n'
                            f'    {mac_tag}\n'
                            f'    <hostnames>{hn_tag}</hostnames>\n'
                            f'    <ports>\n{ports_xml}    </ports>\n'
                            f'    {os_tag}\n'
                            f'    <times rtt="{int(h.rtt_ms * 1000)}"/>\n'
                            f'  </host>\n')
        xml = (f'<?xml version="1.0"?>\n'
               f'<nmaprun scanner="netscan" version="{__version__}" '
               f'start="{result.started_at}">\n'
               f'  <scaninfo type="{result.profile}" protocol="tcp"/>\n'
               f'{host_blocks}'
               f'  <runstats><hosts up="{len(result.hosts)}" down="0" '
               f'total="{len(result.hosts)}"/></runstats>\n'
               f'</nmaprun>')
        with open(path, "w") as f:
            f.write(xml)


# ── MenuEngine ────────────────────────────────────────────────────────────────
class MenuEngine:
    ENVIRONMENTS = {
        "1": ("Home Network",          "quick",    "T3"),
        "2": ("Lab / Test",            "standard", "T4"),
        "3": ("Authorized Engagement", "full",     "T4"),
    }
    PROFILES = {"1": "quick", "2": "standard", "3": "full", "4": "custom"}

    def __init__(self, caps, discovery, scanner, output):
        self._caps        = caps
        self._discovery   = discovery
        self._scanner     = scanner
        self._output      = output
        self._environment = "Home Network"
        self._profile     = "quick"
        self._timing      = "T3"
        self._interfaces  = []
        self._selected    = {}
        self._last_result = None
        self._output_dir  = "."
        self._custom_ports   = "80,443,22,8080"
        self._custom_timing  = "T3"
        self._custom_flags   = ""

    def run(self) -> None:
        self._interfaces = self._discovery.get_interfaces()
        if self._interfaces:
            self._selected = self._interfaces[0]
        while True:
            self._print_header()
            self._print_main_menu()
            choice = input(f"\n  {BOLD}Select>{RESET} ").strip()
            if   choice == "0": print(f"\n  {DIM}Goodbye.{RESET}\n"); break
            elif choice == "1": self._menu_environment()
            elif choice == "2": self._menu_interface()
            elif choice == "3": self._menu_profile()
            elif choice == "4": self._run_scan()
            elif choice == "5": self._view_results()
            elif choice == "6": self._menu_export()
            elif choice == "7": self._show_about()
            else: print(f"  {RED}Invalid choice.{RESET}")

    def _print_header(self) -> None:
        caps_str = "  ".join(self._caps.summary())
        print(f"\n  {BOLD}{CYAN}╔{'═' * 44}╗{RESET}")
        print(f"  {BOLD}{CYAN}║  NETSCAN v{__version__:<34}║{RESET}")
        print(f"  {BOLD}{CYAN}║  {caps_str:<42}║{RESET}")
        print(f"  {BOLD}{CYAN}╚{'═' * 44}╝{RESET}")

    def _print_main_menu(self) -> None:
        subnet = self._selected.get("cidr", "none selected")
        iface  = self._selected.get("name", "–")
        print(f"\n  {BOLD}MAIN MENU{RESET}")
        print(f"  {DIM}Environment : {self._environment}  |  Interface : {iface} ({subnet})  |  Profile : {self._profile}{RESET}\n")
        print(f"  {CYAN}[1]{RESET} Select Environment")
        print(f"  {CYAN}[2]{RESET} Select Interface / Network")
        print(f"  {CYAN}[3]{RESET} Select Scan Profile")
        print(f"  {CYAN}[4]{RESET} {BOLD}Run Scan{RESET}")
        print(f"  {CYAN}[5]{RESET} View Last Results")
        print(f"  {CYAN}[6]{RESET} Export Results")
        print(f"  {CYAN}[7]{RESET} About / Capability Status")
        print(f"  {CYAN}[0]{RESET} Exit")

    def _menu_environment(self) -> None:
        print(f"\n  {BOLD}SELECT ENVIRONMENT{RESET}")
        for k, (name, _, _) in self.ENVIRONMENTS.items():
            print(f"  [{k}] {name}")
        print(f"  [0] Back")
        choice = input(f"\n  {BOLD}Select>{RESET} ").strip()
        if choice in self.ENVIRONMENTS:
            name, profile, timing = self.ENVIRONMENTS[choice]
            self._environment = name
            self._profile     = profile
            self._timing      = timing
            print(f"  {GREEN}Set: {name} (default profile: {profile}){RESET}")

    def _menu_interface(self) -> None:
        print(f"\n  {BOLD}SELECT INTERFACE{RESET}")
        for i, iface in enumerate(self._interfaces, 1):
            print(f"  [{i}] {iface['name']:<10} {iface['cidr']}")
        print(f"  [M] Enter manual CIDR")
        print(f"  [0] Back")
        choice = input(f"\n  {BOLD}Select>{RESET} ").strip()
        if choice.isdigit() and 1 <= int(choice) <= len(self._interfaces):
            self._selected = self._interfaces[int(choice) - 1]
        elif choice.upper() == "M":
            cidr = input("  Enter CIDR (e.g. 192.168.1.0/24): ").strip()
            try:
                ipaddress.IPv4Network(cidr, strict=False)
                self._selected = {"name": "manual", "cidr": cidr}
            except ValueError:
                print(f"  {RED}Invalid CIDR.{RESET}")

    def _menu_profile(self) -> None:
        print(f"\n  {BOLD}SELECT SCAN PROFILE{RESET}")
        print(f"  [1] Quick       — ICMP ping + ARP sweep")
        print(f"  [2] Standard    — Quick + top 20 ports TCP connect")
        if self._caps.full_recon_available():
            print(f"  [3] Full Recon  — nmap -A (OS, services, scripts)")
        else:
            print(f"  {DIM}[3] Full Recon  — requires: brew install nmap && pip install python-nmap{RESET}")
        print(f"  [4] Custom      — define ports, timing, flags")
        print(f"  [0] Back")
        choice = input(f"\n  {BOLD}Select>{RESET} ").strip()
        if choice == "3" and not self._caps.full_recon_available():
            print(f"  {YELLOW}nmap unavailable. Install: brew install nmap && pip install python-nmap{RESET}")
            return
        if choice in self.PROFILES:
            self._profile = self.PROFILES[choice]
            if choice == "4":
                self._configure_custom()

    def _configure_custom(self) -> None:
        print(f"\n  {BOLD}CUSTOM SCAN CONFIGURATION{RESET}")
        ports = input(f"  Ports (e.g. 80,443,8080-8090) [{self._custom_ports}]: ").strip()
        if ports:
            self._custom_ports = ports
        timing = input(f"  Timing T1-T5 [{self._custom_timing}]: ").strip()
        if timing and len(timing) == 2 and timing[0] == "T" and timing[1] in "12345":
            self._custom_timing = timing
        if self._caps.has_nmap:
            flags = input(f"  Extra nmap flags (e.g. -sV -O) [{self._custom_flags}]: ").strip()
            if flags:
                self._custom_flags = flags

    def _run_scan(self) -> None:
        subnet = self._selected.get("cidr", "")
        if not subnet:
            print(f"  {RED}No interface selected. Choose [2] first.{RESET}")
            return
        network    = ipaddress.IPv4Network(subnet, strict=False)
        host_count = network.num_addresses - 2
        print(f"\n  {BOLD}Starting {self._profile} scan — {subnet} ({host_count} hosts){RESET}")
        print(f"  {DIM}Ctrl+C to abort{RESET}\n")
        started = datetime.now().isoformat(timespec="seconds")
        result  = ScanResult(subnet=subnet, profile=self._profile,
                             environment=self._environment, started_at=started)
        counter = {"found": 0, "scanned": 0}
        lock    = threading.Lock()

        def _progress(ip: str, alive: bool) -> None:
            with lock:
                counter["scanned"] += 1
                if alive:
                    counter["found"] += 1
            pct = int(counter["scanned"] / max(host_count, 1) * 100)
            bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
            print(f"\r  [{bar}] {pct:3d}%  {counter['found']} alive  {ip:<15}", end="", flush=True)

        try:
            if self._profile == "quick":
                result.hosts = self._scanner.ping_sweep(subnet, callback=_progress)
            elif self._profile == "standard":
                result.hosts = self._scanner.ping_sweep(subnet, callback=_progress)
                print(f"\n  {DIM}Port scanning {len(result.hosts)} live hosts...{RESET}")
                result.hosts = self._scanner.port_scan(result.hosts)
            elif self._profile == "full":
                result.hosts = self._scanner.full_recon(subnet, timing=self._timing, callback=_progress)
            elif self._profile == "custom":
                result.hosts = self._scanner.custom_scan(
                    subnet, self._custom_ports, self._custom_timing, self._custom_flags)
        except KeyboardInterrupt:
            print(f"\n  {YELLOW}Scan aborted.{RESET}")

        result.finished_at = datetime.now().isoformat(timespec="seconds")
        self._last_result  = result
        print()
        self._output.print_table(result)

        if self._environment == "Authorized Engagement":
            print(f"  {DIM}Engagement mode — auto-saving all formats to {self._output_dir}{RESET}")
            for fmt in ["json", "csv", "txt", "html", "xml"]:
                path = self._output.export(result, fmt, self._output_dir)
                print(f"  {GREEN}Saved:{RESET} {path}")

    def _view_results(self) -> None:
        if not self._last_result:
            print(f"  {DIM}No scan results yet. Run [4] first.{RESET}")
            return
        self._output.print_table(self._last_result)

    def _menu_export(self) -> None:
        if not self._last_result:
            print(f"  {DIM}No results to export. Run [4] first.{RESET}")
            return
        print(f"\n  {BOLD}EXPORT RESULTS{RESET}")
        print(f"  [1] JSON    [2] CSV     [3] TXT")
        print(f"  [4] HTML    [5] XML     [6] All formats")
        print(f"  [D] Set output directory (current: {self._output_dir})")
        print(f"  [0] Back")
        choice   = input(f"\n  {BOLD}Select>{RESET} ").strip().upper()
        fmt_map  = {"1": "json", "2": "csv", "3": "txt", "4": "html", "5": "xml"}
        if choice == "D":
            d = input(f"  Directory [{self._output_dir}]: ").strip()
            if d and os.path.isdir(d):
                self._output_dir = d
            elif d:
                print(f"  {RED}Directory not found.{RESET}")
        elif choice == "6":
            for fmt in ["json", "csv", "txt", "html", "xml"]:
                path = self._output.export(self._last_result, fmt, self._output_dir)
                print(f"  {GREEN}Saved:{RESET} {path}")
        elif choice in fmt_map:
            path = self._output.export(self._last_result, fmt_map[choice], self._output_dir)
            print(f"  {GREEN}Saved:{RESET} {path}")

    def _show_about(self) -> None:
        print(f"\n  {BOLD}NETSCAN v{__version__}{RESET}  Cross-platform network scanner. macOS + Linux.")
        print(f"\n  {BOLD}Capability Status:{RESET}")
        checks = [
            ("nmap binary",  self._caps.has_nmap,        "brew install nmap  /  apt install nmap"),
            ("python-nmap",  self._caps.has_python_nmap,  "pip install python-nmap"),
            ("scapy",        self._caps.has_scapy,        "pip install scapy"),
            ("netifaces",    self._caps.has_netifaces,    "pip install netifaces"),
            ("root/sudo",    self._caps.is_root,          "run with: sudo python3 netscan.py"),
        ]
        for name, ok, hint in checks:
            icon   = f"{GREEN}✓{RESET}" if ok else f"{RED}✗{RESET}"
            hint_s = f"  {DIM}{hint}{RESET}" if not ok else ""
            print(f"  {icon} {name:<16}{hint_s}")
        print()


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    caps      = CapabilityDetector()
    discovery = NetworkDiscovery(caps.has_netifaces)
    scanner   = NetworkScanner(caps)
    output    = OutputManager()
    MenuEngine(caps, discovery, scanner, output).run()


if __name__ == "__main__":
    main()

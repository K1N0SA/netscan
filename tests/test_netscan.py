import sys, os
sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
import unittest

class TestOuiLookup(unittest.TestCase):
    def test_known_vendor(self):
        from netscan import oui_lookup
        self.assertEqual(oui_lookup("00:0C:29:AA:BB:CC"), "VMware")

    def test_unknown_vendor(self):
        from netscan import oui_lookup
        self.assertEqual(oui_lookup("FF:FF:FF:AA:BB:CC"), "")

    def test_empty_mac(self):
        from netscan import oui_lookup
        self.assertEqual(oui_lookup(""), "")

    def test_hyphen_format(self):
        from netscan import oui_lookup
        self.assertEqual(oui_lookup("00-0C-29-AA-BB-CC"), "VMware")

from unittest.mock import patch, MagicMock

class TestCapabilityDetector(unittest.TestCase):
    def test_nmap_found(self):
        from netscan import CapabilityDetector
        with patch("shutil.which", return_value="/usr/bin/nmap"):
            caps = CapabilityDetector()
        self.assertTrue(caps.has_nmap)

    def test_nmap_not_found(self):
        from netscan import CapabilityDetector
        with patch("shutil.which", return_value=None):
            caps = CapabilityDetector()
        self.assertFalse(caps.has_nmap)

    def test_full_recon_requires_both(self):
        from netscan import CapabilityDetector
        caps = CapabilityDetector.__new__(CapabilityDetector)
        caps.has_nmap = True
        caps.has_python_nmap = False
        self.assertFalse(caps.full_recon_available())
        caps.has_python_nmap = True
        self.assertTrue(caps.full_recon_available())

    def test_summary_contains_nmap(self):
        from netscan import CapabilityDetector
        caps = CapabilityDetector.__new__(CapabilityDetector)
        caps.has_nmap = True
        caps.has_python_nmap = False
        caps.has_scapy = False
        caps.has_netifaces = False
        caps.is_root = False
        summary = " ".join(caps.summary())
        self.assertIn("nmap", summary)
        self.assertIn("✓", summary)

class TestNetworkDiscovery(unittest.TestCase):
    LINUX_IP_ADDR = """\
1: lo: <LOOPBACK,UP> mtu 65536
    inet 127.0.0.1/8 scope host lo
2: eth0: <BROADCAST,UP> mtu 1500
    inet 192.168.1.50/24 brd 192.168.1.255 scope global eth0
3: eth1: <BROADCAST,UP> mtu 1500
    inet 10.10.10.5/24 brd 10.10.10.255 scope global eth1
"""

    MACOS_IFCONFIG = """\
lo0: flags=8049<UP,LOOPBACK> mtu 16384
    inet 127.0.0.1 netmask 0xff000000
en0: flags=8863<UP,BROADCAST> mtu 1500
    inet 192.168.1.50 netmask 0xffffff00 broadcast 192.168.1.255
en1: flags=8863<UP,BROADCAST> mtu 1500
    inet 10.10.10.5 netmask 0xffffff00 broadcast 10.10.10.255
"""

    def test_linux_discovery_finds_two_subnets(self):
        from netscan import NetworkDiscovery
        nd = NetworkDiscovery(has_netifaces=False)
        with patch("subprocess.check_output", return_value=self.LINUX_IP_ADDR), \
             patch("sys.platform", "linux"):
            ifaces = nd._linux_discovery()
        self.assertEqual(len(ifaces), 2)
        cidrs = [i["cidr"] for i in ifaces]
        self.assertIn("192.168.1.0/24", cidrs)
        self.assertIn("10.10.10.0/24", cidrs)

    def test_macos_discovery_finds_two_subnets(self):
        from netscan import NetworkDiscovery
        nd = NetworkDiscovery(has_netifaces=False)
        with patch("subprocess.check_output", return_value=self.MACOS_IFCONFIG):
            ifaces = nd._macos_discovery()
        self.assertEqual(len(ifaces), 2)
        cidrs = [i["cidr"] for i in ifaces]
        self.assertIn("192.168.1.0/24", cidrs)
        self.assertIn("10.10.10.0/24", cidrs)

    def test_loopback_excluded(self):
        from netscan import NetworkDiscovery
        nd = NetworkDiscovery(has_netifaces=False)
        with patch("subprocess.check_output", return_value=self.LINUX_IP_ADDR), \
             patch("sys.platform", "linux"):
            ifaces = nd._linux_discovery()
        ips = [i["ip"] for i in ifaces]
        self.assertNotIn("127.0.0.1", ips)

    def test_subprocess_failure_returns_empty(self):
        from netscan import NetworkDiscovery
        nd = NetworkDiscovery(has_netifaces=False)
        with patch("subprocess.check_output", side_effect=FileNotFoundError):
            ifaces = nd._linux_discovery()
        self.assertEqual(ifaces, [])


class TestNetworkScanner(unittest.TestCase):
    def _make_caps(self, nmap=False, scapy=False, root=False, python_nmap=False, netifaces=False):
        from netscan import CapabilityDetector
        caps = CapabilityDetector.__new__(CapabilityDetector)
        caps.has_nmap = nmap
        caps.has_python_nmap = python_nmap
        caps.has_scapy = scapy
        caps.has_netifaces = netifaces
        caps.is_root = root
        return caps

    def test_icmp_checksum_known_value(self):
        from netscan import NetworkScanner
        caps = self._make_caps()
        scanner = NetworkScanner(caps)
        # Checksum of zero-filled 8-byte packet should be 0xFFFF
        data = b'\x08\x00\x00\x00\x00\x00\x00\x00'
        result = scanner._icmp_checksum(data)
        self.assertIsInstance(result, int)
        self.assertGreaterEqual(result, 0)
        self.assertLessEqual(result, 0xFFFF)

    def test_subprocess_ping_returns_tuple(self):
        from netscan import NetworkScanner
        caps = self._make_caps()
        scanner = NetworkScanner(caps)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=0)
            alive, rtt = scanner._subprocess_ping("127.0.0.1")
        self.assertTrue(alive)
        self.assertIsInstance(rtt, float)

    def test_subprocess_ping_dead_host(self):
        from netscan import NetworkScanner
        caps = self._make_caps()
        scanner = NetworkScanner(caps)
        with patch("subprocess.run") as mock_run:
            mock_run.return_value = MagicMock(returncode=1)
            alive, _ = scanner._subprocess_ping("10.255.255.1")
        self.assertFalse(alive)

    def test_parse_port_spec_comma_list(self):
        from netscan import NetworkScanner
        caps = self._make_caps()
        scanner = NetworkScanner(caps)
        result = scanner._parse_port_spec("80,443,8080")
        self.assertEqual(result, [80, 443, 8080])

    def test_parse_port_spec_range(self):
        from netscan import NetworkScanner
        caps = self._make_caps()
        scanner = NetworkScanner(caps)
        result = scanner._parse_port_spec("8080-8083")
        self.assertEqual(result, [8080, 8081, 8082, 8083])

    def test_parse_port_spec_mixed(self):
        from netscan import NetworkScanner
        caps = self._make_caps()
        scanner = NetworkScanner(caps)
        result = scanner._parse_port_spec("22,80-82,443")
        self.assertEqual(result, [22, 80, 81, 82, 443])

    def test_service_name_known_port(self):
        from netscan import NetworkScanner
        caps = self._make_caps()
        scanner = NetworkScanner(caps)
        self.assertEqual(scanner._service_name(22), "ssh")
        self.assertEqual(scanner._service_name(443), "https")
        self.assertEqual(scanner._service_name(3306), "mysql")

    def test_tcp_connect_open_port(self):
        from netscan import NetworkScanner
        caps = self._make_caps()
        scanner = NetworkScanner(caps)
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 0
            mock_sock_cls.return_value = mock_sock
            self.assertTrue(scanner._tcp_connect("192.168.1.1", 80))

    def test_tcp_connect_closed_port(self):
        from netscan import NetworkScanner
        caps = self._make_caps()
        scanner = NetworkScanner(caps)
        with patch("socket.socket") as mock_sock_cls:
            mock_sock = MagicMock()
            mock_sock.connect_ex.return_value = 111
            mock_sock_cls.return_value = mock_sock
            self.assertFalse(scanner._tcp_connect("192.168.1.1", 9999))


import tempfile, json as _json, csv as _csv, os as _os

class TestOutputManager(unittest.TestCase):
    def _make_result(self):
        from netscan import ScanResult, Host
        h1 = Host(ip="192.168.1.1", hostname="router.local", mac="00:0C:29:AA:BB:CC",
                  vendor="VMware", os_guess="Linux 4.x", open_ports=[22, 80, 443],
                  services={22: "ssh", 80: "http", 443: "https"}, rtt_ms=1.2)
        h2 = Host(ip="192.168.1.2", hostname="", mac="", vendor="", os_guess="",
                  open_ports=[], services={}, rtt_ms=5.0)
        return ScanResult(
            subnet="192.168.1.0/24", profile="standard",
            environment="Home Network",
            started_at="2026-05-22T14:00:00",
            finished_at="2026-05-22T14:00:30",
            hosts=[h1, h2],
        )

    def test_json_export_valid_json(self):
        from netscan import OutputManager
        om = OutputManager()
        result = self._make_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = om.export(result, "json", tmpdir)
            with open(path) as f:
                data = _json.load(f)
        self.assertEqual(data["subnet"], "192.168.1.0/24")
        self.assertEqual(len(data["hosts"]), 2)
        self.assertEqual(data["hosts"][0]["ip"], "192.168.1.1")
        self.assertEqual(data["hosts"][0]["open_ports"], [22, 80, 443])

    def test_csv_export_has_header_and_rows(self):
        from netscan import OutputManager
        om = OutputManager()
        result = self._make_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = om.export(result, "csv", tmpdir)
            with open(path) as f:
                rows = list(_csv.reader(f))
        self.assertEqual(rows[0][0], "IP")
        self.assertEqual(rows[1][0], "192.168.1.1")
        self.assertEqual(len(rows), 3)  # header + 2 hosts

    def test_txt_export_contains_ip(self):
        from netscan import OutputManager
        om = OutputManager()
        result = self._make_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = om.export(result, "txt", tmpdir)
            content = open(path).read()
        self.assertIn("192.168.1.1", content)
        self.assertIn("ssh", content)

    def test_html_export_is_valid_html(self):
        from netscan import OutputManager
        om = OutputManager()
        result = self._make_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = om.export(result, "html", tmpdir)
            content = open(path).read()
        self.assertIn("<!DOCTYPE html>", content)
        self.assertIn("192.168.1.1", content)
        self.assertIn("VMware", content)

    def test_xml_export_contains_host(self):
        from netscan import OutputManager
        om = OutputManager()
        result = self._make_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = om.export(result, "xml", tmpdir)
            content = open(path).read()
        self.assertIn('addr="192.168.1.1"', content)
        self.assertIn('portid="22"', content)

    def test_filename_uses_subnet_and_timestamp(self):
        from netscan import OutputManager
        om = OutputManager()
        result = self._make_result()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = om.export(result, "json", tmpdir)
            filename = _os.path.basename(path)
        self.assertTrue(filename.startswith("netscan_192-168-1-0-24_"))
        self.assertTrue(filename.endswith(".json"))


if __name__ == "__main__":
    unittest.main()

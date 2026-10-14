import socket
import concurrent.futures
from core.base_module import BaseModule
from core.utils import print_status
from core.config import Config


COMMON_SERVICES = {
    21: "FTP", 22: "SSH", 23: "Telnet", 25: "SMTP", 53: "DNS",
    80: "HTTP", 110: "POP3", 111: "RPCBind", 135: "MSRPC", 139: "NetBIOS",
    143: "IMAP", 443: "HTTPS", 445: "SMB", 465: "SMTPS", 587: "Submission",
    993: "IMAPS", 995: "POP3S", 1433: "MSSQL", 1521: "Oracle", 1723: "PPTP",
    3306: "MySQL", 3389: "RDP", 5432: "PostgreSQL", 5900: "VNC",
    6379: "Redis", 8080: "HTTP-Alt", 8443: "HTTPS-Alt", 8888: "HTTP-Alt2",
    9090: "WebConsole", 27017: "MongoDB",
}

HTTP_PORTS = {80, 81, 82, 83, 84, 85, 86, 88, 591, 2082, 2095, 2096, 3000, 5000, 8000, 8008, 8080, 8081, 8443, 8888, 9000, 9090}
TLS_PORTS = {443, 465, 636, 993, 995, 8443, 9443}


def _grab_banner(sock, port):
    try:
        sock.settimeout(2.5)
        if port in HTTP_PORTS:
            sock.sendall(b"HEAD / HTTP/1.0\r\nHost: scan\r\nUser-Agent: osintconsole\r\n\r\n")
            data = sock.recv(2048)
            return data.decode('utf-8', errors='replace').split('\r\n\r\n', 1)[0]
        # For SSH/SMTP/FTP/POP3/IMAP: server speaks first - just receive.
        if port in (21, 22, 25, 110, 143, 587, 2525):
            data = sock.recv(1024)
            return data.decode('utf-8', errors='replace').strip()
        if port in TLS_PORTS:
            return "(TLS - banner probe skipped)"
        # Everything else: single short recv then close. No HEAD-poisoning.
        data = sock.recv(512)
        return data.decode('utf-8', errors='replace').strip() if data else ""
    except Exception:
        return ""


class PortScan(BaseModule):
    name = "recon/port_scan"
    description = "TCP port scanner with service detection and banner grabbing"
    category = "recon"
    target_type = "domain/ip"
    intrusive = True

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target IP or domain")
        self.add_option("PORTS", "top", False, "Ports to scan: 'top', 'all', '1-1000', '80,443,8080'")
        self.add_option("THREADS", "50", False, "Number of threads")
        self.add_option("TIMEOUT", "2", False, "Connection timeout in seconds")
        self.add_option("BANNER", "true", False, "Attempt banner grabbing")

    def _parse_ports(self, ports_str):
        if ports_str == "top":
            config = Config()
            return config.get("port_scan.top_ports", list(COMMON_SERVICES.keys()))
        if ports_str == "all":
            return list(range(1, 65536))
        ports = []
        for part in ports_str.split(","):
            part = part.strip()
            if "-" in part:
                start, end = part.split("-", 1)
                ports.extend(range(int(start), int(end) + 1))
            else:
                ports.append(int(part))
        return ports

    def _scan_port(self, ip, port, timeout):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            result = sock.connect_ex((ip, port))
            if result == 0:
                banner = ""
                if self.get_option("BANNER").lower() == "true":
                    banner = _grab_banner(sock, port)
                sock.close()
                return port, banner
            sock.close()
        except Exception:
            pass
        return None, None

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        ports_str = self.get_option("PORTS") or "top"
        threads = int(self.get_option("THREADS") or 50)
        timeout = float(self.get_option("TIMEOUT") or 2)

        try:
            ip = socket.gethostbyname(target)
        except socket.gaierror:
            print_status(f"Cannot resolve {target}", "error")
            return False

        ports = self._parse_ports(ports_str)
        print_status(f"Scanning {target} ({ip}) - {len(ports)} ports with {threads} threads", "info")

        open_ports = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {executor.submit(self._scan_port, ip, p, timeout): p for p in ports}
            for future in concurrent.futures.as_completed(futures):
                port, banner = future.result()
                if port is not None:
                    service = COMMON_SERVICES.get(port, "unknown")
                    entry = {
                        "port": port,
                        "state": "open",
                        "service": service,
                        "banner": banner[:200] if banner else "",
                    }
                    open_ports.append(entry)
                    banner_info = f" | {banner[:60]}" if banner else ""
                    print_status(f"Port {port}/tcp open - {service}{banner_info}", "success")

        open_ports.sort(key=lambda x: x["port"])
        self.results = {
            "target": target,
            "ip": ip,
            "ports_scanned": len(ports),
            "open_ports": open_ports,
            "total_open": len(open_ports),
        }

        print_status(f"Scan complete. {len(open_ports)} open ports found", "info")
        return True

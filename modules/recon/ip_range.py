import socket
import ipaddress
import itertools
from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule
from core.utils import print_status


class IpRange(BaseModule):
    name = "recon/ip_range"
    description = "Expand a CIDR/IP and find live hosts via TCP connect on ports 80/443"
    category = "recon"
    target_type = "ip/cidr"
    intrusive = True

    CHECK_PORTS = (80, 443)
    MAX_HOSTS = 1024

    def _register_options(self):
        self.add_option("TARGET", "", True, "CIDR range (e.g. 1.2.3.0/24) or a single IP")
        self.add_option("THREADS", "50", False, "Number of concurrent threads")
        self.add_option("TIMEOUT", "2", False, "TCP connect timeout in seconds")

    def _check_host(self, ip, timeout):
        open_ports = []
        for port in self.CHECK_PORTS:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            try:
                if sock.connect_ex((ip, port)) == 0:
                    open_ports.append(port)
            except Exception:
                pass
            finally:
                try:
                    sock.close()
                except Exception:
                    pass
        if open_ports:
            return {"ip": ip, "open_ports": open_ports}
        return None

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip()
        try:
            threads = max(1, int(self.get_option("THREADS") or 50))
        except ValueError:
            threads = 50
        try:
            timeout = float(self.get_option("TIMEOUT") or 2)
        except ValueError:
            timeout = 2.0

        try:
            if "/" in target:
                network = ipaddress.ip_network(target, strict=False)
            else:
                # Validates IPv4/IPv6 and normalises to a single-host network.
                addr = ipaddress.ip_address(target)
                network = ipaddress.ip_network(
                    f"{target}/{addr.max_prefixlen}", strict=False
                )
        except ValueError as e:
            print_status(f"Invalid CIDR/IP '{target}': {e}", "error")
            return False

        # Use num_addresses to avoid materialising huge generators (e.g. /8).
        if network.num_addresses > self.MAX_HOSTS + 2:
            print_status(
                f"{network} has {network.num_addresses} addresses; "
                f"capping scan to {self.MAX_HOSTS} hosts",
                "warning",
            )
            hosts = list(itertools.islice(network.hosts(), self.MAX_HOSTS))
        else:
            hosts = list(network.hosts())
            if not hosts:  # single-host /32 (or /128)
                hosts = [network.network_address]

        total = len(hosts)
        print_status(
            f"Scanning {total} host(s) in {network} on ports "
            f"{list(self.CHECK_PORTS)} with {threads} threads...",
            "info",
        )

        alive = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            futures = {
                executor.submit(self._check_host, str(h), timeout): h for h in hosts
            }
            for future in as_completed(futures):
                res = future.result()
                if res:
                    alive.append(res)
                    print_status(
                        f"{res['ip']} is alive (open: {res['open_ports']})", "success"
                    )

        alive.sort(key=lambda x: ipaddress.ip_address(x["ip"]))

        self.results = {
            "cidr": str(network),
            "total_hosts": total,
            "alive": alive,
            "alive_count": len(alive),
        }

        print_status(f"Scan complete. {len(alive)} alive of {total} host(s) scanned", "info")
        return True

"""Mail infrastructure inspection for a domain.

Enumerates MX records, reads the top MX host's SMTP banner + EHLO capabilities
(STARTTLS / advertised AUTH mechanisms only -- no relay testing, no VRFY), and
fetches SPF and DMARC policy records. All network ops are wrapped so a blocked
port 25 (common on many networks) degrades gracefully. REAL data only.
"""
import socket

try:
    import dns.resolver
    _DNS_OK = True
except Exception:
    _DNS_OK = False

from core.base_module import BaseModule
from core.utils import print_status, is_valid_domain


class EmailServer(BaseModule):
    name = "recon/email_server"
    description = "Inspect mail infra: MX, SMTP banner/EHLO, STARTTLS, SPF, DMARC"
    category = "recon"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain")
        self.add_option("DNS_SERVER", "", False,
                        "Resolver to query (blank = system default)")

    def _build_resolver(self):
        resolver = dns.resolver.Resolver()
        server = (self.get_option("DNS_SERVER") or "").strip()
        if server:
            resolver.nameservers = [server]
        resolver.timeout = 8
        resolver.lifetime = 12
        return resolver

    @staticmethod
    def _txt_value(rdata):
        try:
            return b"".join(rdata.strings).decode("utf-8", errors="replace")
        except Exception:
            return str(rdata).strip('"')

    @staticmethod
    def _read_smtp(sock):
        """Read one (possibly multiline) SMTP response."""
        data = b""
        try:
            while True:
                chunk = sock.recv(4096)
                if not chunk:
                    break
                data += chunk
                text = data.decode("utf-8", errors="replace")
                lines = [l for l in text.split("\r\n") if l.strip()]
                if lines:
                    last = lines[-1]
                    # Final line: "NNN " (space after code), not "NNN-".
                    if len(last) >= 4 and last[3] == " ":
                        break
                    if len(last) == 3 and last.isdigit():
                        break
        except socket.timeout:
            pass
        except Exception:
            pass
        return data.decode("utf-8", errors="replace")

    def _probe_smtp(self, host):
        """Return (banner, starttls, auth_list, reachable, note)."""
        banner, starttls, auth, note = "", False, [], ""
        sock = None
        try:
            sock = socket.create_connection((host, 25), timeout=8)
            sock.settimeout(8)
            banner = self._read_smtp(sock).strip()
            if banner:
                print_status(f"SMTP banner: {banner.splitlines()[0]}", "success")

            sock.sendall(b"EHLO osintconsole.local\r\n")
            caps = self._read_smtp(sock)

            seen = set()
            for line in caps.splitlines():
                body = line[4:].strip() if len(line) >= 4 else line.strip()
                upper = body.upper()
                if upper.startswith("STARTTLS"):
                    starttls = True
                if upper.startswith("AUTH"):
                    for mech in body.split()[1:]:
                        m = mech.upper()
                        if m and m not in seen:
                            seen.add(m)
                            auth.append(m)

            try:
                sock.sendall(b"QUIT\r\n")
            except Exception:
                pass
            return banner, starttls, auth, True, "connected"
        except socket.timeout:
            note = "SMTP unreachable: connection timed out (port 25 likely blocked)"
            print_status(note, "warning")
        except (ConnectionRefusedError, OSError) as e:
            note = f"SMTP unreachable: {e}"
            print_status(note, "warning")
        except Exception as e:
            note = f"SMTP probe error: {e}"
            print_status(note, "warning")
        finally:
            if sock is not None:
                try:
                    sock.close()
                except Exception:
                    pass
        return banner, starttls, auth, False, note

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET").strip().lower().rstrip(".")

        self.results = {
            "domain": target,
            "mx_records": [],
            "smtp_banner": "",
            "starttls": False,
            "auth_mechanisms": [],
            "spf": "",
            "dmarc": "",
            "smtp_reachable": False,
            "smtp_note": "",
        }

        if not is_valid_domain(target):
            print_status(f"Invalid domain: {target}", "error")
            return True

        if not _DNS_OK:
            print_status("dnspython not available; cannot inspect mail infra", "error")
            return True

        print_status(f"Inspecting mail infrastructure for {target}", "info")
        resolver = self._build_resolver()

        # --- MX records, sorted by preference ---
        mx_list = []
        try:
            answers = resolver.resolve(target, "MX")
            for rdata in answers:
                host = str(rdata.exchange).rstrip(".")
                mx_list.append({"host": host, "preference": int(rdata.preference)})
            mx_list.sort(key=lambda m: m["preference"])
            self.results["mx_records"] = mx_list
            for mx in mx_list:
                print_status(f"MX {mx['preference']} {mx['host']}", "success")
        except dns.resolver.NoAnswer:
            print_status("No MX records found", "warning")
        except dns.resolver.NXDOMAIN:
            print_status(f"Domain {target} does not exist", "error")
            return True
        except Exception as e:
            print_status(f"MX lookup failed: {e}", "warning")

        # --- SMTP banner + EHLO on the top MX ---
        if mx_list:
            top = mx_list[0]["host"]
            print_status(f"Probing SMTP on {top}:25", "info")
            banner, starttls, auth, reachable, note = self._probe_smtp(top)
            self.results["smtp_banner"] = banner
            self.results["starttls"] = starttls
            self.results["auth_mechanisms"] = auth
            self.results["smtp_reachable"] = reachable
            self.results["smtp_note"] = note
            if reachable:
                print_status(
                    f"STARTTLS: {starttls} | AUTH: {', '.join(auth) or 'none advertised'}",
                    "info")
        else:
            self.results["smtp_note"] = "No MX host to probe"

        # --- SPF (TXT with v=spf1) ---
        try:
            for rdata in resolver.resolve(target, "TXT"):
                val = self._txt_value(rdata)
                if val.lower().startswith("v=spf1"):
                    self.results["spf"] = val
                    print_status(f"SPF: {val}", "success")
                    break
            if not self.results["spf"]:
                print_status("No SPF record", "warning")
        except dns.resolver.NoAnswer:
            print_status("No TXT/SPF record", "warning")
        except Exception:
            pass

        # --- DMARC (TXT at _dmarc.<domain>) ---
        try:
            for rdata in resolver.resolve(f"_dmarc.{target}", "TXT"):
                val = self._txt_value(rdata)
                if val.lower().startswith("v=dmarc1"):
                    self.results["dmarc"] = val
                    print_status(f"DMARC: {val}", "success")
                    break
            if not self.results["dmarc"]:
                print_status("No DMARC record", "warning")
        except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN):
            print_status("No DMARC record", "warning")
        except Exception:
            pass

        print_status(f"Mail inspection complete for {target}", "info")
        return True

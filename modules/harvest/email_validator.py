"""Email validation — SMTP probe + MX lookup + disposable check (intrusive=True)."""
import re
import socket
import smtplib
from core.base_module import BaseModule
import core.http as http_client
from core.utils import print_status


_EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]+$")

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "tempmail.com",
    "throwaway.email", "yopmail.com", "sharklasers.com", "guerrillamailblock.com",
    "grr.la", "guerrillamail.info", "guerrillamail.biz", "guerrillamail.de",
    "guerrillamail.net", "guerrillamail.org", "spam4.me", "trashmail.at",
    "trashmail.io", "trashmail.me", "trashmail.net", "trashmail.xyz",
    "dispostable.com", "maildrop.cc", "fakeinbox.com", "mailnull.com",
    "spamgourmet.com", "spamgourmet.net", "spamgourmet.org",
    "mytemp.email", "tempinbox.com", "temp-mail.org", "discard.email",
    "spamhere.eu", "spamfree24.org", "spamfree.eu",
    "mailexpire.com", "spamthisplease.com",
}


class EmailValidator(BaseModule):
    name = "harvest/email_validator"
    description = "Validate email: MX lookup, SMTP RCPT probe, disposable domain check (intrusive)"
    category = "harvest"
    target_type = "email"
    intrusive = True

    def _register_options(self):
        self.add_option("TARGET", "", True, "Email address to validate")
        self.add_option("SMTP_TIMEOUT", "10", False, "SMTP connection timeout in seconds")
        self.add_option("FROM_ADDR", "probe@example.com", False, "EHLO/MAIL FROM address for SMTP probe")

    def run(self):
        if not self.validate():
            return False

        email = (self.get_option("TARGET") or "").strip().lower()
        if not _EMAIL_RE.match(email):
            print_status(f"Not a valid email format: {email}", "error")
            return False

        try:
            smtp_timeout = int(self.get_option("SMTP_TIMEOUT") or "10")
        except (TypeError, ValueError):
            smtp_timeout = 10

        from_addr = (self.get_option("FROM_ADDR") or "probe@example.com").strip()
        local, _, domain = email.partition("@")

        results = {
            "email": email,
            "domain": domain,
            "format_valid": True,
            "mx_records": [],
            "mx_resolved": False,
            "disposable": domain in DISPOSABLE_DOMAINS,
            "smtp_deliverable": None,
            "smtp_response": None,
            "smtp_catch_all": None,
            "confidence": "unknown",
        }

        # --- MX lookup ---
        print_status(f"Looking up MX for {domain}...", "info")
        try:
            import dns.resolver
            answers = dns.resolver.resolve(domain, "MX")
            mx_list = sorted(
                [(r.preference, str(r.exchange).rstrip(".")) for r in answers],
                key=lambda x: x[0],
            )
            results["mx_records"] = [{"priority": p, "host": h} for p, h in mx_list]
            results["mx_resolved"] = True
            print_status(f"MX: {[h for _, h in mx_list]}", "success")
        except ImportError:
            # Fallback: socket-based lookup can't do MX; use HTTP-based check
            try:
                r = http_client.get(
                    "https://dns.google/resolve",
                    params={"name": domain, "type": "MX"},
                    timeout=10,
                )
                if r and r.status_code == 200:
                    data = r.json()
                    for rec in data.get("Answer", []):
                        parts = rec.get("data", "").split()
                        if len(parts) == 2:
                            results["mx_records"].append({"priority": int(parts[0]), "host": parts[1].rstrip(".")})
                    results["mx_resolved"] = bool(results["mx_records"])
                    print_status(f"MX (via DNS-over-HTTPS): {len(results['mx_records'])} records", "success")
            except Exception as e:
                print_status(f"MX lookup failed: {e}", "warning")
        except Exception as e:
            print_status(f"MX lookup failed: {e}", "warning")

        if not results["mx_resolved"]:
            results["confidence"] = "invalid (no MX)"
            self.results = results
            return True

        # --- SMTP probe ---
        mx_host = results["mx_records"][0]["host"] if results["mx_records"] else domain
        print_status(f"SMTP probe via {mx_host}...", "info")
        try:
            with smtplib.SMTP(timeout=smtp_timeout) as smtp:
                smtp.connect(mx_host, 25)
                smtp.ehlo_or_helo_if_needed()
                smtp.mail(from_addr)
                code, msg = smtp.rcpt(email)
                results["smtp_response"] = f"{code} {msg.decode(errors='replace')}"
                results["smtp_deliverable"] = (200 <= code < 300)
                print_status(f"SMTP RCPT: {code}", "success" if results["smtp_deliverable"] else "warning")

                # Catch-all check: probe a nonexistent address at same domain
                fake = f"noreply_probe_zzz99@{domain}"
                code2, _ = smtp.rcpt(fake)
                results["smtp_catch_all"] = (200 <= code2 < 300)
                if results["smtp_catch_all"]:
                    print_status("Domain accepts catch-all — deliverable result unreliable", "warning")
        except (smtplib.SMTPConnectError, ConnectionRefusedError, socket.timeout, OSError) as e:
            results["smtp_response"] = str(e)
            print_status(f"SMTP connect failed: {e}", "warning")
        except smtplib.SMTPRecipientsRefused as e:
            results["smtp_deliverable"] = False
            results["smtp_response"] = str(e)
            print_status("SMTP: address rejected", "info")
        except Exception as e:
            results["smtp_response"] = str(e)
            print_status(f"SMTP error: {e}", "warning")

        # --- Confidence ---
        if results["disposable"]:
            results["confidence"] = "disposable"
        elif not results["mx_resolved"]:
            results["confidence"] = "invalid"
        elif results["smtp_catch_all"]:
            results["confidence"] = "unverifiable (catch-all)"
        elif results["smtp_deliverable"] is True:
            results["confidence"] = "valid"
        elif results["smtp_deliverable"] is False:
            results["confidence"] = "invalid (rejected)"
        else:
            results["confidence"] = "unknown (SMTP blocked)"

        # Print summary
        print(f"\n  Email:        {email}")
        print(f"  Domain:       {domain}")
        print(f"  MX records:   {len(results['mx_records'])}")
        print(f"  Disposable:   {'YES' if results['disposable'] else 'no'}")
        print(f"  Deliverable:  {results['smtp_deliverable']}")
        print(f"  Catch-all:    {results['smtp_catch_all']}")
        print(f"  Confidence:   {results['confidence']}")

        self.results = results
        return True

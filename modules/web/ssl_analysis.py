import ssl
import socket
import datetime
from core.base_module import BaseModule
from core.utils import print_status

try:
    from cryptography import x509
    HAS_CRYPTO = True
except ImportError:
    HAS_CRYPTO = False


class SslAnalysis(BaseModule):
    name = "web/ssl_analysis"
    description = "SSL/TLS certificate and cipher suite analysis"
    category = "web"
    target_type = "domain"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Target domain")
        self.add_option("PORT", "443", False, "Target port")

    def _days_left(self, expiry):
        now = (datetime.datetime.now(expiry.tzinfo) if expiry.tzinfo
               else datetime.datetime.utcnow())
        return (expiry - now).days

    def _parse_der(self, der_cert):
        """Parse a DER certificate with cryptography (handles any cert)."""
        try:
            c = x509.load_der_x509_certificate(der_cert)
            subject = {a.oid._name: a.value for a in c.subject}
            issuer = {a.oid._name: a.value for a in c.issuer}
            not_before = getattr(c, "not_valid_before_utc", c.not_valid_before)
            not_after = getattr(c, "not_valid_after_utc", c.not_valid_after)
            san = []
            try:
                ext = c.extensions.get_extension_for_class(x509.SubjectAlternativeName)
                san = ext.value.get_values_for_type(x509.DNSName)
            except Exception:
                pass
            return {
                "subject": subject,
                "issuer": issuer,
                "serial_number": str(c.serial_number),
                "version": c.version.name,
                "not_before": not_before.strftime("%Y-%m-%d %H:%M:%S %Z").strip(),
                "not_after": not_after.strftime("%Y-%m-%d %H:%M:%S %Z").strip(),
                "san": san,
                "days_until_expiry": self._days_left(not_after),
                "signature_algorithm": c.signature_algorithm_oid._name,
            }
        except Exception:
            return {}

    def _parse_dict(self, cert):
        """Parse the ssl module's cert dict (populated only for valid certs)."""
        if not cert:
            return {}
        info = {
            "subject": dict(x[0] for x in cert.get("subject", [])),
            "issuer": dict(x[0] for x in cert.get("issuer", [])),
            "serial_number": cert.get("serialNumber"),
            "version": cert.get("version"),
            "not_before": cert.get("notBefore"),
            "not_after": cert.get("notAfter"),
            "san": [entry[1] for entry in cert.get("subjectAltName", [])],
        }
        na = cert.get("notAfter")
        if na:
            try:
                exp = datetime.datetime.strptime(na, "%b %d %H:%M:%S %Y %Z")
                info["days_until_expiry"] = (exp - datetime.datetime.utcnow()).days
            except (ValueError, TypeError):
                pass
        return info

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        try:
            port = int(self.get_option("PORT") or 443)
        except ValueError:
            port = 443

        print_status(f"Analyzing SSL/TLS for {target}:{port}", "info")

        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((target, port), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=target) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    der_cert = ssock.getpeercert(binary_form=True)

            # Record whether the cert passes default verification
            verified = False
            try:
                vctx = ssl.create_default_context()
                with socket.create_connection((target, port), timeout=10) as sock2:
                    with vctx.wrap_socket(sock2, server_hostname=target) as ssock2:
                        cert = ssock2.getpeercert()
                        verified = True
            except ssl.SSLCertVerificationError as e:
                print_status(f"Certificate NOT trusted: {e}", "warning")
                cert = {}
            except Exception:
                cert = {}

            # Parse DER (works for self-signed/invalid too); fall back to ssl dict
            cert_info = {}
            if HAS_CRYPTO and der_cert:
                cert_info = self._parse_der(der_cert)
            if not cert_info:
                cert_info = self._parse_dict(cert)
            cert_info["verified"] = verified

            days_left = cert_info.get("days_until_expiry")
            if days_left is not None and days_left < 30:
                print_status(f"Certificate expires in {days_left} days!", "warning")

            # Only the cipher the target actually negotiated during THIS
            # handshake is a real finding. (A former "weak_ciphers_available"
            # field listed the local client's SSLContext cipher list, which is
            # identical for every target and tells you nothing about the
            # server - removed because it was a fabricated/for-show result.)
            negotiated_name = cipher[0] if cipher else ""
            negotiated_weak = bool(negotiated_name) and any(
                w in negotiated_name for w in ("RC4", "DES", "NULL", "EXPORT", "MD5")
            )

            self.results = {
                "target": target,
                "port": port,
                "tls_version": version,
                "cipher_suite": negotiated_name,
                "cipher_bits": cipher[2] if cipher else 0,
                "certificate": cert_info,
                "negotiated_cipher_weak": negotiated_weak,
                "cert_size_bytes": len(der_cert) if der_cert else 0,
            }

            print_status(f"TLS Version: {version}", "success")
            print_status(f"Cipher: {cipher[0]} ({cipher[2]} bits)" if cipher else "No cipher info", "success")
            if cert_info:
                print_status(f"Subject: {cert_info.get('subject', {}).get('commonName', 'N/A')}", "success")
                print_status(f"Issuer: {cert_info.get('issuer', {}).get('organizationName', 'N/A')}", "success")
                print_status(f"SANs: {', '.join(cert_info.get('san', []))}", "success")
                print_status(f"Expires: {cert_info.get('not_after', 'N/A')}", "success")
            if negotiated_weak:
                print_status(f"Negotiated cipher is weak: {negotiated_name}", "warning")

            print_status("SSL/TLS analysis complete", "info")
            return True

        except Exception as e:
            print_status(f"SSL analysis failed: {e}", "error")
            return False

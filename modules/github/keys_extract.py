import re
from modules.github.base import GitHubModule
from core.utils import print_status


class KeysExtract(GitHubModule):
    """SSH and GPG key extraction with email discovery.

    SSH keys: fetched from https://github.com/{user}.keys (public, no auth needed).
    GPG keys: fetched from /users/{user}/gpg_keys API (contains embedded emails).
    """

    name = "github/keys_extract"
    description = "Extract SSH/GPG public keys and embedded emails from GitHub profiles"
    target_type = "username"

    def _register_options(self):
        self.add_option("TARGET", "", True, "GitHub username")

    # -----------------------------------------------------------------
    # SSH keys
    # -----------------------------------------------------------------

    def _fetch_ssh_keys(self, username):
        """Fetch SSH keys from https://github.com/{username}.keys."""
        url = f"{self.client.BASE_WEB}/{username}.keys"
        raw = self.client.get_raw(url)
        if not raw or not raw.strip():
            return []

        keys = []
        for line in raw.strip().splitlines():
            line = line.strip()
            if not line:
                continue
            parsed = self._parse_ssh_key(line)
            if parsed:
                keys.append(parsed)
        return keys

    @staticmethod
    def _parse_ssh_key(line):
        """Parse a single SSH public key line into type, size, and fingerprint hint."""
        parts = line.split(None, 2)
        if len(parts) < 2:
            return None

        key_type = parts[0]  # e.g. ssh-rsa, ssh-ed25519, ecdsa-sha2-nistp256
        key_data = parts[1]
        comment = parts[2] if len(parts) > 2 else ""

        # Determine human-readable type
        type_map = {
            "ssh-rsa": "RSA",
            "ssh-ed25519": "ED25519",
            "ecdsa-sha2-nistp256": "ECDSA-256",
            "ecdsa-sha2-nistp384": "ECDSA-384",
            "ecdsa-sha2-nistp521": "ECDSA-521",
            "ssh-dss": "DSA",
            "sk-ssh-ed25519@openssh.com": "ED25519-SK",
            "sk-ecdsa-sha2-nistp256@openssh.com": "ECDSA-SK",
        }
        friendly_type = type_map.get(key_type, key_type)

        # Estimate key size from base64-decoded length (rough)
        import base64
        key_size = None
        try:
            decoded = base64.b64decode(key_data)
            bit_len = len(decoded) * 8
            if "rsa" in key_type.lower():
                # RSA key blob contains the modulus; rough mapping
                if bit_len > 4000:
                    key_size = 4096
                elif bit_len > 2000:
                    key_size = 2048
                elif bit_len > 1000:
                    key_size = 1024
                else:
                    key_size = bit_len
            elif "ed25519" in key_type.lower():
                key_size = 256
            elif "nistp256" in key_type:
                key_size = 256
            elif "nistp384" in key_type:
                key_size = 384
            elif "nistp521" in key_type:
                key_size = 521
        except Exception:
            pass

        return {
            "algorithm": key_type,
            "type": friendly_type,
            "key_size": key_size,
            "comment": comment,
            "raw": line,
        }

    # -----------------------------------------------------------------
    # GPG keys
    # -----------------------------------------------------------------

    def _fetch_gpg_keys(self, username):
        """Fetch GPG keys from /users/{username}/gpg_keys."""
        data = self.client.get(f"/users/{username}/gpg_keys")
        if not data or not isinstance(data, list):
            return [], []

        keys = []
        emails = []

        for key_obj in data:
            key_info = {
                "key_id": key_obj.get("key_id", ""),
                "primary_key_id": key_obj.get("primary_key_id"),
                "created_at": key_obj.get("created_at", ""),
                "expires_at": key_obj.get("expires_at"),
                "can_sign": key_obj.get("can_sign", False),
                "can_encrypt_comms": key_obj.get("can_encrypt_comms", False),
                "can_encrypt_storage": key_obj.get("can_encrypt_storage", False),
                "can_certify": key_obj.get("can_certify", False),
            }

            # Emails from the structured emails field
            key_emails = []
            for email_obj in key_obj.get("emails", []):
                email = email_obj.get("email", "").lower()
                if email:
                    key_emails.append(email)
                    emails.append(email)

            key_info["emails"] = key_emails

            # Try to extract emails from raw_key if present
            raw_key = key_obj.get("raw_key", "")
            if raw_key:
                raw_emails = self._extract_emails_from_gpg_raw(raw_key)
                for email in raw_emails:
                    if email not in key_emails:
                        key_emails.append(email)
                        emails.append(email)
                key_info["raw_key_snippet"] = raw_key[:80] + "..." if len(raw_key) > 80 else raw_key

            # Sub-keys
            subkeys = key_obj.get("subkeys", [])
            key_info["subkey_count"] = len(subkeys)

            keys.append(key_info)

        return keys, emails

    @staticmethod
    def _extract_emails_from_gpg_raw(raw_key):
        """Extract email addresses embedded in a raw GPG key block."""
        if not raw_key:
            return []
        pattern = r'[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}'
        found = re.findall(pattern, raw_key)
        skip = {"noreply@github.com"}
        return [
            e.lower() for e in found
            if not e.endswith("@users.noreply.github.com") and e.lower() not in skip
        ]

    # -----------------------------------------------------------------
    # Main entry point
    # -----------------------------------------------------------------

    def run(self):
        if not self.validate():
            return False

        self._init_client()

        target = self.get_option("TARGET")
        parsed = self.parse_github_target(target)
        username = parsed["owner"]

        print_status(f"Extracting SSH/GPG keys for '{username}'...", "info")

        # SSH keys
        print_status("Fetching SSH public keys...", "info")
        ssh_keys = self._fetch_ssh_keys(username)
        if ssh_keys:
            print_status(f"Found {len(ssh_keys)} SSH key(s):", "success")
            for k in ssh_keys:
                size_str = f" {k['key_size']}-bit" if k.get("key_size") else ""
                comment_str = f" ({k['comment']})" if k.get("comment") else ""
                print_status(f"  {k['type']}{size_str}{comment_str}", "info")
        else:
            print_status("No SSH keys found", "info")

        # GPG keys
        print_status("Fetching GPG keys...", "info")
        gpg_keys, gpg_emails = self._fetch_gpg_keys(username)
        if gpg_keys:
            print_status(f"Found {len(gpg_keys)} GPG key(s):", "success")
            for k in gpg_keys:
                expires = k.get("expires_at") or "never"
                print_status(
                    f"  Key ID: {k['key_id']} | created: {k['created_at']} | "
                    f"expires: {expires}", "info"
                )
                if k.get("emails"):
                    for email in k["emails"]:
                        print_status(f"    email: {email}", "success")
        else:
            print_status("No GPG keys found", "info")

        # Consolidate all emails discovered from keys
        all_emails = sorted(set(
            e for e in gpg_emails
            if not e.endswith("@users.noreply.github.com")
            and e != "noreply@github.com"
        ))

        if all_emails:
            print_status(f"Emails from keys: {', '.join(all_emails)}", "success")

        # Nothing came back AND we are rate-limited: that is a fetch FAILURE, not
        # evidence the user has no keys. Surface it instead of reading as empty.
        if (not ssh_keys and not gpg_keys
                and getattr(self.client, "_rate_remaining", None) == 0):
            print_status(f"GitHub rate limit hit fetching keys for '{username}' - "
                         f"status UNKNOWN, not 'no keys'", "error")
            self.results = {
                "target": username,
                "ssh_keys": [],
                "ssh_key_count": 0,
                "gpg_keys": [],
                "gpg_key_count": 0,
                "all_emails_from_keys": [],
                "error": "fetch_failed",
            }
            return False

        self.results = {
            "target": username,
            "ssh_keys": ssh_keys,
            "ssh_key_count": len(ssh_keys),
            "gpg_keys": gpg_keys,
            "gpg_key_count": len(gpg_keys),
            "all_emails_from_keys": all_emails,
        }
        return True

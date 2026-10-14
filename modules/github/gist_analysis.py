import re
import math
from modules.github.base import GitHubModule
from core.utils import print_status


def _shannon_entropy(s):
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    length = len(s)
    return -sum((c/length) * math.log2(c/length) for c in counts.values())


def _is_likely_real_secret(match_text):
    PLACEHOLDERS = ('your', 'xxx', 'example', 'placeholder', 'dummy', 'sample',
                     'test123', 'password123', 'changeme', 'todo', 'fake', 'abc123',
                     'secret_key_here', 'api_key_here')
    low = match_text.lower()
    for p in PLACEHOLDERS:
        if p in low:
            return False
    # High-entropy strings are more likely real secrets
    # Short tokens (<16) get a pass if they match a known-format regex,
    # but long alnum strings need entropy > 3.5 to be considered real
    if len(match_text) >= 20 and _shannon_entropy(match_text) < 3.0:
        return False
    return True


class GistAnalysis(GitHubModule):
    name = "github/gist_analysis"
    description = "Public Gist analysis - scan gist contents for emails, API keys, tokens, and secrets"
    target_type = "username"

    SECRET_PATTERNS = {
        "AWS Access Key ID": r'\b(?:AKIA|ASIA|AGPA|AIDA|ANPA|AROA)[A-Z0-9]{16}\b',
        "GitHub Token": r'\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}\b',
        "Google API Key": r'\bAIza[0-9A-Za-z_\-]{35}\b',
        "Slack Token": r'\bxox[baprs]-[A-Za-z0-9\-]{10,}\b',
        "Stripe Live Key": r'\bsk_live_[A-Za-z0-9]{24,}\b',
        "JWT": r'\beyJ[A-Za-z0-9_\-]+\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\b',
        "Private Key": r'-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP )?PRIVATE KEY-----',
        "Discord Token": r'\b[MN][A-Za-z\d]{23}\.[\w-]{6}\.[\w-]{27}\b',
        "Discord Webhook": r'https://discord(?:app)?\.com/api/webhooks/\d{17,20}/[A-Za-z0-9_-]{60,}',
        "Telegram Bot Token": r'\b\d{8,10}:[A-Za-z0-9_-]{35}\b',
    }

    def _register_options(self):
        self.add_option("TARGET", "", True, "GitHub username")
        self.add_option("MAX_GISTS", "20", False, "Maximum number of gists to analyze")
        self.add_option("SCAN_CONTENT", "true", False, "Download and scan gist content for secrets (true/false)")

    def _scan_for_secrets(self, text, source=""):
        """Scan text for secret patterns. Returns list of findings."""
        findings = []
        if not text:
            return findings

        for pattern_name, pattern in self.SECRET_PATTERNS.items():
            matches = re.finditer(pattern, text)
            for match in matches:
                matched_text = match.group(0)
                # Entropy/placeholder filter to reduce false positives
                if not _is_likely_real_secret(matched_text):
                    continue
                # Truncate long matches for display
                display = matched_text if len(matched_text) <= 40 else matched_text[:37] + "..."
                findings.append({
                    "type": pattern_name,
                    "match": display,
                    "source": source,
                })
        return findings

    def run(self):
        if not self.validate():
            return False

        self._init_client()
        target = self.get_option("TARGET")
        max_gists = int(self.get_option("MAX_GISTS") or 20)
        scan_content = (self.get_option("SCAN_CONTENT") or "true").lower() == "true"

        parsed = self.parse_github_target(target)
        username = parsed["owner"]

        print_status(f"Fetching public gists for '{username}'", "info")

        # Fetch gists with pagination
        gists_data = self.client.paginate(
            f"/users/{username}/gists",
            max_pages=max(1, (max_gists // 100) + 1),
        )

        if not gists_data:
            # Throttled fetch != "user has no gists": an empty result while
            # rate-limited is a FAILURE, not a clean "nothing found".
            if getattr(self.client, "_rate_remaining", None) == 0:
                print_status(f"GitHub rate limit hit fetching gists for "
                             f"'{username}' - status UNKNOWN, not 'no gists'", "error")
                self.results = {
                    "target": username,
                    "gists_found": 0,
                    "gist_details": [],
                    "secrets_found": [],
                    "emails_found": [],
                    "total_files": 0,
                    "error": "fetch_failed",
                }
                return False
            print_status(f"No public gists found for '{username}'", "warning")
            self.results = {
                "target": username,
                "gists_found": 0,
                "gist_details": [],
                "secrets_found": [],
                "emails_found": [],
                "total_files": 0,
            }
            return True

        gists_data = gists_data[:max_gists]
        print_status(f"Found {len(gists_data)} public gists", "info")

        gist_details = []
        all_secrets = []
        all_emails = set()
        total_files = 0

        for i, gist in enumerate(gists_data, 1):
            gist_id = gist.get("id", "")
            description = gist.get("description", "") or ""
            created_at = gist.get("created_at", "")
            updated_at = gist.get("updated_at", "")
            comments = gist.get("comments", 0)
            html_url = gist.get("html_url", "")
            is_public = gist.get("public", True)

            files_info = gist.get("files", {})
            file_list = []

            print_status(
                f"[{i}/{len(gists_data)}] Analyzing gist {gist_id[:8]}... "
                f"({len(files_info)} files)", "info"
            )

            # Scan description for emails and secrets
            desc_emails = self.extract_emails_from_text(description)
            all_emails.update(desc_emails)
            desc_secrets = self._scan_for_secrets(
                description, source=f"gist:{gist_id[:8]}/description"
            )
            all_secrets.extend(desc_secrets)

            for filename, file_meta in files_info.items():
                total_files += 1
                file_type = file_meta.get("type", "")
                file_language = file_meta.get("language", "")
                file_size = file_meta.get("size", 0)
                raw_url = file_meta.get("raw_url", "")

                file_entry = {
                    "filename": filename,
                    "type": file_type,
                    "language": file_language,
                    "size": file_size,
                }

                # Download and scan content if enabled
                if scan_content and raw_url:
                    # Skip very large files (> 1MB) or binary types
                    if file_size > 1_000_000:
                        print_status(
                            f"  Skipping {filename} (too large: {file_size} bytes)",
                            "info",
                        )
                        file_entry["scanned"] = False
                        file_list.append(file_entry)
                        continue

                    content = self.client.get_raw(raw_url)
                    if content:
                        # Scan for emails
                        file_emails = self.extract_emails_from_text(content)
                        if file_emails:
                            all_emails.update(file_emails)
                            for email in file_emails:
                                print_status(
                                    f"  Email found in {filename}: {email}", "success"
                                )

                        # Scan for secrets
                        source_label = f"gist:{gist_id[:8]}/{filename}"
                        file_secrets = self._scan_for_secrets(content, source=source_label)
                        if file_secrets:
                            all_secrets.extend(file_secrets)
                            for secret in file_secrets:
                                print_status(
                                    f"  Secret found [{secret['type']}] in {filename}: "
                                    f"{secret['match']}", "warning"
                                )

                        file_entry["scanned"] = True
                    else:
                        file_entry["scanned"] = False
                else:
                    file_entry["scanned"] = False

                file_list.append(file_entry)

            gist_detail = {
                "id": gist_id,
                "description": description[:200] if description else "",
                "html_url": html_url,
                "public": is_public,
                "created_at": created_at,
                "updated_at": updated_at,
                "comments": comments,
                "files": file_list,
                "file_count": len(file_list),
            }
            gist_details.append(gist_detail)

        # Deduplicate secrets by (type, match, source)
        seen_secrets = set()
        unique_secrets = []
        for secret in all_secrets:
            key = (secret["type"], secret["match"], secret["source"])
            if key not in seen_secrets:
                seen_secrets.add(key)
                unique_secrets.append(secret)

        emails_list = sorted(all_emails)

        # Summary
        print_status(f"Gist analysis complete for {username}", "success")
        print_status(f"  Gists analyzed: {len(gist_details)}", "info")
        print_status(f"  Total files: {total_files}", "info")
        print_status(f"  Emails found: {len(emails_list)}", "info")
        if unique_secrets:
            print_status(f"  Secrets/credentials found: {len(unique_secrets)}", "warning")
        else:
            print_status("  No secrets or credentials detected", "info")

        self.results = {
            "target": username,
            "gists_found": len(gist_details),
            "gist_details": gist_details,
            "secrets_found": unique_secrets,
            "emails_found": emails_list,
            "total_files": total_files,
        }
        return True

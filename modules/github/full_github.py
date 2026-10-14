from modules.github.base import GitHubModule
from core.utils import print_status, Colors
from core.reporter import Reporter


class FullGithub(GitHubModule):
    """Run ALL 11 GitHub OSINT modules on a username and produce a unified report."""

    name = "github/full_github"
    description = "Full GitHub OSINT - runs all 11 modules on a username with unified report"

    def _register_options(self):
        self.add_option("TARGET", "", True, "GitHub username or org")
        self.add_option("SKIP", "", False, "Comma-separated module names to skip")

    def run(self):
        if not self.validate():
            return False

        target = self.get_option("TARGET")
        skip_list = [s.strip() for s in (self.get_option("SKIP") or "").split(",")
                     if s.strip()]

        print(f"\n{Colors.BOLD}{Colors.CYAN}")
        print("=" * 60)
        print("  FULL GITHUB OSINT SCAN")
        print(f"  Target: {target}")
        print(f"  Modules: 10")
        print("=" * 60)
        print(f"{Colors.RESET}\n")

        from modules.github.user_profile import UserProfile
        from modules.github.username_to_email import UsernameToEmail
        from modules.github.commit_emails import CommitEmails
        from modules.github.keys_extract import KeysExtract
        from modules.github.repo_analysis import RepoAnalysis
        from modules.github.event_history import EventHistory
        from modules.github.gist_analysis import GistAnalysis
        from modules.github.social_network import SocialNetwork
        from modules.github.code_search import CodeSearch
        from modules.recon.github_org import GithubOrg

        module_list = [
            ("github/user_profile", UserProfile),
            ("github/username_to_email", UsernameToEmail),
            ("github/commit_emails", CommitEmails),
            ("github/keys_extract", KeysExtract),
            ("github/repo_analysis", RepoAnalysis),
            ("github/event_history", EventHistory),
            ("github/gist_analysis", GistAnalysis),
            ("github/social_network", SocialNetwork),
            ("github/code_search", CodeSearch),
            ("recon/github_org", GithubOrg),
        ]

        all_results = {}
        completed = 0
        failed = 0
        skipped = 0
        total = len(module_list)

        for mod_name, mod_class in module_list:
            if mod_name in skip_list:
                print_status(f"Skipping {mod_name}", "warning")
                skipped += 1
                continue

            print(f"\n{Colors.BOLD}{Colors.YELLOW}{'─'*50}")
            print(f"  Running: {mod_name} [{completed + failed + skipped + 1}/{total}]")
            print(f"{'─'*50}{Colors.RESET}\n")

            try:
                mod = mod_class()
                mod.set_option("TARGET", target)
                if mod.run():
                    all_results[mod_name] = mod.get_results()
                    completed += 1
                    print_status(f"{mod_name} completed", "success")
                else:
                    failed += 1
                    print_status(f"{mod_name} failed", "error")
            except Exception as e:
                failed += 1
                print_status(f"{mod_name} error: {e}", "error")

        # --- Phase 2: if we found emails, do reverse lookup on the primary one ---
        primary_email = None
        all_emails = set()

        for data in all_results.values():
            if not isinstance(data, dict):
                continue
            for key in ("all_emails", "unique_emails", "emails_found",
                        "emails_from_pushes", "all_emails_from_keys",
                        "extracted_emails", "commit_emails"):
                val = data.get(key)
                if isinstance(val, list):
                    all_emails.update(e for e in val if isinstance(e, str))
                elif isinstance(val, set):
                    all_emails.update(e for e in val if isinstance(e, str))
                elif isinstance(val, dict):
                    all_emails.update(str(k) for k in val.keys())
            ec = data.get("email_confidence", {})
            if isinstance(ec, dict):
                all_emails.update(ec.keys())
            if data.get("email_details"):
                all_emails.update(data["email_details"].keys())

        all_emails = {e for e in all_emails
                      if "@" in e
                      and not e.endswith("noreply.github.com")
                      and e != "noreply@github.com"
                      and "." in e.split("@")[-1]}

        # Reverse email -> GitHub lookup removed intentionally.

        # --- Unified collection ---
        profile = all_results.get("github/user_profile", {})
        keys_data = all_results.get("github/keys_extract", {})
        repo_data = all_results.get("github/repo_analysis", {})
        social_data = all_results.get("github/social_network", {})
        code_data = all_results.get("github/code_search", {})
        gist_data = all_results.get("github/gist_analysis", {})

        ssh_keys = keys_data.get("ssh_keys", [])
        gpg_keys = keys_data.get("gpg_keys", [])
        all_keys = ssh_keys + gpg_keys

        repos = repo_data.get("repositories", repo_data.get("repos", []))
        if isinstance(repos, dict):
            repos = list(repos.values())

        social = {
            "followers_count": social_data.get("followers_count", 0),
            "following_count": social_data.get("following_count", 0),
            "mutual_count": social_data.get("mutual_count",
                            len(social_data.get("mutual_connections", []))),
            "organizations": social_data.get("organizations", []),
            "interest_profile": social_data.get("interest_profile", {}),
        }

        # Only VALIDATED secrets drive the verdict. gist_analysis applies regex
        # + entropy/placeholder filtering, so its hits are high-confidence.
        # code_search "files_with_secrets" are keyword-only matches (a file
        # merely containing the word "password"/"token", or filename:config) -
        # these are informational and must NOT escalate the risk level.
        validated_secrets = gist_data.get("secrets_found", []) or []
        keyword_hits = code_data.get("files_with_secrets", []) or []

        # repo_analysis flags file existence; a committed
        # Dockerfile/docker-compose/.github-workflows in a public repo is normal
        # -> informational. Only high-signal files (e.g. .env) are a real signal.
        all_repo_files = repo_data.get("sensitive_files_found", []) or []
        high_signal_files = repo_data.get("high_signal_files")
        if high_signal_files is None:
            high_signal_files = [f for f in all_repo_files
                                 if not f.get("informational")]
        info_files = [f for f in all_repo_files if f.get("informational")]

        # combined count kept for the report, but NOT used for the verdict
        secrets = validated_secrets + keyword_hits
        sensitive_files = all_repo_files

        # --- Risk assessment ---
        risks = []
        if validated_secrets:
            risks.append(f"{len(validated_secrets)} validated secret(s) found in gists")
        if high_signal_files:
            risks.append(f"{len(high_signal_files)} high-signal file(s) in repos (e.g. .env)")
        if all_keys:
            risks.append(f"{len(all_keys)} cryptographic key(s) publicly exposed")
        if len(all_emails) > 5:
            risks.append(f"Large email footprint: {len(all_emails)} addresses discovered")
        # Informational only - surfaced for manual review, never verdict-driving.
        if keyword_hits:
            risks.append(f"[info] {len(keyword_hits)} code-search keyword hit(s) "
                         f"(unverified - review manually)")
        if info_files:
            risks.append(f"[info] {len(info_files)} common infra file(s) "
                         f"(Dockerfile/compose/workflows)")

        risk_level = "LOW"
        if validated_secrets:
            risk_level = "HIGH"
        elif high_signal_files or len(all_emails) > 5:
            risk_level = "MEDIUM"

        # --- Save report ---
        reporter = Reporter()
        unified = {
            "target": target,
            "risk_level": risk_level,
            "all_emails": sorted(all_emails),
            "total_emails": len(all_emails),
            "profile": profile.get("profile", profile),
            "ssh_keys": len(ssh_keys),
            "gpg_keys": len(gpg_keys),
            "repositories_count": len(repos),
            "social": social,
            "risk_assessment": risks,
            "secrets_found": len(validated_secrets),
            "code_search_keyword_hits": len(keyword_hits),
            "sensitive_files": sensitive_files,
            "high_signal_files": high_signal_files,
            "module_results": all_results,
        }
        md_path, json_path = reporter.generate_full_report(target, all_results)
        reporter.save_module_result(target, "full_github", unified)

        # --- Final summary ---
        print(f"\n{Colors.BOLD}{Colors.GREEN}")
        print("=" * 60)
        print("  FULL GITHUB OSINT COMPLETE")
        print("=" * 60)
        print(f"{Colors.RESET}")

        p = profile.get("profile", profile)
        print(f"  {Colors.BOLD}Target:{Colors.RESET}     {target}")
        if p.get("name"):
            print(f"  {Colors.BOLD}Name:{Colors.RESET}       {p.get('name')}")
        if p.get("company"):
            print(f"  {Colors.BOLD}Company:{Colors.RESET}    {p.get('company')}")
        if p.get("location"):
            print(f"  {Colors.BOLD}Location:{Colors.RESET}   {p.get('location')}")
        if p.get("blog"):
            print(f"  {Colors.BOLD}Website:{Colors.RESET}    {p.get('blog')}")
        print(f"  {Colors.BOLD}Modules:{Colors.RESET}    {completed}/{total} completed")

        print(f"\n  {Colors.BOLD}{Colors.CYAN}Emails ({len(all_emails)}):{Colors.RESET}")
        if all_emails:
            for email in sorted(all_emails):
                print(f"    {Colors.GREEN}+{Colors.RESET} {email}")
        else:
            print(f"    {Colors.DIM}(none found){Colors.RESET}")

        if all_keys:
            print(f"\n  {Colors.BOLD}{Colors.CYAN}Keys:{Colors.RESET} "
                  f"{len(ssh_keys)} SSH + {len(gpg_keys)} GPG")

        print(f"\n  {Colors.BOLD}{Colors.CYAN}Social:{Colors.RESET}")
        print(f"    Followers: {social['followers_count']} | "
              f"Following: {social['following_count']} | "
              f"Mutual: {social['mutual_count']}")
        orgs = social.get("organizations", [])
        if orgs:
            org_names = ", ".join(o.get("login", "") for o in orgs[:10])
            print(f"    Orgs: {org_names}")

        print(f"\n  {Colors.BOLD}{Colors.CYAN}Repos:{Colors.RESET} {len(repos)} analyzed")

        risk_color = Colors.RED if risk_level == "HIGH" else (
            Colors.YELLOW if risk_level == "MEDIUM" else Colors.GREEN)
        print(f"\n  {Colors.BOLD}Risk Level: {risk_color}{risk_level}{Colors.RESET}")
        for r in risks:
            print(f"    {Colors.RED}!{Colors.RESET} {r}")

        print(f"\n  {Colors.BOLD}Reports:{Colors.RESET}")
        print(f"    {Colors.DIM}{md_path}{Colors.RESET}")
        print(f"    {Colors.DIM}{json_path}{Colors.RESET}")
        print(f"\n{Colors.GREEN}{'='*60}{Colors.RESET}\n")

        self.results = unified
        self.results["report_md"] = md_path
        self.results["report_json"] = json_path
        return True

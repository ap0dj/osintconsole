from concurrent.futures import ThreadPoolExecutor, as_completed
from core.base_module import BaseModule
from core.utils import print_status, Colors
from core import http
from modules.harvest.crypto_transactions import FetchErrorsMixin


AFFIXES = [
    "", "-dev", "-prod", "-stage", "-staging", "-test", "-qa", "-backup",
    "-backups", "-data", "-assets", "-static", "-media", "-images", "-files",
    "-uploads", "-public", "-private", "-internal", "-logs", "-archive",
    "-db", "-dump", "-config", "-secret", "-admin", "-app", "-api", "-web",
    "-cdn", "-store", "-storage", "-bucket", "-s3",
]


class CloudEnum(FetchErrorsMixin, BaseModule):
    name = "recon/cloud_enum"
    description = "Enumerate public cloud storage (AWS S3, GCP, Azure Blob) from a keyword"
    category = "recon"
    target_type = "keyword"

    def _register_options(self):
        self.add_option("TARGET", "", True, "Company/keyword base name (e.g. acme)")
        self.add_option("THREADS", "20", False, "Concurrent requests")
        self.add_option("PROVIDERS", "aws,gcp,azure", False, "Which clouds: aws,gcp,azure")

    def _candidates(self, base):
        base = base.lower().replace(" ", "")
        names = set()
        for affix in AFFIXES:
            names.add(f"{base}{affix}")
            names.add(f"{affix.lstrip('-')}{('-' + base) if affix else base}"
                      if affix else base)
        return sorted(n.strip("-") for n in names if n.strip("-"))

    # Each probe returns (result_or_None, error_or_None):
    #   - (hit_tuple, None)  a confirmed bucket/account
    #   - (None, None)       a definitive miss (got a clear negative answer)
    #   - (None, "msg")      the probe could not get a verdict (network/5xx) ->
    #                        a fetch error, so a dead uplink is never read as "no
    #                        buckets found".
    def _check_aws(self, bucket):
        url = f"https://{bucket}.s3.amazonaws.com"
        # *.s3.amazonaws.com is wildcard DNS, so the host always resolves and a
        # missing bucket answers 404 -- any connection error here is a real
        # network failure, not "bucket absent".
        try:
            resp = http.get(url, timeout=8)
        except Exception as e:
            return None, f"AWS S3 {bucket}: {e}"
        if resp.status_code == 200:
            return ("AWS S3", bucket, url, "OPEN (listable)"), None
        if resp.status_code == 403:
            return ("AWS S3", bucket, url, "EXISTS (private)"), None
        if resp.status_code == 404:
            return None, None  # NoSuchBucket -> definitive miss
        return None, f"AWS S3 {bucket}: HTTP {resp.status_code}"

    def _check_gcp(self, bucket):
        url = f"https://storage.googleapis.com/{bucket}"
        # storage.googleapis.com always resolves; a missing bucket answers 404.
        try:
            resp = http.get(url, timeout=8)
        except Exception as e:
            return None, f"GCP {bucket}: {e}"
        if resp.status_code == 200:
            return ("GCP Storage", bucket, url, "OPEN (listable)"), None
        if resp.status_code == 403:
            return ("GCP Storage", bucket, url, "EXISTS (private)"), None
        if resp.status_code == 404:
            return None, None  # definitive miss
        return None, f"GCP {bucket}: HTTP {resp.status_code}"

    def _check_azure(self, account):
        base = f"https://{account}.blob.core.windows.net"
        url = f"{base}/?comp=list"
        # A non-existent Azure storage account does not resolve in DNS, so a
        # connection error here means "account absent", not a fetch failure.
        try:
            resp = http.get(url, timeout=8)
        except Exception:
            return None, None  # account subdomain did not resolve -> miss
        # Only a clear positive counts. 200 = public container listing.
        # 403 = AuthenticationFailed/AuthorizationFailure -> the account exists
        # but access is denied. 400/409 are ambiguous Azure request errors and
        # were previously over-reported as EXISTS -> drop them to avoid false
        # positives.
        if resp.status_code == 200:
            return ("Azure Blob", account, base, "OPEN"), None
        if resp.status_code == 403:
            return ("Azure Blob", account, base, "EXISTS (private)"), None
        return None, None  # 400/404/409/other -> not a confirmed account

    def run(self):
        if not self.validate():
            return False

        base = self.get_option("TARGET").strip()
        threads = max(1, int(self.get_option("THREADS") or 20))
        providers = [p.strip().lower() for p in
                     self.get_option("PROVIDERS").split(",") if p.strip()]

        candidates = self._candidates(base)

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*58}")
        print(f"  Cloud Storage Enumeration: {base}")
        print(f"  Candidates: {len(candidates)} x {len(providers)} providers")
        print(f"{'='*58}{Colors.RESET}\n")

        self._errors = []
        successes = 0
        tasks = []
        with ThreadPoolExecutor(max_workers=threads) as executor:
            for name in candidates:
                if "aws" in providers:
                    tasks.append(executor.submit(self._check_aws, name))
                if "gcp" in providers:
                    tasks.append(executor.submit(self._check_gcp, name))
                if "azure" in providers:
                    azure_name = name.replace("-", "")[:24]
                    tasks.append(executor.submit(self._check_azure, azure_name))

            hits = []
            for future in as_completed(tasks):
                result, error = future.result()
                if error:
                    # Recorded on the main thread -> _note_error print is safe.
                    self._note_error(error)
                else:
                    successes += 1  # probe returned a definitive verdict
                if result:
                    provider, bucket, url, state = result
                    hits.append({"provider": provider, "name": bucket,
                                 "url": url, "state": state})
                    color = Colors.RED if "OPEN" in state else Colors.GREEN
                    print(f" {color}[+]{Colors.RESET} {provider:<14} {bucket:<28} "
                          f"{state}  {url}")

        hits.sort(key=lambda x: (x["provider"], x["name"]))
        open_buckets = [h for h in hits if "OPEN" in h["state"]]

        self.results = {
            "base": base,
            "providers": providers,
            "candidates_tested": len(candidates),
            "found_count": len(hits),
            "open_count": len(open_buckets),
            "buckets": hits,
            "fetch_errors": list(getattr(self, "_errors", [])),
        }

        # Not a single probe got a verdict (every request errored) -> the network
        # or the cloud endpoints are unreachable. This is NOT "0 buckets found".
        if successes == 0 and self._errors:
            self.results["error"] = "fetch_failed"
            print_status(
                "Cloud enumeration FAILED - every probe errored "
                "(network/endpoint unreachable); this is NOT evidence that no "
                "buckets exist", "error")
            return False

        print(f"\n{Colors.BOLD}{Colors.GREEN}{'='*58}")
        print(f"  Found {len(hits)} bucket(s), {len(open_buckets)} publicly open")
        if self._errors:
            print(f"  {Colors.YELLOW}{len(self._errors)} probe(s) errored - "
                  f"results may be partial{Colors.RESET}")
        print(f"{Colors.GREEN}{'='*58}{Colors.RESET}\n")

        return True

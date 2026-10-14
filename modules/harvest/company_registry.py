"""Company / business-registry OSINT — map a name or domain to corporate identity.

This is the registry pillar the toolkit was missing: given a company name (or a
domain, whose registrable label is used as a name guess) it resolves corporate
identity, filings and global entity records from TWO free, keyless sources.

Sources (both verified live, no API key):
  1. SEC EDGAR (US public companies). A descriptive User-Agent is REQUIRED by
     EDGAR or it 403s, so every SEC request carries one.
       - company_tickers.json  (name/ticker -> CIK, 10-digit zero-padded)
         https://www.sec.gov/files/company_tickers.json
       - submissions           (identity + recent filings)
         https://data.sec.gov/submissions/CIK##########.json
     Surfaces: company name, CIK, tickers, exchanges, SIC/industry, EIN, LEI,
     state of incorporation, addresses, and recent filings (form + date +
     accession + primary document).
  2. GLEIF LEI (global, fully open JSON:API).
       https://api.gleif.org/api/v1/lei-records?filter[entity.legalName]=<name>
     Surfaces: LEI code, legal name, legal/HQ address, registration status,
     and direct/ultimate parent (LEI + name) when present.

A source FAILURE (403/404/429/timeout/non-JSON) is recorded via _note_error and,
if nothing at all is retrieved, makes run() return False — it is never silently
downgraded to an empty "no results". A genuine 200 with zero matches is reported
as "no match", which is a real answer, not a failure.
"""
import re

from core.base_module import BaseModule
from core.utils import print_status, Colors, is_valid_domain
from core import http
# Reuse the crypto modules' failure-vs-empty contract so an API failure is a
# real failure, not a misleading empty result.
from modules.harvest.crypto_transactions import FetchErrorsMixin


# EDGAR mandates a descriptive UA with a contact; the console's default Chrome UA
# is deliberately overridden here so SEC never 403s this module.
SEC_HEADERS = {
    "User-Agent": "osintconsole research contact@example.com",
    "Accept": "application/json",
}
GLEIF_HEADERS = {"Accept": "application/vnd.api+json"}

SEC_TICKERS_URL = "https://www.sec.gov/files/company_tickers.json"
SEC_SUBMISSIONS = "https://data.sec.gov/submissions/CIK{cik10}.json"
GLEIF_URL = "https://api.gleif.org/api/v1/lei-records"

# Second-level labels that are not the company name (e.g. example.co.uk).
_SLD = {"co", "com", "org", "net", "gov", "edu", "ac", "gob", "go"}


class CompanyRegistry(FetchErrorsMixin, BaseModule):
    name = "harvest/company_registry"
    description = ("Map a company name or domain to corporate identity, filings "
                   "and global entity records (SEC EDGAR + GLEIF LEI, free/no-key)")
    category = "harvest"
    target_type = "domain/keyword"
    intrusive = False

    def _register_options(self):
        self.add_option("TARGET", "", True,
                        "Company name or domain to look up")
        self.add_option("SOURCE", "auto", False,
                        "Which registries to query: auto (both) | sec | gleif")
        self.add_option("MAX_RESULTS", "5", False,
                        "Maximum matching entities per source")
        self.add_option("MAX_FILINGS", "10", False,
                        "Maximum recent SEC filings to list per company")

    # ---- option helpers ----------------------------------------------
    def _int_opt(self, name, default, lo, hi):
        try:
            return max(lo, min(hi, int(self.get_option(name) or default)))
        except (TypeError, ValueError):
            return default

    @staticmethod
    def _name_from_domain(target):
        """Registrable label of a domain -> a company-name guess.

        example.com -> 'example'; shop.example.co.uk -> 'example'. Returns None
        when the target is not a domain (so it is used verbatim as a name).
        """
        t = target.strip().lower()
        t = re.sub(r"^https?://", "", t).split("/")[0]
        t = t.split("@")[-1]  # strip any user@ prefix
        if not is_valid_domain(t):
            return None
        labels = t.split(".")
        if len(labels) < 2:
            return None
        # Drop the TLD; if the SLD is a public second level (co.uk), drop it too.
        idx = len(labels) - 2
        if idx >= 1 and labels[idx] in _SLD:
            idx -= 1
        return labels[idx]

    # ---- SEC EDGAR ----------------------------------------------------
    @staticmethod
    def _score_title(query, title, ticker):
        """Accuracy-first match score; 0 means reject (avoids false positives).

        Bare-substring matches (e.g. 'apple' in 'Pineapple') are deliberately NOT
        accepted — only exact, prefix, whole-word or exact-ticker matches count.
        """
        q = query.strip().lower()
        t = (title or "").lower()
        if not q or not t:
            return 0
        if ticker and ticker.lower() == q:
            return 100
        if t == q:
            return 90
        # Prefix match ending on a word boundary ("apple inc." for "apple").
        if t.startswith(q) and (len(t) == len(q) or not t[len(q)].isalnum()):
            return 70
        if re.search(r"\b" + re.escape(q) + r"\b", t):
            return 50
        return 0

    def _sec_find_ciks(self, query, max_results):
        """Resolve a name/ticker to matching {cik, ticker, title} via EDGAR."""
        try:
            resp = http.get(SEC_TICKERS_URL, headers=SEC_HEADERS, timeout=30)
        except Exception as exc:
            self._note_error(f"SEC tickers error: {exc}")
            return None
        if resp.status_code != 200:
            self._note_error(f"SEC tickers HTTP {resp.status_code}")
            return None
        try:
            data = resp.json()
        except Exception as exc:
            self._note_error(f"SEC tickers non-JSON: {exc}")
            return None
        self._any_success = True

        scored = []
        for entry in data.values():
            if not isinstance(entry, dict):
                continue
            score = self._score_title(query, entry.get("title", ""),
                                      entry.get("ticker", ""))
            if score:
                scored.append((score, entry))
        scored.sort(key=lambda s: (-s[0], s[1].get("title", "")))
        out, seen = [], set()
        for _, entry in scored:
            cik = entry.get("cik_str")
            if cik in seen:
                continue
            seen.add(cik)
            out.append({
                "cik": int(cik),
                "ticker": entry.get("ticker"),
                "title": entry.get("title"),
            })
            if len(out) >= max_results:
                break
        return out

    def _sec_submissions(self, cik, max_filings):
        """Full identity + recent filings for one CIK."""
        cik10 = str(int(cik)).zfill(10)
        try:
            resp = http.get(SEC_SUBMISSIONS.format(cik10=cik10),
                            headers=SEC_HEADERS, timeout=30)
        except Exception as exc:
            self._note_error(f"SEC submissions error (CIK{cik10}): {exc}")
            return None
        if resp.status_code != 200:
            self._note_error(f"SEC submissions HTTP {resp.status_code} (CIK{cik10})")
            return None
        try:
            data = resp.json()
        except Exception as exc:
            self._note_error(f"SEC submissions non-JSON (CIK{cik10}): {exc}")
            return None
        self._any_success = True

        business = (data.get("addresses") or {}).get("business") or {}
        company = {
            "source": "sec",
            "name": data.get("name"),
            "cik": int(cik),
            "cik_padded": cik10,
            "tickers": data.get("tickers") or [],
            "exchanges": data.get("exchanges") or [],
            "sic": data.get("sic"),
            "industry": data.get("sicDescription"),
            "entity_type": data.get("entityType"),
            "ein": data.get("ein"),
            "lei": data.get("lei"),
            "state_of_incorporation": data.get("stateOfIncorporation"),
            "website": data.get("website"),
            "phone": data.get("phone"),
            "former_names": [n.get("name") for n in (data.get("formerNames") or [])
                             if isinstance(n, dict) and n.get("name")],
            "business_address": self._fmt_sec_addr(business),
            "recent_filings": self._sec_filings(data, cik, max_filings),
        }
        return company

    @staticmethod
    def _fmt_sec_addr(addr):
        parts = [addr.get("street1"), addr.get("street2"), addr.get("city"),
                 addr.get("stateOrCountry"), addr.get("zipCode")]
        return ", ".join(p for p in parts if p) or None

    def _sec_filings(self, data, cik, max_filings):
        """Parse the parallel-array recent-filings block into filing dicts."""
        recent = ((data.get("filings") or {}).get("recent") or {})
        forms = recent.get("form") or []
        dates = recent.get("filingDate") or []
        rdates = recent.get("reportDate") or []
        accns = recent.get("accessionNumber") or []
        docs = recent.get("primaryDocument") or []
        descs = recent.get("primaryDocDescription") or []
        out = []
        for i in range(min(len(forms), len(accns), max_filings)):
            accn = accns[i]
            nodash = (accn or "").replace("-", "")
            out.append({
                "company": data.get("name"),
                "cik": int(cik),
                "form": forms[i],
                "filing_date": dates[i] if i < len(dates) else None,
                "report_date": rdates[i] if i < len(rdates) else None,
                "accession": accn,
                "primary_doc": docs[i] if i < len(docs) else None,
                "description": descs[i] if i < len(descs) else None,
                "url": (f"https://www.sec.gov/Archives/edgar/data/"
                        f"{int(cik)}/{nodash}/" + (docs[i] if i < len(docs)
                                                   and docs[i] else "")),
            })
        return out

    def _run_sec(self, query, max_results, max_filings):
        companies, filings = [], []
        matches = self._sec_find_ciks(query, max_results)
        if not matches:
            return companies, filings
        for m in matches:
            company = self._sec_submissions(m["cik"], max_filings)
            if company:
                companies.append(company)
                filings.extend(company.get("recent_filings") or [])
        return companies, filings

    # ---- GLEIF --------------------------------------------------------
    def _run_gleif(self, query, max_results):
        records = []
        try:
            resp = http.get(GLEIF_URL,
                            params={"filter[entity.legalName]": query,
                                    "page[size]": max(1, min(50, max_results))},
                            headers=GLEIF_HEADERS, timeout=30)
        except Exception as exc:
            self._note_error(f"GLEIF error: {exc}")
            return records
        if resp.status_code != 200:
            self._note_error(f"GLEIF HTTP {resp.status_code}")
            return records
        try:
            data = resp.json()
        except Exception as exc:
            self._note_error(f"GLEIF non-JSON: {exc}")
            return records
        self._any_success = True

        for rec in (data.get("data") or [])[:max_results]:
            records.append(self._parse_gleif(rec))
        return records

    def _parse_gleif(self, rec):
        attrs = rec.get("attributes") or {}
        ent = attrs.get("entity") or {}
        reg = attrs.get("registration") or {}
        rels = rec.get("relationships") or {}
        return {
            "source": "gleif",
            "lei": rec.get("id"),
            "legal_name": (ent.get("legalName") or {}).get("name"),
            "other_names": [o.get("name") for o in (ent.get("otherNames") or [])
                            if isinstance(o, dict) and o.get("name")],
            "legal_address": self._fmt_gleif_addr(ent.get("legalAddress")),
            "headquarters_address": self._fmt_gleif_addr(
                ent.get("headquartersAddress")),
            "jurisdiction": ent.get("jurisdiction"),
            "legal_form": (ent.get("legalForm") or {}).get("id"),
            "entity_status": ent.get("status"),
            "registration_status": reg.get("status"),
            "initial_registration_date": reg.get("initialRegistrationDate"),
            "last_update_date": reg.get("lastUpdateDate"),
            "direct_parent": self._gleif_parent(rels.get("direct-parent")),
            "ultimate_parent": self._gleif_parent(rels.get("ultimate-parent")),
        }

    @staticmethod
    def _fmt_gleif_addr(addr):
        if not isinstance(addr, dict):
            return None
        parts = list(addr.get("addressLines") or [])
        parts += [addr.get("city"), addr.get("region"),
                  addr.get("postalCode"), addr.get("country")]
        text = ", ".join(p for p in parts if p)
        return {
            "text": text or None,
            "city": addr.get("city"),
            "region": addr.get("region"),
            "country": addr.get("country"),
            "postal_code": addr.get("postalCode"),
        }

    def _gleif_parent(self, rel):
        """Resolve a direct/ultimate parent to {lei, name} when one exists.

        No parent -> GLEIF returns only a 'reporting-exception' link; a real
        parent exposes a 'lei-record' sub-resource which we fetch for the LEI
        and legal name. A fetch failure is noted but does not fail the record.
        """
        if not isinstance(rel, dict):
            return None
        links = rel.get("links") or {}
        url = links.get("lei-record")
        if not url:
            return None  # reporting-exception / no parent
        try:
            resp = http.get(url, headers=GLEIF_HEADERS, timeout=30)
        except Exception as exc:
            self._note_error(f"GLEIF parent error: {exc}")
            return {"lei": None, "name": None, "unresolved": True}
        if resp.status_code != 200:
            self._note_error(f"GLEIF parent HTTP {resp.status_code}")
            return {"lei": None, "name": None, "unresolved": True}
        try:
            pdata = (resp.json() or {}).get("data")
        except Exception:
            return {"lei": None, "name": None, "unresolved": True}
        if not isinstance(pdata, dict):
            return None
        pent = (pdata.get("attributes") or {}).get("entity") or {}
        return {
            "lei": pdata.get("id"),
            "name": (pent.get("legalName") or {}).get("name"),
        }

    # ------------------------------------------------------------------
    @staticmethod
    def _entities(companies, lei_records):
        """Flat entity-ish lists for the correlation engine.

        Officers are not reliably exposed by these free endpoints, so the field
        is present but left empty rather than fabricated.
        """
        names, ciks, tickers, leis = set(), set(), set(), set()
        for c in companies:
            if c.get("name"):
                names.add(c["name"])
            if c.get("cik") is not None:
                ciks.add(c["cik"])
            for t in c.get("tickers") or []:
                tickers.add(t)
            if c.get("lei"):
                leis.add(c["lei"])
            for fn in c.get("former_names") or []:
                names.add(fn)
        for r in lei_records:
            if r.get("legal_name"):
                names.add(r["legal_name"])
            if r.get("lei"):
                leis.add(r["lei"])
            for p in (r.get("direct_parent"), r.get("ultimate_parent")):
                if isinstance(p, dict) and p.get("name"):
                    names.add(p["name"])
                if isinstance(p, dict) and p.get("lei"):
                    leis.add(p["lei"])
        return {
            "company_names": sorted(names),
            "ciks": sorted(ciks),
            "tickers": sorted(tickers),
            "leis": sorted(leis),
            "officers": [],
        }

    def run(self):
        if not self.validate():
            return False

        target = (self.get_option("TARGET") or "").strip()
        source = (self.get_option("SOURCE") or "auto").strip().lower()
        if source not in ("auto", "sec", "gleif"):
            source = "auto"
        max_results = self._int_opt("MAX_RESULTS", 5, 1, 50)
        max_filings = self._int_opt("MAX_FILINGS", 10, 1, 100)

        name_guess = self._name_from_domain(target)
        query = name_guess or target
        is_domain = name_guess is not None

        print(f"\n{Colors.BOLD}{Colors.CYAN}{'='*60}")
        print(f"  Company Registry Lookup: {target}")
        print(f"{'='*60}{Colors.RESET}\n")
        if is_domain:
            print_status(f"Domain target - searching as company '{query}'", "info")

        self._errors = []
        self._any_success = False
        companies, filings, lei_records, sources_used = [], [], [], []

        if source in ("auto", "sec"):
            print_status("Querying SEC EDGAR...", "info")
            sources_used.append("sec")
            c, f = self._run_sec(query, max_results, max_filings)
            companies.extend(c)
            filings.extend(f)
            print_status(f"SEC: {len(c)} company record(s), {len(f)} filing(s)",
                         "success" if c else "info")

        if source in ("auto", "gleif"):
            print_status("Querying GLEIF LEI...", "info")
            sources_used.append("gleif")
            lei_records = self._run_gleif(query, max_results)
            print_status(f"GLEIF: {len(lei_records)} LEI record(s)",
                         "success" if lei_records else "info")

        self.results = {
            "target": target,
            "name_query": query,
            "is_domain": is_domain,
            "companies": companies,
            "filings": filings,
            "lei_records": lei_records,
            "entities": self._entities(companies, lei_records),
            "sources_used": sources_used,
            "fetch_errors": list(self._errors),
        }

        found = bool(companies or lei_records)
        if not found and not self._any_success:
            # Every attempted source errored and nothing parsed -> real failure,
            # NOT evidence the company does not exist.
            return self._fail()

        if not found:
            print_status("No matching companies found (clean no-match)", "info")
            return True

        self._print_summary(companies, lei_records)
        if self._errors:
            print_status(f"Partial data: {len(self._errors)} fetch error(s)",
                         "warning")
        print()
        return True

    def _print_summary(self, companies, lei_records):
        for c in companies:
            tick = f" [{', '.join(c['tickers'])}]" if c.get("tickers") else ""
            print_status(f"{c.get('name')}{tick}  CIK {c.get('cik')}  "
                         f"{c.get('industry') or ''}", "success")
            if c.get("lei"):
                print_status(f"    LEI: {c['lei']}", "info")
            if c.get("recent_filings"):
                latest = c["recent_filings"][0]
                print_status(f"    latest filing: {latest.get('form')} "
                             f"{latest.get('filing_date')} "
                             f"({latest.get('accession')})", "info")
        for r in lei_records:
            addr = (r.get("legal_address") or {}).get("text") or ""
            print_status(f"LEI {r.get('lei')}  {r.get('legal_name')}  "
                         f"[{r.get('registration_status')}]  {addr}", "success")
            for label, p in (("direct parent", r.get("direct_parent")),
                             ("ultimate parent", r.get("ultimate_parent"))):
                if isinstance(p, dict) and p.get("lei"):
                    print_status(f"    {label}: {p.get('name')} ({p['lei']})",
                                 "info")

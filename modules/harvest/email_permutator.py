from core.base_module import BaseModule
from core.utils import print_status, format_table


class EmailPermutator(BaseModule):
    name = "harvest/email_permutator"
    description = "Generate email address permutations from a name and domain for targeted OSINT"
    category = "harvest"
    target_type = "person"
    intrusive = False

    def _register_options(self):
        self.add_option("FIRST_NAME", "", True, "First name / given name")
        self.add_option("LAST_NAME", "", True, "Last / family name")
        self.add_option(
            "DOMAIN", "", False,
            "Domain to use (e.g. company.com). Leave blank to show patterns only."
        )
        self.add_option(
            "INCLUDE_NUMBERS", "true", False,
            "Include patterns with birth year numbers (1985-2005)"
        )
        self.add_option("MAX_RESULTS", "100", False, "Limit output count")

    # ------------------------------------------------------------------
    # Pattern generation
    # ------------------------------------------------------------------
    def _build_patterns(self, first, last):
        """Return an ordered, deduplicated list of username patterns."""
        f = first[0] if first else ""
        l = last[0] if last else ""

        f3 = first[:3]
        f4 = first[:4]
        l3 = last[:3]
        l4 = last[:4]

        raw = [
            # ----- dot-separated -----
            f"{first}.{last}",
            f"{last}.{first}",
            f"{f}.{last}",
            f"{first}.{l}",
            f"{f}.{l}",
            f"{l}.{f}",
            f"{f3}.{last}",
            f"{f4}.{last}",
            f"{last}.{f3}",
            f"{last}.{f4}",
            f"{first}.{l3}",
            f"{first}.{l4}",
            f"{l3}.{first}",
            f"{l4}.{first}",
            f"{f3}.{l3}",
            f"{f4}.{l4}",
            f"{f3}.{l4}",
            f"{f4}.{l3}",
            # ----- concatenated -----
            f"{f}{last}",
            f"{first}{last}",
            f"{last}{first}",
            f"{last}{f}",
            f"{first}{l}",
            f"{last}{l}",
            f"{f}{l}",
            f"{l}{f}",
            f"{f3}{last}",
            f"{f4}{last}",
            f"{first}{l3}",
            f"{first}{l4}",
            f"{f3}{l3}",
            f"{f4}{l4}",
            f"{f3}{l4}",
            f"{f4}{l3}",
            f"{f}{f}{last}",
            f"{first}{l}{l}",
            # single name
            f"{first}",
            f"{last}",
            # ----- underscore -----
            f"{first}_{last}",
            f"{last}_{first}",
            f"{f}_{last}",
            f"{first}_{l}",
            f"{f}_{l}",
            f"{l}_{f}",
            f"{l3}_{first}",
            f"{l4}_{first}",
            f"{f3}_{last}",
            f"{f4}_{last}",
            # ----- hyphen -----
            f"{first}-{last}",
            f"{last}-{first}",
            f"{f}-{last}",
            f"{first}-{l}",
            f"{f3}-{last}",
            f"{f4}-{last}",
            # ----- numeric suffix (non-year) -----
            f"{first}.{last}1",
            f"{first}.{last}2",
            f"{first}.{last}3",
            f"{first}{last}1",
            f"{first}{last}2",
            f"{first}_{last}1",
            f"{f}.{last}1",
            f"{f}{last}1",
            f"{first}1",
            f"{first}2",
        ]

        seen = set()
        unique = []
        for p in raw:
            if p and p not in seen:
                seen.add(p)
                unique.append(p)
        return unique

    # ------------------------------------------------------------------
    # run()
    # ------------------------------------------------------------------
    def run(self):
        if not self.validate():
            return False

        first = (self.get_option("FIRST_NAME") or "").strip().lower()
        last = (self.get_option("LAST_NAME") or "").strip().lower()
        domain = (self.get_option("DOMAIN") or "").strip().lower().lstrip("@")
        include_numbers = (
            (self.get_option("INCLUDE_NUMBERS") or "true").strip().lower() == "true"
        )
        try:
            max_results = int(self.get_option("MAX_RESULTS") or 100)
        except ValueError:
            max_results = 100

        f_init = first[0] if first else ""
        l_init = last[0] if last else ""
        initials = f"{f_init}{l_init}".upper()

        print_status(f"Generating permutations for: {first} {last}", "info")
        if domain:
            print_status(f"Domain: {domain}", "info")
        else:
            print_status("No domain set — showing patterns only", "info")

        base_patterns = self._build_patterns(first, last)

        # Build email list or pattern list
        if domain:
            emails = [f"{p}@{domain}" for p in base_patterns]
        else:
            emails = list(base_patterns)

        # Year variants for top 10 base patterns
        if include_numbers:
            top = base_patterns[:10]
            for p in top:
                for year in range(1985, 2006):
                    entry = f"{p}{year}@{domain}" if domain else f"{p}{year}"
                    emails.append(entry)

        # Subaddress variants (only when domain is set)
        if domain:
            for sub in ("mail", "corp", "m", "work", "us", "eu"):
                emails.append(f"{first}@{sub}.{domain}")

        # Deduplicate, preserve order
        seen: set = set()
        unique_emails = []
        for e in emails:
            if e not in seen:
                seen.add(e)
                unique_emails.append(e)

        # Cap at max_results
        unique_emails = unique_emails[:max_results]

        # Print table
        rows = []
        for i, entry in enumerate(unique_emails, 1):
            if "@" in entry:
                pat, dom = entry.rsplit("@", 1)
                rows.append([str(i), pat, f"@{dom}"])
            else:
                rows.append([str(i), entry, "(no domain)"])

        print(f"\n{format_table(['#', 'Pattern', 'Domain'], rows)}\n")
        print_status(
            f"Generated {len(unique_emails)} permutations "
            f"({'with domain' if domain else 'patterns only'})",
            "success",
        )

        # Name variants for results metadata
        name_variants = [first, last, f"{first} {last}", f"{last} {first}"]
        if len(first) > 6:
            name_variants += [first[:4], first[:3]]

        self.results = {
            "first_name": first,
            "last_name": last,
            "domain": domain,
            "total_generated": len(unique_emails),
            "patterns": unique_emails,
            "initials": initials,
            "name_variants": name_variants,
        }
        return True

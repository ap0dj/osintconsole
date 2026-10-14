"""Shared helpers for social OSINT modules.
Deduplicates confidence tiers, verification hints, uncertainty disclaimer,
and the final uncertainty box used by telegram/discord/instagram/tiktok/snapchat.
"""
from core.utils import Colors


def confidence_tier(similarity):
    """Return a human-readable confidence label from a similarity ratio."""
    if similarity >= 0.99:
        return "exact-match"
    if similarity >= 0.90:
        return "high"
    if similarity >= 0.75:
        return "medium"
    if similarity >= 0.55:
        return "low"
    return "very-low"


# Platform-specific hints that take a candidate dict and return list[str].
# Each module keeps its own hints function because the hints are domain-specific,
# but we expose a common verification_hints builder for shared fields.

def common_verification_hints(platform):
    """Hints that apply across platforms."""
    base = [
        "A matched username does NOT identify the person behind it - multiple real "
        "people can share usernames and username patterns.",
        "Cross-reference with other platforms where the target is known to post.",
        "Check timestamps / creation dates against the target's known timeline.",
    ]
    return base


def print_uncertainty_box(platform, hints_summary=None):
    """Print the standard yellow uncertainty box used by all social modules."""
    print()
    print(f"{Colors.YELLOW}{Colors.BOLD}{'=' * 62}")
    print(f"  IMPORTANT - these are CANDIDATES, not confirmed matches")
    print(f"{'=' * 62}{Colors.RESET}")
    print(f"  {Colors.YELLOW}Multiple accounts can share names, usernames, and patterns.{Colors.RESET}")
    print(f"  {Colors.YELLOW}The target may be:{Colors.RESET}")
    print(f"    - the exact-match if present (highest confidence)")
    print(f"    - one of the high/medium candidates")
    print(f"    - NOT in this list at all (private, deleted, or on another platform)")
    if hints_summary:
        print(f"  {Colors.YELLOW}For {platform} specifically:{Colors.RESET}")
        for line in hints_summary:
            print(f"    - {line}")
    print(f"  {Colors.DIM}Each candidate carries 'verification_hints' in self.results.{Colors.RESET}")
    print(f"{Colors.YELLOW}{'=' * 62}{Colors.RESET}\n")


def build_disclaimer(platform, candidate_count, extra_text=""):
    """Return the standard disclaimer sentence."""
    base = (
        f"{candidate_count} candidate(s) returned via {platform} username probing. "
        "These are POSSIBLE matches, not confirmed as the target. "
        "Multiple real people can share similar usernames. "
        "Verify each manually using the per-candidate 'verification_hints' before "
        "acting on any lead."
    )
    if extra_text:
        base = base + " " + extra_text
    return base


def tag_candidate(candidate, platform, similarity, hints_fn):
    """Stamp a candidate dict with the standard uncertainty fields.
    Call this from each module after computing similarity:
        tag_candidate(c, "telegram", sim, _verification_hints_telegram)
    """
    candidate["confidence_tier"] = confidence_tier(similarity)
    candidate["is_verified_as_target"] = False
    candidate["verification_hints"] = hints_fn(candidate)
    return candidate

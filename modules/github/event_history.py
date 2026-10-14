from collections import Counter
from modules.github.base import GitHubModule
from core.utils import print_status


class EventHistory(GitHubModule):
    name = "github/event_history"
    description = "GitHub Events API analysis - extract emails from push events and map activity patterns"
    target_type = "username"

    def _register_options(self):
        self.add_option("TARGET", "", True, "GitHub username")
        self.add_option("MAX_PAGES", "3", False, "Max pages to fetch (each page = 30 events, max 10)")

    def _parse_timestamp(self, ts):
        """Extract hour and weekday from ISO 8601 timestamp."""
        if not ts:
            return None, None
        try:
            # Format: 2024-01-15T14:30:00Z
            parts = ts.replace("Z", "").split("T")
            if len(parts) == 2:
                date_part = parts[0]
                time_part = parts[1]
                hour = int(time_part.split(":")[0])
                # Calculate weekday from date
                year, month, day = map(int, date_part.split("-"))
                # Zeller-like day of week using Python's datetime
                import datetime
                weekday = datetime.date(year, month, day).strftime("%A")
                return hour, weekday
        except (ValueError, IndexError):
            pass
        return None, None

    def run(self):
        if not self.validate():
            return False

        self._init_client()
        target = self.get_option("TARGET")
        max_pages = min(int(self.get_option("MAX_PAGES") or 3), 10)

        parsed = self.parse_github_target(target)
        username = parsed["owner"]

        print_status(f"Fetching public events for '{username}'", "info")

        # Fetch events using pagination (events endpoint returns 30 per page, up to 10 pages)
        all_events = self.client.paginate(
            f"/users/{username}/events/public",
            params={"per_page": 30},
            max_pages=max_pages,
        )

        if not all_events:
            # Distinguish a throttled fetch from a genuinely inactive account:
            # an empty result while rate-limited is a FAILURE, not "no events".
            if getattr(self.client, "_rate_remaining", None) == 0:
                print_status(f"GitHub rate limit hit fetching events for "
                             f"'{username}' - status UNKNOWN, not 'no events'", "error")
                self.results = {
                    "target": username,
                    "emails_from_pushes": [],
                    "activity_timeline": {"hours": {}, "days": {}},
                    "repos_interacted": [],
                    "event_type_counts": {},
                    "total_events": 0,
                    "error": "fetch_failed",
                }
                return False
            print_status(f"No public events found for '{username}'", "warning")
            self.results = {
                "target": username,
                "emails_from_pushes": [],
                "activity_timeline": {"hours": {}, "days": {}},
                "repos_interacted": [],
                "event_type_counts": {},
                "total_events": 0,
            }
            return True

        print_status(f"Retrieved {len(all_events)} events", "info")

        # Data structures
        emails_found = {}  # email -> {names, repos, count}
        repos_interacted = {}  # repo_name -> event count
        event_types = Counter()
        hour_counts = Counter()
        day_counts = Counter()

        for event in all_events:
            event_type = event.get("type", "Unknown")
            event_types[event_type] += 1

            # Track repo interaction
            repo_info = event.get("repo", {})
            repo_name = repo_info.get("name", "unknown/unknown")
            repos_interacted[repo_name] = repos_interacted.get(repo_name, 0) + 1

            # Parse timestamp for activity timeline
            created_at = event.get("created_at", "")
            hour, weekday = self._parse_timestamp(created_at)
            if hour is not None:
                hour_counts[hour] += 1
            if weekday is not None:
                day_counts[weekday] += 1

            # Extract emails from PushEvents
            if event_type == "PushEvent":
                payload = event.get("payload", {})
                commits = payload.get("commits", [])
                for commit in commits:
                    author = commit.get("author", {})
                    email = author.get("email", "")
                    name = author.get("name", "")

                    if not email:
                        continue

                    # Skip GitHub noreply addresses
                    if email.endswith("@users.noreply.github.com"):
                        continue
                    if email.lower() in ("noreply@github.com", "notifications@github.com"):
                        continue

                    email_lower = email.lower()
                    if email_lower not in emails_found:
                        emails_found[email_lower] = {
                            "email": email_lower,
                            "names": set(),
                            "repos": set(),
                            "count": 0,
                        }
                    if name:
                        emails_found[email_lower]["names"].add(name)
                    emails_found[email_lower]["repos"].add(repo_name)
                    emails_found[email_lower]["count"] += 1

        # Convert sets to lists for JSON serialization
        emails_list = []
        for email_data in emails_found.values():
            emails_list.append({
                "email": email_data["email"],
                "names": list(email_data["names"]),
                "repos": list(email_data["repos"]),
                "commit_count": email_data["count"],
            })
            print_status(
                f"  Email found: {email_data['email']} "
                f"(names: {', '.join(email_data['names'])}, "
                f"{email_data['count']} commits)", "success"
            )

        # Build sorted repos list
        sorted_repos = sorted(
            [{"repo": r, "event_count": c} for r, c in repos_interacted.items()],
            key=lambda x: x["event_count"],
            reverse=True,
        )

        # Activity timeline
        activity_timeline = {
            "hours": dict(sorted(hour_counts.items())),
            "days": dict(sorted(day_counts.items(), key=lambda x: [
                "Monday", "Tuesday", "Wednesday", "Thursday",
                "Friday", "Saturday", "Sunday"
            ].index(x[0]) if x[0] in [
                "Monday", "Tuesday", "Wednesday", "Thursday",
                "Friday", "Saturday", "Sunday"
            ] else 7)),
        }

        # Find peak activity
        if hour_counts:
            peak_hour = hour_counts.most_common(1)[0]
            print_status(f"  Peak hour: {peak_hour[0]}:00 UTC ({peak_hour[1]} events)", "info")
        if day_counts:
            peak_day = day_counts.most_common(1)[0]
            print_status(f"  Peak day: {peak_day[0]} ({peak_day[1]} events)", "info")

        # Summary
        print_status(f"Event analysis complete for {username}", "success")
        print_status(f"  Total events: {len(all_events)}", "info")
        print_status(f"  Unique emails from pushes: {len(emails_list)}", "info")
        print_status(f"  Repos interacted with: {len(sorted_repos)}", "info")
        print_status(f"  Event types: {dict(event_types.most_common())}", "info")

        self.results = {
            "target": username,
            "emails_from_pushes": emails_list,
            "activity_timeline": activity_timeline,
            "repos_interacted": sorted_repos,
            "event_type_counts": dict(event_types.most_common()),
            "total_events": len(all_events),
        }
        return True

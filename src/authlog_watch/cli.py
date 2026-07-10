import argparse
import json

from .parser import load_events
from .report import AuthSummary, summarize_events


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="authlog-watch",
        description="Review Linux auth.log SSH events.",
    )
    parser.add_argument("path", help="Path to an auth.log-style file")
    parser.add_argument(
        "--json",
        action="store_true",
        help="Print the summary as JSON for scripts",
    )
    parser.add_argument(
        "--failed-threshold",
        type=positive_int,
        default=3,
        help="Flag source IPs with this many failed SSH login events",
    )
    args = parser.parse_args()

    events = load_events(args.path)
    summary = summarize_events(events, failed_threshold=args.failed_threshold)

    if args.json:
        print(json.dumps(summary.to_dict(), indent=2))
    else:
        print_report(summary)


def print_report(summary: AuthSummary) -> None:
    print("authlog-watch")
    print(f"SSH events parsed: {summary.events_checked}")
    print(f"Failed passwords: {summary.failed_passwords}")
    print(f"Invalid users: {summary.invalid_users}")
    print(f"Accepted passwords: {summary.accepted_passwords}")
    print(f"Accepted publickeys: {summary.accepted_publickeys}")
    print(f"Disconnected: {summary.disconnected}")

    if summary.top_source_ips:
        print("\nTop failed source IPs")
        for source_ip, count in summary.top_source_ips:
            print(f"- {source_ip}: {count}")

    if summary.top_users:
        print("\nTop targeted users")
        for user, count in summary.top_users:
            print(f"- {user}: {count}")

    if summary.findings:
        print("\nFindings")
        for finding in summary.findings:
            print(f"- {finding.rule_id}: {finding.message}")


def positive_int(value: str) -> int:
    parsed = int(value)
    if parsed < 1:
        raise argparse.ArgumentTypeError("must be at least 1")
    return parsed

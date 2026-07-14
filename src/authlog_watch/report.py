from collections import Counter
from dataclasses import dataclass

from .models import AuthEvent


@dataclass(frozen=True)
class AuthFinding:
    rule_id: str
    source_ip: str
    failed_count: int
    message: str

    def to_dict(self) -> dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "source_ip": self.source_ip,
            "failed_count": self.failed_count,
            "message": self.message,
        }


@dataclass(frozen=True)
class AuthSummary:
    events_checked: int
    failed_passwords: int
    invalid_users: int
    accepted_passwords: int
    accepted_publickeys: int
    disconnected: int
    connection_closed: int
    top_source_ips: list[tuple[str, int]]
    top_users: list[tuple[str, int]]
    findings: list[AuthFinding]

    def to_dict(self) -> dict[str, object]:
        return {
            "events_checked": self.events_checked,
            "failed_passwords": self.failed_passwords,
            "invalid_users": self.invalid_users,
            "accepted_passwords": self.accepted_passwords,
            "accepted_publickeys": self.accepted_publickeys,
            "disconnected": self.disconnected,
            "connection_closed": self.connection_closed,
            "top_source_ips": [
                {"source_ip": source_ip, "count": count}
                for source_ip, count in self.top_source_ips
            ],
            "top_users": [
                {"user": user, "count": count}
                for user, count in self.top_users
            ],
            "findings": [finding.to_dict() for finding in self.findings],
        }


def summarize_events(
    events: list[AuthEvent],
    limit: int = 5,
    failed_threshold: int = 3,
) -> AuthSummary:
    failed_events = [
        event
        for event in events
        if event.event_type in {"failed_password", "invalid_user"}
    ]
    failed_source_counts = Counter(event.source_ip for event in failed_events)

    return AuthSummary(
        events_checked=len(events),
        failed_passwords=count_type(events, "failed_password"),
        invalid_users=count_type(events, "invalid_user"),
        accepted_passwords=count_type(events, "accepted_password"),
        accepted_publickeys=count_type(events, "accepted_publickey"),
        disconnected=count_type(events, "disconnected"),
        connection_closed=count_type(events, "connection_closed"),
        top_source_ips=failed_source_counts.most_common(limit),
        top_users=Counter(event.user for event in failed_events).most_common(limit),
        findings=make_failed_source_findings(failed_source_counts, failed_threshold),
    )


def count_type(events: list[AuthEvent], event_type: str) -> int:
    return sum(1 for event in events if event.event_type == event_type)


def make_failed_source_findings(
    failed_source_counts: Counter[str],
    failed_threshold: int,
) -> list[AuthFinding]:
    if failed_threshold < 1:
        raise ValueError("failed_threshold must be at least 1")

    findings: list[AuthFinding] = []
    for source_ip, failed_count in failed_source_counts.most_common():
        if failed_count < failed_threshold:
            continue

        findings.append(
            AuthFinding(
                rule_id="repeated_failed_source",
                source_ip=source_ip,
                failed_count=failed_count,
                message=(
                    f"{source_ip} had {failed_count} failed SSH login events "
                    f"(threshold: {failed_threshold})"
                ),
            )
        )
    return findings

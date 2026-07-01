from collections import Counter
from dataclasses import dataclass

from .models import AuthEvent


@dataclass(frozen=True)
class AuthSummary:
    events_checked: int
    failed_passwords: int
    invalid_users: int
    accepted_passwords: int
    top_source_ips: list[tuple[str, int]]
    top_users: list[tuple[str, int]]

    def to_dict(self) -> dict[str, object]:
        return {
            "events_checked": self.events_checked,
            "failed_passwords": self.failed_passwords,
            "invalid_users": self.invalid_users,
            "accepted_passwords": self.accepted_passwords,
            "top_source_ips": [
                {"source_ip": source_ip, "count": count}
                for source_ip, count in self.top_source_ips
            ],
            "top_users": [
                {"user": user, "count": count}
                for user, count in self.top_users
            ],
        }


def summarize_events(events: list[AuthEvent], limit: int = 5) -> AuthSummary:
    failed_events = [
        event
        for event in events
        if event.event_type in {"failed_password", "invalid_user"}
    ]

    return AuthSummary(
        events_checked=len(events),
        failed_passwords=count_type(events, "failed_password"),
        invalid_users=count_type(events, "invalid_user"),
        accepted_passwords=count_type(events, "accepted_password"),
        top_source_ips=Counter(event.source_ip for event in failed_events).most_common(limit),
        top_users=Counter(event.user for event in failed_events).most_common(limit),
    )


def count_type(events: list[AuthEvent], event_type: str) -> int:
    return sum(1 for event in events if event.event_type == event_type)

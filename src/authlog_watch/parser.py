import re
from pathlib import Path

from .models import AuthEvent

PREFIX_RE = re.compile(
    r"^(?P<timestamp>\w{3}\s+\d+\s+\d\d:\d\d:\d\d)\s+"
    r"(?P<host>\S+)\s+"
    r"(?P<service>sshd)\[(?P<pid>\d+)\]:\s+"
    r"(?P<message>.*)$"
)

FAILED_PASSWORD_RE = re.compile(
    r"^Failed password for (?:(?P<invalid>invalid user)\s+)?"
    r"(?P<user>\S+) from (?P<source_ip>\S+) port (?P<port>\d+)"
)

ACCEPTED_PASSWORD_RE = re.compile(
    r"^Accepted password for (?P<user>\S+) from (?P<source_ip>\S+) port (?P<port>\d+)"
)

DISCONNECTED_RE = re.compile(
    r"^Disconnected from (?:(?P<invalid>invalid user)\s+|(?P<auth>authenticating user)\s+)?"
    r"(?P<user>\S+) (?P<source_ip>\S+) port (?P<port>\d+)"
)


def load_events(path: str | Path) -> list[AuthEvent]:
    lines = Path(path).read_text(encoding="utf-8").splitlines()
    return parse_lines(lines)


def parse_lines(lines: list[str]) -> list[AuthEvent]:
    events: list[AuthEvent] = []
    for line in lines:
        event = parse_line(line)
        if event:
            events.append(event)
    return events


def parse_line(line: str) -> AuthEvent | None:
    prefix = PREFIX_RE.match(line)
    if not prefix:
        return None

    message = prefix.group("message")
    failed = FAILED_PASSWORD_RE.match(message)
    if failed:
        return make_event(
            prefix=prefix,
            match=failed,
            event_type="invalid_user" if failed.group("invalid") else "failed_password",
            raw=line,
        )

    accepted = ACCEPTED_PASSWORD_RE.match(message)
    if accepted:
        return make_event(
            prefix=prefix,
            match=accepted,
            event_type="accepted_password",
            raw=line,
        )

    disconnected = DISCONNECTED_RE.match(message)
    if disconnected:
        return make_event(
            prefix=prefix,
            match=disconnected,
            event_type="disconnected",
            raw=line,
        )

    return None


def make_event(prefix: re.Match[str], match: re.Match[str], event_type: str, raw: str) -> AuthEvent:
    return AuthEvent(
        timestamp=prefix.group("timestamp"),
        host=prefix.group("host"),
        service=prefix.group("service"),
        event_type=event_type,
        user=match.group("user"),
        source_ip=match.group("source_ip"),
        port=match.group("port"),
        raw=raw,
    )

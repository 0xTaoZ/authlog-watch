import unittest

from authlog_watch.models import AuthEvent
from authlog_watch.report import summarize_events


def make_event(event_type: str, user: str, source_ip: str) -> AuthEvent:
    return AuthEvent(
        timestamp="Jul  1 08:15:01",
        host="lab",
        service="sshd",
        event_type=event_type,
        user=user,
        source_ip=source_ip,
        port="53321",
        raw="sample",
    )


class ReportTest(unittest.TestCase):
    def test_summarize_events_counts_auth_types(self):
        events = [
            make_event("failed_password", "alice", "198.51.100.10"),
            make_event("invalid_user", "admin", "203.0.113.50"),
            make_event("accepted_password", "alice", "198.51.100.10"),
            make_event("accepted_publickey", "deploy", "203.0.113.77"),
            make_event("disconnected", "root", "192.168.1.10"),
            make_event("connection_closed", "git", "192.0.2.44"),
        ]

        summary = summarize_events(events)

        self.assertEqual(summary.events_checked, 6)
        self.assertEqual(summary.failed_passwords, 1)
        self.assertEqual(summary.invalid_users, 1)
        self.assertEqual(summary.accepted_passwords, 1)
        self.assertEqual(summary.accepted_publickeys, 1)
        self.assertEqual(summary.disconnected, 1)
        self.assertEqual(summary.connection_closed, 1)

    def test_summarize_events_tracks_top_failed_sources_and_users(self):
        events = [
            make_event("failed_password", "alice", "198.51.100.10"),
            make_event("failed_password", "alice", "198.51.100.10"),
            make_event("invalid_user", "admin", "203.0.113.50"),
            make_event("accepted_password", "bob", "192.0.2.20"),
        ]

        summary = summarize_events(events)

        self.assertEqual(summary.top_source_ips[0], ("198.51.100.10", 2))
        self.assertEqual(summary.top_users[0], ("alice", 2))

    def test_summarize_events_flags_repeated_failed_sources(self):
        events = [
            make_event("failed_password", "alice", "198.51.100.10"),
            make_event("invalid_user", "root", "198.51.100.10"),
            make_event("failed_password", "bob", "203.0.113.50"),
        ]

        summary = summarize_events(events, failed_threshold=2)

        self.assertEqual(len(summary.findings), 1)
        self.assertEqual(summary.findings[0].rule_id, "repeated_failed_source")
        self.assertEqual(summary.findings[0].source_ip, "198.51.100.10")
        self.assertEqual(summary.findings[0].failed_count, 2)

    def test_summarize_events_rejects_invalid_threshold(self):
        with self.assertRaises(ValueError):
            summarize_events([], failed_threshold=0)


if __name__ == "__main__":
    unittest.main()

import unittest

from authlog_watch.parser import parse_line, parse_lines


class ParserTest(unittest.TestCase):
    def test_parse_failed_password(self):
        line = "Jul  1 08:15:01 lab sshd[1842]: Failed password for alice from 198.51.100.10 port 53321 ssh2"

        event = parse_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "failed_password")
        self.assertEqual(event.user, "alice")
        self.assertEqual(event.source_ip, "198.51.100.10")

    def test_parse_invalid_user(self):
        line = "Jul  1 08:17:44 lab sshd[1848]: Failed password for invalid user admin from 203.0.113.50 port 49152 ssh2"

        event = parse_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "invalid_user")
        self.assertEqual(event.user, "admin")

    def test_parse_invalid_user_probe(self):
        line = "Jul  1 08:17:40 lab sshd[1847]: Invalid user admin from 203.0.113.50 port 49151"

        event = parse_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "invalid_user")
        self.assertEqual(event.user, "admin")
        self.assertEqual(event.source_ip, "203.0.113.50")

    def test_parse_accepted_password(self):
        line = "Jul  1 08:21:02 lab sshd[1850]: Accepted password for alice from 198.51.100.10 port 53330 ssh2"

        event = parse_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "accepted_password")

    def test_parse_accepted_publickey(self):
        line = "Jul  1 08:22:10 lab sshd[1851]: Accepted publickey for deploy from 203.0.113.77 port 51234 ssh2: ED25519 SHA256:abc123"

        event = parse_line(line)

        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "accepted_publickey")
        self.assertEqual(event.user, "deploy")
        self.assertEqual(event.source_ip, "203.0.113.77")

    def test_parse_disconnected_authenticating_user(self):
        line = "Jul  1 08:25:12 lab sshd[1852]: Disconnected from authenticating user root 192.168.1.10 port 44321 [preauth]"
        
        event = parse_line(line)
        
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "disconnected")
        self.assertEqual(event.user, "root")
        self.assertEqual(event.source_ip, "192.168.1.10")

    def test_parse_disconnected_invalid_user(self):
        line = "Jul  1 08:26:15 lab sshd[1855]: Disconnected from invalid user admin 10.0.0.1 port 12345 [preauth]"
        
        event = parse_line(line)
        
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "disconnected")
        self.assertEqual(event.user, "admin")
        self.assertEqual(event.source_ip, "10.0.0.1")

    def test_parse_disconnected_plain_user(self):
        line = "Jul  1 08:27:10 lab sshd[1856]: Disconnected from user alice 192.168.1.10 port 12345"
        
        event = parse_line(line)
        
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, "disconnected")
        self.assertEqual(event.user, "alice")
        self.assertEqual(event.source_ip, "192.168.1.10")

    def test_parse_lines_ignores_unknown_lines(self):
        lines = [
            "Jul  1 08:15:01 lab sudo: alice : TTY=pts/0 ; PWD=/home/alice ; USER=root ; COMMAND=/usr/bin/id",
            "Jul  1 08:15:02 lab sshd[1842]: Failed password for alice from 198.51.100.10 port 53321 ssh2",
        ]

        events = parse_lines(lines)

        self.assertEqual(len(events), 1)


if __name__ == "__main__":
    unittest.main()

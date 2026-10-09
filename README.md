# authlog-watch

A small Python tool for reviewing Linux SSH authentication logs.

It reads auth.log-style lines, groups common SSH events, and prints a short triage report. The goal is to practice blue-team log review with simple code that can be read in one sitting.

Both rsyslog timestamp styles are read: the classic `Oct  8 03:00:01` and the RFC 3339 format that Debian 12 and Ubuntu 23.10 and later write by default (`2026-10-08T03:00:01.123456+02:00`). Lines from `sshd-session` and `sshd-auth`, which OpenSSH 9.8 and 10.0 use for per-connection logging, are read as well as `sshd`.

This is a learning project, not a replacement for a SIEM.

## Quick start

```bash
PYTHONPATH=src python3 -m authlog_watch samples/auth.log
```

Run tests:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

## Example output

```text
authlog-watch
SSH events parsed: 11
Failed passwords: 2
Invalid users: 3
Accepted passwords: 1
Accepted publickeys: 1
Disconnected: 0
Connection closed: 2
Received disconnects: 1
Unable to negotiate: 1

Top failed source IPs
- 203.0.113.50: 3
- 198.51.100.10: 2

Successful login source IPs
- 198.51.100.10: 1
- 203.0.113.77: 1

Successful login users
- alice: 1
- deploy: 1

Pre-auth disconnect source IPs
- 192.0.2.44: 1
- 192.0.2.46: 1
- 192.0.2.45: 1
- 203.0.113.88: 1

Top targeted users
- alice: 2
- admin: 2
- test: 1

Findings
- repeated_failed_source: 203.0.113.50 had 3 failed SSH login events (threshold: 3)
- mixed_auth_outcome_source: 198.51.100.10 had 2 failed and 1 successful SSH login events
```

JSON output is available for small scripts:

```bash
PYTHONPATH=src python3 -m authlog_watch samples/auth.log --json
```

## Repeated failure findings

The default report flags a source IP after 3 failed SSH login events. Use a lower
or higher threshold when reviewing short lab logs or noisy production logs:

```bash
PYTHONPATH=src python3 -m authlog_watch samples/auth.log --failed-threshold 2
```

That adds a `Findings` section to the text report and a `findings` list to JSON
output. The rule counts both normal failed passwords and invalid-user attempts.

The report also flags a source IP when it has both failed and successful SSH
login events. That does not prove compromise by itself, but it is a useful
small clue when reviewing lab logs or looking for noisy login attempts followed
by a real session.

Limit each top summary section when reviewing noisy logs:

```bash
PYTHONPATH=src python3 -m authlog_watch samples/auth.log --limit 3
```

Print only the event counts when you do not need ranked details or findings:

```bash
PYTHONPATH=src python3 -m authlog_watch samples/auth.log --summary-only
```

`--summary-only` is a text output mode and cannot be combined with `--json`.

Connection-close records without a username are included in disconnect counts and
source summaries. Their event user is `-`; they do not count as failed logins or
targeted users. Both IPv4 and IPv6 source addresses are supported.

## Current plan

- parse common SSH login events
- summarize failed login sources and target users
- print text and JSON reports
- keep fake sample logs for practice
- flag repeated failed login sources
- flag source IPs with both failed and successful SSH login events
- count standalone invalid-user probes before password checks
- count accepted password and public-key logins separately
- summarize successful login source IPs
- summarize successful login users
- count SSH connections closed during pre-authentication
- count SSH received-disconnect pre-authentication events
- count SSH negotiation failures before authentication
- summarize pre-authentication disconnect source IPs
- limit top summary sections for noisy logs
- print event counts without detail sections
- add more SSH event types over time

# authlog-watch

A small Python tool for reviewing Linux SSH authentication logs.

It reads auth.log-style lines, groups common SSH events, and prints a short triage report. The goal is to practice blue-team log review with simple code that can be read in one sitting.

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
SSH events parsed: 10
Failed passwords: 2
Invalid users: 3
Accepted passwords: 1
Accepted publickeys: 1
Disconnected: 0
Connection closed: 1
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
- add more SSH event types over time

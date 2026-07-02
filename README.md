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
SSH events parsed: 5
Failed passwords: 2
Invalid users: 2
Accepted passwords: 1

Top failed source IPs
- 198.51.100.10: 2
- 203.0.113.50: 2

Top targeted users
- alice: 2
- admin: 1
- test: 1
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

## Current plan

- parse common SSH login events
- summarize failed login sources and target users
- print text and JSON reports
- keep fake sample logs for practice
- flag repeated failed login sources
- add more SSH event types over time

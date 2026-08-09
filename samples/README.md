# Samples

The sample log is fake auth.log-style data for testing and practice.

It includes failed SSH logins, a standalone invalid-user probe, password and
public-key successful logins, one pre-authentication connection-close event,
one pre-authentication received-disconnect event, and one unrelated sudo line
that the parser ignores.

One source IP has 3 invalid-user or failed SSH login events, and another has 2.
That makes the file useful for trying the repeated-failure rule with
`--failed-threshold 2` or the default threshold of 3.

The successful password and public-key login lines also let the report show
which source IPs actually got SSH access.

The pre-authentication connection-close and received-disconnect lines use
different fake source IPs, so the report can show quick source counts for
disconnect noise before a login succeeds or fails.

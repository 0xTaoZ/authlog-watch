# Samples

The sample log is fake auth.log-style data for testing and practice.

It includes failed SSH logins, invalid users, one successful login, and one unrelated sudo line that the parser ignores.

Two source IPs have 2 failed SSH login events each. That makes the file useful
for trying the repeated-failure rule with `--failed-threshold 2`.

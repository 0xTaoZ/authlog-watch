# Contributing

This is a small learning project, so changes should stay easy to review.

Useful contributions:

- add a new auth.log pattern with a test
- improve the text report without making it noisy
- add fake sample lines that show a real investigation case
- keep dependencies low unless a library clearly helps

Before opening a change, run:

```bash
PYTHONPATH=src python3 -m unittest discover -s tests
```

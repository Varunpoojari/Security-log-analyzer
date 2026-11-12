# Security Policy

Security Log Analyzer reads JSON Lines log files and flags suspicious activity such as repeated failed logins. Log files often come from untrusted sources, so please treat any file you did not create yourself as untrusted input.

## Supported versions

| Version | Supported |
|---|---|
| `main` | Yes |
| Older commits | No |

## Reporting a vulnerability

Please **do not open a public issue** for security problems.

Report privately through GitHub's [private vulnerability reporting](https://github.com/Varunpoojari/Security-log-analyzer/security/advisories/new) (Security tab, then "Report a vulnerability").

Please include:

- what is affected (a function or input format)
- steps to reproduce, with a minimal log file if possible
- the impact you expect (for example a crash, excessive memory use, or wrong results from crafted input)

I aim to acknowledge reports within 7 days and to agree a fix and disclosure timeline with you before anything is made public.

## Scope

In scope:

- parsing of log files in `log_analyzer.py`
- detection logic that could be bypassed or abused by crafted log entries

Out of scope:

- vulnerabilities in third-party dependencies such as pandas (please report those upstream)
- findings that need an already-compromised machine

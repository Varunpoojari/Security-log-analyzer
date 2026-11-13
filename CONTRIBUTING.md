# Contributing to Security Log Analyzer

Thanks for your interest in improving this project. Bug reports, new detection ideas and documentation fixes are welcome.

## Reporting bugs and ideas

1. Search the existing [issues](https://github.com/Varunpoojari/Security-log-analyzer/issues) first.
2. Open a new issue with the steps to reproduce, ideally with a small log file that triggers the problem (remove real IP addresses and user data first).
3. For security problems, follow [SECURITY.md](SECURITY.md) instead of opening a public issue.

## Development setup

```bash
git clone https://github.com/Varunpoojari/Security-log-analyzer.git
cd Security-log-analyzer
python3 -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
pip install -r requirements-dev.txt
```

Run the tests:

```bash
pytest
```

Run the analyzer on the included sample log:

```bash
python log_analyzer.py
```

## Pull request process

1. Fork the repository and create a branch from `main` (for example `feature/detect-port-scan`).
2. Keep each pull request to one change.
3. Add or update tests in `tests/` for any change in behaviour, and make sure `pytest` passes.
4. Update the README when you add options or change the log format.
5. Explain what changed and why in the pull request description.

## Code style

- PEP 8 with four-space indentation.
- Keep detection rules small and testable, and document the threshold or logic they use.
- Never commit real logs or personal data.

## License

By contributing you agree that your contributions are licensed under the project's [MIT License](LICENSE).

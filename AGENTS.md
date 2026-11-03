# Repository Guidelines

## Project Structure & Module Organization
- `reality_installer.py`: main Python entrypoint for installing and configuring Xray (`VLESS + Reality + Vision`).
- `check_deployment.py`: read-only health check for versions, UFW rules, fq/BBR, service state, and config.
- `tests/test_installer.py`: unit tests for parser logic, distro adapters, firewall/sysctl command selection, and config generation.
- `tests/test_check_deployment.py`: unit tests for check-script parsers.
- `docs/`: usage and planning docs (including Chinese deployment notes and implementation plans).
- Root files: `README.md` (usage), `LICENSE`, `.gitignore`.

Keep new production logic in `reality_installer.py` unless refactoring into modules becomes necessary; place tests under `tests/` with matching scope.

## Build, Test, and Development Commands
- `python3 -m unittest discover -s tests -v`: run all tests.
- `python3 reality_installer.py --dry-run`: simulate installer actions without changing the system.
- `sudo python3 reality_installer.py --server-name www.tesla.com --port 443 --skip-upgrade`: run installer locally with explicit options.
- `sudo python3 check_deployment.py`: read-only deployment health check.

There is no separate build step; this project consists of Python runtime scripts.

## Coding Style & Naming Conventions
- Follow PEP 8 with 4-space indentation and descriptive snake_case names (`parse_os_release_text`, `get_upgrade_commands`).
- Keep functions focused and side-effect boundaries explicit (pure helpers vs. system-changing calls).
- Prefer typed signatures already used in code (`-> dict[str, str]`, `list[list[str]]`).
- Raise `DeploymentError` for recoverable deployment failures; avoid silent fallbacks.

## Testing Guidelines
- Framework: Python `unittest`.
- Add tests for every behavior change, especially distro detection, command generation, config rendering, and check-script parsers.
- Name tests as `test_<behavior>` and group by concern in `unittest.TestCase` classes.
- Run `python3 -m unittest discover -s tests -v` before opening a PR.

## Commit & Pull Request Guidelines
- Use concise, conventional-style commit messages (for example: `feat: add arch sysctl path handling`, `fix: validate short-id length`).
- Keep commits focused and logically isolated.
- PRs should include:
  - Purpose and summary of behavior changes.
  - Test evidence (commands run and key results).
  - Any operational impact (required sudo/root behavior, firewall or sysctl changes).
  - Linked issue/task when applicable.

## Security & Configuration Tips
- Treat generated UUID/private key/short-id values as sensitive.
- Prefer `--dry-run` first on unfamiliar hosts.
- Document risky defaults or distro-specific assumptions in `README.md` and tests.

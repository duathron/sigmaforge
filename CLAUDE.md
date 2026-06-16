# sigmaforge

CLI tool: Honest Sigma-rule backtest harness. Built with the Shipwright framework.

## Rules
- All code, commits, docs in English.
- Architecture: Typer CLI, Pydantic v2 models, Rich output (package under `sigmaforge/`).
- Config hierarchy: CLI flags > env (`SIGMAFORGE_*`) > `~/.sigmaforge/config.yaml` > defaults.
- `__version__` is a literal (never importlib.metadata — stale on editable installs).

## Quality policy (from Shipwright — enforced)
- **No self-review** — gate every change with an independent reviewer (the Skeptic persona).
- **No release without a dogfood pass** — `just dogfood` (real + adversarial inputs) must pass.
- **Parse liberally at boundaries** — external input never raises; unknown -> safe fallback (see `sigmaforge/detect.py`).
- **Two test tiers** — Tier-1 mocked every push (CI); Tier-2 live+recorded before release.

## Dev loop
`uv sync --dev` · `uv run pre-commit install` · `just lint` · `just test` · `just dogfood`

default:
    @just --list

lint:
    uv run ruff check .
    uv run ruff format --check .

fmt:
    uv run ruff format .

test:
    uv run pytest -q

smoke:
    uv run sigmaforge manual >/dev/null

# Mandatory pre-release gate: real + adversarial inputs, never crash.
dogfood:
    bash dogfood.sh

build:
    uv build

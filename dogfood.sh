#!/usr/bin/env bash
# Dogfood gate — run the real CLI against real + adversarial inputs.
# Framework QA policy: no release without a dogfood pass.
#
# Hermetic: no engine, no corpus, no user config. Every call runs with SIGMAFORGE_HOME /
# SIGMAFORGE_ZIRCOLITE unset and an empty --config, so an installed engine or a personal
# config cannot change the outcome. The CLI must handle every input gracefully:
# an allowed exit code is 0 (ok), 3 (no engine) or 4 (no corpus); 1 (crash) or 2 (usage) fails.
set -uo pipefail

CMD="sigmaforge"
fail=0
WORK="$(mktemp -d)"
EMPTY_CFG="$WORK/empty.yaml"
EMPTY_ENGINE="$WORK/no-engine"
: >"$EMPTY_CFG"
mkdir -p "$EMPTY_ENGINE"

run() {
  # run <allowed exit codes, comma separated> <command and args...>
  local allowed="$1"
  shift
  local out rc
  out="$(env -u SIGMAFORGE_HOME -u SIGMAFORGE_ZIRCOLITE uv run "$@" 2>&1)"
  rc=$?
  case ",$allowed," in
    *",$rc,"*) ;;
    *)
      echo "DOGFOOD FAIL: '$*' exited $rc (allowed: $allowed)"
      printf '%s\n' "$out" | tail -3
      fail=1
      ;;
  esac
}

echo "== dogfood: no-engine surface =="
run 0 "$CMD" manual
run 0 "$CMD" backtest --help
run 0 "$CMD" hunt --help
run 4 "$CMD" backtest --config "$EMPTY_CFG"
run 3 "$CMD" hunt --config "$EMPTY_CFG" --engine-home "$EMPTY_ENGINE" --rules data/fixtures/smoke/rules --logs data/fixtures/smoke/benign.jsonl

echo "== dogfood: adversarial inputs =="
for r in "" "/etc/passwd" "no/such/rules" "a sentence." "[/x][bold]"; do
  run 3 "$CMD" hunt --config "$EMPTY_CFG" --engine-home "$EMPTY_ENGINE" --rules "$r" --logs "$r"
done
run 4 "$CMD" backtest --config "$EMPTY_CFG" --rules /etc/passwd

# --- LIVE tier (opt-in) ---
# Add real service calls here. Read the API key from SIGMAFORGE_API_KEY,
# and if it is unset, print "dogfood SKIPPED (live): no key" and continue.
# A skipped live tier must NOT satisfy the release gate (skip != pass).

if [ "$fail" -ne 0 ]; then echo "DOGFOOD: FAIL"; exit 1; fi
echo "DOGFOOD: PASS"

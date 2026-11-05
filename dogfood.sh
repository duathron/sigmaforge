#!/usr/bin/env bash
# Dogfood gate — run the real CLI against real + adversarial inputs.
# Framework QA policy: no release without a dogfood pass.
#
# Hermetic: no engine, no corpus, no user config. Every call runs with SIGMAFORGE_HOME /
# SIGMAFORGE_ZIRCOLITE unset and an empty --config, so an installed engine or a personal
# config cannot change the outcome. The CLI must handle every input gracefully:
# an allowed exit code is 0 (ok), 3 (no engine) or 4 (no corpus); 1 (a crash OR an engine
# failure, both mean the run did not complete) or 2 (usage) fails,
# and so does any raw ESC byte in the output (terminal-escape injection).
#
# What the tiers prove: the no-engine / adversarial tier proves the CLI refuses cleanly (never
# a traceback) BEFORE the engine is needed. The fake-engine tier gets past that preflight with
# a stub engine whose rule title and stderr are hostile, so compile + run + report paths are
# exercised for crash-resistance. Neither tier measures detection quality (no real engine here).
set -uo pipefail

CMD="sigmaforge"
fail=0
WORK="$(mktemp -d)"
EMPTY_CFG="$WORK/empty.yaml"
EMPTY_ENGINE="$WORK/no-engine"
FAKE_ENGINE="$WORK/fake-engine"
FAKE_RULES="$WORK/rules"
: >"$EMPTY_CFG"
mkdir -p "$EMPTY_ENGINE" "$FAKE_ENGINE/Zircolite/zircolite" "$FAKE_RULES"
# Stub engine: a package that "compiles" one hostile-titled rule, and a script that writes
# hostile text to stdout/stderr and an empty detection list.
: >"$FAKE_ENGINE/Zircolite/zircolite/__init__.py"
cat >"$FAKE_ENGINE/Zircolite/zircolite/config.py" <<'PYEOF'
class RulesetConfig:
    def __init__(self, ruleset, pipeline, save_ruleset):
        self.ruleset = ruleset
PYEOF
cat >"$FAKE_ENGINE/Zircolite/zircolite/rules.py" <<'PYEOF'
class RulesetHandler:
    def __init__(self, ruleset_config, logger):
        title = "[/x][bold]PASS\x1b]0;t\x07 | 9 | 9\n## forged"
        logger.info("converted %s", title)
        self.rulesets = [{"title": title}]
PYEOF
cat >"$FAKE_ENGINE/Zircolite/zircolite.py" <<'PYEOF'
import sys
sys.stdout.write("EVIL \x1b]0;PWN\x07 [link=http://x]ml[/link]\n")
sys.stderr.write("EVIL \x1b[41m\n")
open(sys.argv[sys.argv.index("--outfile") + 1], "w").write("[]")
PYEOF
printf 'title: "[/x] | evil"\nlogsource: {category: process_creation, product: windows}\ndetection: {s: {Image: x}, condition: s}\n' >"$FAKE_RULES/r.yml"

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
  case "$out" in
    *$'\033'*)
      echo "DOGFOOD FAIL: '$*' printed a raw ESC byte"
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

echo "== dogfood: past the preflight (stub engine, hostile rule title) =="
run 0 "$CMD" hunt --config "$EMPTY_CFG" --engine-home "$FAKE_ENGINE" --rules "$FAKE_RULES" \
  --logs data/fixtures/smoke/benign.jsonl --out "$WORK/hits.json"

# --- LIVE tier (opt-in) ---
# Add real service calls here. Read the API key from SIGMAFORGE_API_KEY,
# and if it is unset, print "dogfood SKIPPED (live): no key" and continue.
# A skipped live tier must NOT satisfy the release gate (skip != pass).

if [ "$fail" -ne 0 ]; then echo "DOGFOOD: FAIL"; exit 1; fi
echo "DOGFOOD: PASS"

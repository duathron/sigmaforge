#!/usr/bin/env bash
# Dogfood gate — run the real CLI against real + adversarial inputs.
# Framework QA policy: no release without a dogfood pass.
set -uo pipefail

CMD="sigmaforge"
fail=0

run() {
  # ANY non-zero exit = the CLI failed on this input (a crash exits 1, a usage
  # error exits 2). The CLI must handle every input gracefully and exit 0.
  if ! out="$(uv run "$CMD" classify "$1" 2>&1)"; then
    echo "DOGFOOD FAIL: '$1' exited nonzero"
    printf '%s\n' "$out" | tail -3
    fail=1
  fi
}

echo "== dogfood: real inputs =="
for i in 8.8.8.8 example.com "$(printf 'a%.0s' {1..40})"; do run "$i"; done

echo "== dogfood: adversarial inputs =="
for i in "" "report.dll" "/etc/passwd" "a sentence." "boom" "999.999.999.999"; do run "$i"; done

# --- LIVE tier (opt-in) ---
# Add real service calls here. Read the API key from SIGMAFORGE_API_KEY,
# and if it is unset, print "dogfood SKIPPED (live): no key" and continue.
# A skipped live tier must NOT satisfy the release gate (skip != pass).

if [ "$fail" -ne 0 ]; then echo "DOGFOOD: FAIL"; exit 1; fi
echo "DOGFOOD: PASS"

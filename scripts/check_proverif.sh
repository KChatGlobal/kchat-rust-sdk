#!/usr/bin/env bash
set -euo pipefail

require_outcomes() {
  local expected_true="$1"
  local expected_false="$2"
  local model="$3"
  local combined_model
  local output

  combined_model="$(mktemp /private/tmp/kchat-proverif.XXXXXX)"
  trap 'rm -f "$combined_model"' RETURN
  cat proofs/proverif/cryptolib.pvl "$model" > "$combined_model"
  if ! output="$(proverif -in pitype "$combined_model")"; then
    printf '%s\n' "$output"
    rm -f "$combined_model"
    trap - RETURN
    return 1
  fi
  rm -f "$combined_model"
  trap - RETURN
  printf '%s\n' "$output"
  [[ "$(grep -Ec '^RESULT (not attacker|not event|inj-event).* is true\.$' <<<"$output")" -eq "$expected_true" ]]
  [[ "$(grep -Ec '^RESULT (not attacker|not event|inj-event).* is false\.$' <<<"$output")" -eq "$expected_false" ]]
}

require_xwing_combined_wire_model() {
  local model="$1"

  grep -Eq 'let xwing_pk = xwing_public\(' "$model"
  grep -Eq 'xwing_encaps\(xwing_pk, coins\)' "$model"
  ! grep -Eq 'classical_kem_(pk|sk|private|public|encrypt|decrypt)' "$model"
  ! grep -Eq 'mlkem_(private|public|encaps|decaps|shared)' "$model"
}

proverif -help >/dev/null 2>&1 || :
require_xwing_combined_wire_model proofs/proverif/pq_mls_xwing_quantum_break.pv
require_outcomes 3 0 proofs/proverif/pq_mls_onboarding.pv
require_outcomes 0 2 proofs/proverif/pq_mls_classical_quantum_break.pv
require_outcomes 1 1 proofs/proverif/pq_mls_xwing_quantum_break.pv
require_outcomes 3 0 proofs/proverif/pq_mls_full_pq_quantum_break.pv

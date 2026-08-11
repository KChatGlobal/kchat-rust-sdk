# KChat full-PQ MLS ProVerif models

## Scope

Symbolic Dolev--Yao verification of new-group full-PQ MLS onboarding only.
The layout follows Signal's `proofs/proverif` convention; these are
independently written KChat models.

## KChat code mapping

- `merge_pending_commit()` maps to `CommitMerged`;
- `export_ratchet_tree(...)` maps to `TreeExported`; and
- `process_welcome_with_ratchet_tree(...)` maps to `JoinAccepted`.

## Non-goals

The models do not prove Rust implementation correctness, concrete security,
constant-time behavior, side-channel resistance, payload size, performance, or
MLS interoperability.

They also do not simulate quantum computation. The quantum-comparison models
instead give the attacker explicit symbolic reductions that break classical
public-key primitives; ML-KEM and ML-DSA remain ideal assumptions.

## Model outcomes

### Full-PQ onboarding model

`pq_mls_onboarding.pv` verifies three claims under the model's ideal ML-KEM,
ML-DSA, and authenticated-encryption assumptions:

| Claim | ProVerif result | Interpretation |
| --- | --- | --- |
| The Welcome-protected application secret is not learned by the network attacker. | true | The attacker cannot derive the secret from the Welcome and public transcript. |
| `JoinAccepted(group, epoch, tree_hash)` implies a matching `CommitMerged(group, epoch, tree_hash)`. | true | A join is tied to a committed group state. |
| `JoinAccepted(group, epoch, tree_hash)` implies a matching `TreeExported(group, epoch, tree_hash)`. | true | A join is tied to the external ratchet tree selected by that state. |

External-tree substitution is checked against the running implementation, not
by a deliberately vulnerable symbolic model: the full-PQ Rust integration test
mutates a serialized tree and verifies that
`process_welcome_with_ratchet_tree()` rejects it.

### Quantum-break comparison models

These models give the attacker an explicit symbolic "Shor oracle" for
classical public-key encryption and signatures. They do not model quantum
algorithms. A `false` result below is expected: it exhibits the consequence of
the stated classical break.

| Model | Result | Interpretation |
| --- | --- | --- |
| `pq_mls_classical_quantum_break.pv` | 0 true / 2 false | Classical confidentiality and classical signature authentication both fail under the break assumption. |
| `pq_mls_xwing_quantum_break.pv` | 1 true / 1 false | The ideal ML-KEM branch preserves Welcome secrecy, but a classical signature can be forged. |
| `pq_mls_full_pq_quantum_break.pv` | 3 true / 0 false | Welcome secrecy, authentication, and committed-state binding hold while ML-KEM and ML-DSA remain ideal assumptions. |

## Run

```bash
opam install -y proverif.2.05
eval "$(opam env)"
scripts/check_proverif.sh
```

---
name: sast-qa
description: Check a sast-assess run and its sast-report pack before anything is shared outside the assessment team. Use to normalise wording across reports, catch claims stronger than the evidence, reconcile counts between records and artefacts, find secrets or personal data, verify owner-pack checksums, and decide which artefacts are safe to share and which need human review. Finds nothing new.
---

# SAST QA

The last gate before a report leaves the team. It checks the set of artefacts as a whole,
fixes drift in wording, and records which artefacts may be shared. It discovers nothing and
never makes a claim stronger.

Read `../sast-assess/references/run-control.md` and
`../sast-assess/references/evidence-model.md` first.

## 1. Mechanical checks

Run all four and keep the output:

```sh
node <sast-assess-dir>/cloudflare/validate-findings.cjs <output-dir>/findings.json
node <sast-assess-dir>/cloudflare/validate-coverage-ledger.cjs <output-dir>/coverage-ledger.json
node <sast-assess-dir>/scripts/validate-register.mjs <output-dir>
node <skill-dir>/scripts/check-pack.mjs <output-dir>
```

An error in any of them blocks sharing. `check-pack` warnings each need a decision: strong
wording is acceptable only where it quotes a `not_safe_to_say` statement or describes a
`deployed-validated` record. Rewrite anything else using the evidence model's wording.

## 2. Rules of engagement

From `run-record.json` and the scan copy manifest, confirm:

- the scope was approved before the run, and names attacker classes and thresholds;
- the target was a scan copy, and its manifest shows the secret scan was run and anything it
  found was redacted;
- `execution` was `none` or `sandboxed-local`, and nothing in the reports suggests a live or
  shared system was touched;
- outputs are in the scope's output location, not in a repository;
- `same_model_verification` is stated in every finding report and the executive summary when
  it is true.

Any failure here blocks sharing.

## 3. Reading the set

Use the register and counts first; open report bodies only where something disagrees.

- Each report's verdict, severity, labels and claims match `findings.json` and
  `register.json`.
- Evidence labels are the canonical ones. Replace near-synonyms: "confirmed in code" is
  `SAST-confirmed`; "not tested" is `not-validated`; "needs config check" is
  `config-dependent`; "confirmed locally" is `locally-validated`.
- Local results are never described as deployed ones. Production impact is stated only
  with `deployed-validated` evidence.
- No `needs_validation` record has a severity anywhere, including tickets and the summary.
- Scanner leads are never described as findings.
- Web, API and admin findings keep authentication, endpoint authorisation, object scope,
  CSRF and feature flags separate.
- Remediation matches the control that is missing, and validation actions are safe,
  specific, and say whether live access is needed.
- Every chain is labelled no stronger than its weakest link.
- The executive summary's coverage and limits section matches the ledger and the scan copy
  manifest.
- Hardening notes are not presented as findings.

Fix wording in place. Never change a verdict, severity or claim here. If one looks wrong, list
it as unresolved and send it back to `sast-assess`.

## 4. Decide

Write `<output-dir>/report/QA.md`:

| Artefact | Lifecycle | Result | Changes made | Reason |
|---|---|---|---|---|

Result is one of:

- `safe-to-share`: every check above passes for this artefact and its records;
- `requires-human-review`: wording or a judgement needs a named reviewer;
- `withheld`: an error, a rules-of-engagement failure or an unresolved mismatch.

List unresolved mismatches with file paths. Re-run `check-pack.mjs` after every change; edits
inside an owner pack mean regenerating its `SHA256SUMS`.

End `QA.md` with exactly:

```text
QA result: <n> safe to share, <n> requiring human review, <n> withheld.
```

"Safe to share" means the artefact is consistent with the evidence. It does not replace the
named human review recorded in each register entry.

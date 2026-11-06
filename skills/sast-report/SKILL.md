---
name: sast-report
description: Turn a finished sast-assess run into reporting for a public-sector department, without changing any verdict. Use to write owner-ready finding reports, validation requests, an executive summary, SARIF for code-scanning tools, Jira or ServiceNow import files, and one delivery pack per owning team. Every sentence stays within the evidence register's claims.
---

# SAST reporting

Convert verified records into artefacts that engineers, owners and senior readers can use
without returning to the model. This skill discovers nothing and decides nothing: verdicts,
severities, blockers and claims come from the run's records, and the prose follows them.

Run control from `sast-assess` applies: read `../sast-assess/references/run-control.md`,
then `../sast-assess/references/evidence-model.md`.

## Before starting

The output directory must hold a completed `sast-assess` run: `findings.json`,
`register.json`, `run-record.json`, `coverage-ledger.json` and Cloudflare's `REPORT.md`. All
three validators must pass:

```sh
node <sast-assess-dir>/cloudflare/validate-findings.cjs <output-dir>/findings.json
node <sast-assess-dir>/cloudflare/validate-coverage-ledger.cjs <output-dir>/coverage-ledger.json
node <sast-assess-dir>/scripts/validate-register.mjs <output-dir>
```

If any fails, stop and hand back to `sast-assess`. If the run is incomplete, every artefact
says so in its first lines.

## Rules

- Do not add, merge, upgrade or downgrade a record. If a record looks wrong, write a reviewer
  note in `report/RECONCILIATION.md` and leave the record alone.
- Every statement about a record comes from its fields or its claims. Nothing is stronger
  than `safe_to_say`. Use `not_safe_to_say` as a list of things the text must not imply.
- Severity appears only for `confirmed` records, copied from `findings.json`.
- Keep source excerpts to the lines that carry the evidence. No secrets, personal data,
  commit author details or host paths.
- Live checks appear only as the validation actions already in the register, never as new
  test steps or payloads.
- Fill templates completely. A leftover `{{` marker fails QA.

## Outputs

Write under `<output-dir>/report/`. File names use the fingerprint with every character
outside `A-Z a-z 0-9 . _ -` replaced by `-`.

| File | From | For |
|---|---|---|
| `findings/<slug>.md` | [templates/finding-report.md](templates/finding-report.md) | Each `promoted-finding` at or above the scope's `severity_threshold`. Lower ones appear in the summary table only. |
| `validation/<slug>.md` | [templates/validation-request.md](templates/validation-request.md) | Each `validation-candidate`. |
| `EXECUTIVE-SUMMARY.md` | [templates/executive-summary.md](templates/executive-summary.md) | Senior readers. |
| `findings.sarif` | `node <skill-dir>/scripts/to-sarif.mjs <output-dir>` | Code-scanning tools. |
| `tickets-jira.csv`, `tickets-servicenow.csv` | `node <skill-dir>/scripts/to-tickets.mjs <output-dir>` | Work-item import. |
| `packs/<routing-id>/` | see below | One owning team each. |
| `RECONCILIATION.md` | see below | Traceability. |

### Owner packs

For each routing id among the register's `promoted-finding` and `validation-candidate`
entries, make `report/packs/<routing-id>/` holding:

- `README.md`: who the pack is for, whether ownership still needs confirming, what is asked
  of them and by when, and how to report back;
- copies of that owner's `findings/` and `validation/` files;
- their tickets: `node <skill-dir>/scripts/to-tickets.mjs <output-dir> --routing-id <id> --out-dir <pack-dir>`;
- `report-back.md` from [templates/report-back.md](templates/report-back.md);
- `SHA256SUMS`, written last, covering every other file in the pack:
  `(cd <pack-dir> && find . -type f ! -name SHA256SUMS | sort | xargs shasum -a 256 > SHA256SUMS)`.

A chain whose links have different owners goes in each owner's pack, with a note naming the
other owners.

### Reconciliation

`RECONCILIATION.md` lists every register entry and chain with the artefacts produced for it,
or the reason none was: below the severity threshold, rejected, or awaiting validation. It
ends with the counts below, which must agree:

- register entries, by lifecycle;
- `findings/` and `validation/` files;
- SARIF results (confirmed plus needs validation);
- ticket rows;
- owner packs, and the entries they cover.

## Next

Run `sast-qa` on `<output-dir>` before anything is shared outside the assessment team.

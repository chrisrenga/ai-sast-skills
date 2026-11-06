# Evidence model

One question runs through every record: what has actually been observed, and what is
still an assumption? This file fixes the words used to answer it, so that a reader can
tell a demonstrated defect from a plausible one without reading the trace.

## Verdicts

Every candidate that survives hunting ends in exactly one verdict in `findings.json`. The
verdicts and their record shapes are Cloudflare's (`cloudflare/report-schema.json`):

| Verdict | Bar |
|---|---|
| `confirmed` | A complete source trace from a lower-trust entry point to the sink, no source-visible control that prevents it, and an observed result from a bounded local check in an approved sandbox, reproduced by a fresh verifier. Preferably a regression test that fails on the untouched source. |
| `needs_validation` | A source-grounded hypothesis that a specific, named fact blocks: a deployment setting, identity-provider behaviour, private code, or execution not being approved. It has no severity. It carries an exact check that would settle it. |
| `rejected` | Disproved by source, by a local check, by a visible control, by a missing meaningful impact, or by an impossible prerequisite. Kept so later runs do not repeat the claim. |

A model's reading of the source, however careful, does not reach `confirmed` on its own.
Nor does agreement between two agents running the same model: the run record shows when
that happened.

Only `confirmed` records carry severity, scored as likelihood, impact and overall
severity using the anchors in `cloudflare/METHOD.md`. Overall severity never exceeds the
demonstrated impact. Potential impact never raises confidence.

## Register labels

`register.json` describes each record in the vocabulary many departmental reporting
processes already use. The labels follow from the verdict; `validate-register.mjs`
enforces the combinations below.

| Verdict | Lifecycle | Source | Runtime | Exploitability | Disclosure classification |
|---|---|---|---|---|---|
| `confirmed` | `promoted-finding` | `SAST-confirmed` | `locally-validated` or `deployed-validated` | `confirmed`, `hypothesis`, `config-dependent` or `private-dependent` | same as runtime |
| `needs_validation` | `validation-candidate` | `SAST-confirmed`, `SAST-likely` or `SAST-suspected` | `not-validated` | `hypothesis`, `config-dependent` or `private-dependent` | `validation-candidate` |
| `rejected` | `disconfirmed` | any | any | `disconfirmed` | `disconfirmed` |

Label meanings:

- **Source.** `SAST-confirmed`: source shows the whole path. `SAST-likely`: one step rests
  on a framework convention or code not read. `SAST-suspected`: a pattern needing deeper
  review. `source-disconfirmed`: source shows a control that breaks it.
- **Runtime.** `locally-validated`: reproduced in the sandbox with dummy data.
  `deployed-validated`: an owner observed it in an authorised environment and reported back.
  `not-validated`: nothing has run. `not-applicable`: running would not change the claim.
- **Reachability.** `source-visible`, `config-dependent`, `runtime-dependent`,
  `private-dependent` or `not-established`.
- **Exploitability.** `confirmed` only when the observed result closes every
  load-bearing assumption, including deployment ones. A local test of a library function
  can do that; a local test of a web route usually cannot, because the route's exposure is
  a deployment fact.

`locally-validated` never means the deployed service is affected. `deployed-validated`
needs a validation action whose recorded result is `vulnerable`.

Other outcomes are not records in `findings.json`. Duplicates are merged by fingerprint
before validation. Hardening observations, out-of-scope items and repository directives go
in the register's `notes`.

## Claims

Every `promoted-finding` and `validation-candidate` carries claims that every later
artefact must stay within:

- `safe_to_say`: statements the evidence directly supports.
- `not_safe_to_say`: the overstatements a reader is most likely to make.
- `safe_if_validated`: statements that become true if a named validation action comes back
  `vulnerable`.

`production_impact` is `confirmed` only with `deployed-validated` runtime evidence.
Otherwise it is `not-established` (or `not-applicable`).

Wording that fits unvalidated or locally validated evidence:

- "source evidence shows", "the local test showed", "could allow, if the stated conditions
  hold", "not established from current evidence", "would need the owner to check".

Wording to avoid unless deployed evidence supports it:

- "confirmed exploitable", "attacker can", "will allow", "production is vulnerable",
  "live issue", "has been exploited", "demonstrated" (for anything not `confirmed`).

For an unvalidated chain:

> The source-level defect is confirmed. End-to-end exploitability remains a hypothesis
> until `<validation action>` is completed.

## Chains

A chain links findings, and explicit assumptions, into an attacker path that no single
record shows.

- A chain cites at least one fingerprint. Assumptions are listed, never hidden in prose.
- A chain is never stronger than its weakest link. It is `validated-chain` only when every
  linked record is `confirmed` and no assumption remains open; otherwise it is
  `plausible-chain`.
- A chain never cites a `rejected` record.
- Findings describe defects. Chains describe paths. One object is never both.

## Missing facts

Write "Not established from current evidence." Never fill a gap with a likely value.

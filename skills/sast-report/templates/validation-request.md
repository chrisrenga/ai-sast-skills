# Please check: {{title}}

| | |
|---|---|
| Fingerprint | `{{fingerprint}}` |
| Assessment | {{assessment_id}}, {{run_id}} |
| Repository | {{repository}} at `{{source_ref}}` |
| Sent to | {{owner, or routing id and "please confirm you own this"}} |

**Status: needs validation.** This is not a confirmed vulnerability and it has no severity.
The source shows a possible problem, but one fact that decides it is outside what we could
see. We are asking you to check that fact.

## What the source shows

{{disclosure.safe_to_say}}

| Step | Location | What happens |
|---|---|---|
| {{trace[n].kind}} | `{{trace[n].file}}:{{trace[n].line}}` | {{trace[n].description}} |

## What we could not establish

{{blockers}}

## What we are asking you to check

| Action | What to check | Evidence we need | Live access needed |
|---|---|---|---|
| {{validation_actions[n].id}} | {{action}} | {{evidence_required}} | {{live_access_required}} |

Use a non-production environment and test accounts wherever the check allows it.

## What your answer means

| Result | What happens next |
|---|---|
| `vulnerable` | {{disclosure.safe_if_validated}} We will raise it as a finding with a severity and a fix. |
| `not-vulnerable` | We close it as rejected and record your reason, so later runs do not raise it again. |
| `inconclusive` | It stays open. Tell us what stopped the check. |

## Please do not repeat

The evidence does not support these statements yet: {{disclosure.not_safe_to_say}}

## Reporting back

Fill in `report-back.md` in this pack and return it through {{the department's reporting route}}.

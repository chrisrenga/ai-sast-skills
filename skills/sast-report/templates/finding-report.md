# {{title}}

| | |
|---|---|
| Fingerprint | `{{fingerprint}}` |
| Assessment | {{assessment_id}}, {{run_id}} |
| Repository | {{repository}} at `{{source_ref}}` |
| Owner | {{owner, or routing id and "owner not confirmed"}} |
| Human review | {{human_review.status}}{{, reviewer and date}} |

## Decision snapshot

- **Established:** {{disclosure.safe_to_say}}
- **Not established:** {{reachability_proof.unvalidated_conditions}}
- **Severity:** {{severity.overall_severity}} (likelihood {{severity.likelihood.score}}, impact {{severity.impact.score}})
- **Action now:** {{first remediation action}}
- **What would change this:** {{disclosure.safe_if_validated}}

## Summary

{{Plain English, no labels doing the work: what the defect is, who could reach it and how,
what they could achieve if the unvalidated conditions hold, what the local test showed, and
what still needs checking. Stay within the claims below.}}

## Evidence status

| Field | Value |
|---|---|
| Source | `{{labels.source}}` |
| Runtime | `{{labels.runtime}}` |
| Reachability | `{{labels.reachability}}` |
| Exploitability | `{{labels.exploitability}}` |
| Disclosure classification | `{{disclosure.classification}}` |
| Production impact | `{{disclosure.production_impact}}` |
| Confidence | {{confidence.score}}: {{confidence.reason}} |

## Claims

| | |
|---|---|
| Safe to say now | {{disclosure.safe_to_say}} |
| Not safe to say | {{disclosure.not_safe_to_say}} |
| Safe only if validated | {{disclosure.safe_if_validated}} |

## Where it is

| Step | Location | Scope | What happens |
|---|---|---|---|
| {{trace[n].kind}} | `{{trace[n].file}}:{{trace[n].line}}` | {{trace[n].scope}} | {{trace[n].description}} |

Supporting evidence: {{evidence, as file:line and description}}

{{If endpoint_authorisation is set:}}

| Route | Authentication | Endpoint authorisation | Object or tenant scope | CSRF or session | Feature flag | Backend privilege | Gap |
|---|---|---|---|---|---|---|---|
| {{route}} {{methods}} | {{authentication}} | {{endpoint_authorisation}} | {{object_scope}} | {{csrf_or_session}} | {{feature_flag}} | {{backend_privilege}} | {{gap}} |

## How it was shown

This was reproduced in an isolated sandbox with dummy data. Do not repeat it against a live
service; use the validation actions below instead.

- **Perspective:** {{execution.attacker_perspective}}
- **Input:** {{execution.payloads}}
- **Steps:** {{execution.instructions}}
- **Observed result:** {{execution.observed_result}}

Conditions: {{conditions, as kind and description}}

## Fix

{{remediation.strategy}}

| Action | What to change | Done when |
|---|---|---|
| {{remediation_actions[n].id}} | {{remediation_actions[n].action}} | {{remediation_actions[n].acceptance}} |

## Validation still needed

| Action | Who | What to check | Evidence needed | Live access needed |
|---|---|---|---|---|
| {{validation_actions[n].id}} | {{owner_type}} | {{action}} | {{evidence_required}} | {{live_access_required}} |

## How this was produced

An AI agent drafted this report from records that passed independent verification and the
pack's validators. It is not final until the human review above says `accepted`.

| | |
|---|---|
| Models | {{stage: model and version, one per stage}} |
| Same model hunted and verified | {{same_model_verification}} |
| Skill pack | {{skill_pack_version}}, Cloudflare method `{{cloudflare_method_commit}}` |
| Run status | {{run_status}} |

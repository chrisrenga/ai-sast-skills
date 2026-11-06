# Security assessment: {{repository}}

{{If the run is incomplete, say so here first, with the reason and what was not covered.}}

| | |
|---|---|
| Assessment | {{assessment_id}}, {{run_id}} |
| Source | {{repository}} at `{{source_ref}}` |
| Profile and scope | {{profile}}, {{scope_paths or "whole repository"}} |
| Human review | {{who reviewed this summary, and when}} |

## Decision snapshot

- **Confirmed findings:** {{count}} ({{count by severity}}). Each was reproduced with dummy
  data in an isolated sandbox. None has been shown in a deployed service unless the table says
  so.
- **Needs validation:** {{count}}. Each needs one fact checked by its owner. They have no
  severity yet.
- **Rejected:** {{count}} candidates were disproved and are recorded so they are not raised
  again.
- **Action now:** {{the one or two actions that matter most}}

## Confirmed findings

| Severity | Finding | Owner | What we can say |
|---|---|---|---|
| {{overall_severity}} | {{title}} | {{owner or routing id}} | {{safe_to_say}} |

## Needing validation

| Finding | Owner | What needs checking |
|---|---|---|
| {{title}} | {{owner or routing id}} | {{validation action}} |

## Coverage and limits

- Coverage units: {{covered}} covered, {{candidate}} with candidates, {{blocked}} blocked,
  {{deferred}} deferred, {{out_of_scope}} out of scope.
- Not covered: {{deferred and out-of-scope areas, scan copy coverage notes, scanner leads not
  reviewed}}.
- One run does not find everything. {{Prior runs used, or "No earlier run of this repository
  was available."}}

## What this summary does not say

{{The strongest not_safe_to_say statements across the findings, for example that no
production impact has been established.}}

## How it was produced

AI agents assessed a sanitised copy of the source under the department's run control. A
fresh agent tried to disprove every candidate. {{If same_model_verification is true: "The same
model found and verified some records, so that verification was not fully independent."}}
Models: {{models by stage}}. Skill pack {{skill_pack_version}}.

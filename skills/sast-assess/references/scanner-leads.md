# Scanner leads (optional)

A cheap deterministic pass can point hunters at code worth reading, especially in
languages where the model's own search is weakest. Its output is a list of leads. A lead
is never a finding, and a scanner's dataflow is never a trace.

## When

Only if the run scope allows a scanner pass and names the tools. Run before
reconnaissance.

## How

- Run each tool inside the sandbox against the scan copy, with network access off and
  rules already present locally. Do not let a tool fetch rules or upload results.
- Useful classes of tool: a taint or pattern scanner for the main language (for example
  Semgrep, CodeQL, or Psalm for PHP), a secret scanner (gitleaks), and a dependency and
  infrastructure-as-code scanner (for example Trivy or OSV-Scanner).
- Keep the raw tool output in the output directory. Pass only lead records to agents.
- Group repeats of one rule in one file into one lead.

## scanner-leads.json

```json
[
  {
    "lead_id": "L001",
    "tool": "semgrep",
    "tool_version": "1.x",
    "rule_id": "php.lang.security.injection.tainted-sql-string",
    "file": "app/Reports/Export.php",
    "line": 57,
    "class": "SQL injection",
    "disposition": "candidate",
    "fingerprint": "sqli/report-export/order-by",
    "reason": null
  }
]
```

`disposition` is one of:

| Value | Meaning |
|---|---|
| `candidate` | Hunting turned it into a candidate. `fingerprint` names its record in `findings.json`, whatever the verdict. |
| `rejected` | Read and dismissed. `reason` says why, for example "value is cast to int at line 50". |
| `duplicate` | Same root cause as another lead. `reason` names it. |
| `not-reviewed` | Not read within the budget. `reason` says so. It appears in the coverage statement as a gap. |

Every lead has a disposition before reporting. `validate-register.mjs` checks this.

## Where leads go

Reconnaissance agent 1c receives the lead list as extra starting paths. Hunters receive the
leads inside their assigned units as places to start reading, never as candidates to
confirm.

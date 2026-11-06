#!/usr/bin/env node
// Convert findings.json and register.json into SARIF 2.1.0 for code-scanning tools.
// Confirmed records become results of kind "fail" with a level from their severity.
// needs_validation records become kind "review" with level "none", as SARIF requires for
// results that are not failures. Rejected records are left out.
//
// Usage: node to-sarif.mjs <output-dir> [--out <file>]
// Default output: <output-dir>/report/findings.sarif

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const LEVEL = { critical: "error", high: "error", medium: "warning", low: "note", informational: "note" };
// GitHub code scanning reads this property to rank security results.
const SECURITY_SEVERITY = { critical: "9.5", high: "8.0", medium: "5.5", low: "3.0", informational: "0.0" };

const location = (step) => ({
  physicalLocation: { artifactLocation: { uri: step.file }, region: { startLine: step.line } },
});

export function toSarif({ findings, register, runRecord }) {
  const entries = new Map(register.entries.map((e) => [e.fingerprint, e]));
  const rules = [];
  const results = [];

  for (const finding of findings) {
    if (finding.verdict === "rejected") continue;
    const entry = entries.get(finding.fingerprint) ?? {};
    const confirmed = finding.verdict === "confirmed";
    const severity = confirmed ? finding.severity.overall_severity : null;
    const sink = finding.trace[finding.trace.length - 1];
    const disclosure = entry.disclosure ?? {};

    rules.push({
      id: finding.fingerprint,
      shortDescription: { text: finding.title },
      fullDescription: { text: finding.description },
      properties: {
        tags: ["security", confirmed ? "confirmed" : "needs-validation"],
        ...(confirmed ? { "security-severity": SECURITY_SEVERITY[severity] } : {}),
      },
    });

    const message = confirmed
      ? `${finding.title}. ${(disclosure.safe_to_say ?? []).join(" ")}`
      : `${finding.title}. Needs validation: ${finding.blockers.join(" ")}`;

    results.push({
      ruleId: finding.fingerprint,
      ruleIndex: rules.length - 1,
      kind: confirmed ? "fail" : "review",
      level: confirmed ? LEVEL[severity] : "none",
      message: { text: message.trim() },
      locations: [location(sink)],
      ...(finding.trace.length > 1
        ? {
            codeFlows: [{
              threadFlows: [{
                locations: finding.trace.map((step) => ({ location: { ...location(step), message: { text: step.description } } })),
              }],
            }],
          }
        : {}),
      fingerprints: { "ai-sast/v1": finding.fingerprint },
      properties: {
        verdict: finding.verdict,
        overall_severity: severity,
        disclosure_classification: disclosure.classification ?? null,
        production_impact: disclosure.production_impact ?? null,
        safe_to_say: disclosure.safe_to_say ?? [],
        not_safe_to_say: disclosure.not_safe_to_say ?? [],
        routing_id: entry.routing?.routing_id ?? null,
        owner: entry.routing?.owner ?? null,
        remediation_action_ids: (entry.remediation_actions ?? []).map((a) => a.id),
        validation_action_ids: (entry.validation_actions ?? []).map((a) => a.id),
        human_review: entry.human_review?.status ?? null,
      },
    });
  }

  const target = runRecord.target ?? {};
  return {
    $schema: "https://json.schemastore.org/sarif-2.1.0.json",
    version: "2.1.0",
    runs: [{
      tool: { driver: { name: "ai-sast-skills", version: runRecord.tools?.skill_pack_version ?? "unknown", rules } },
      automationDetails: { id: `${runRecord.scope?.assessment_id ?? "assessment"}/${runRecord.run_id}` },
      ...(target.repository_url ? { versionControlProvenance: [{ repositoryUri: target.repository_url, revisionId: target.source_ref }] } : {}),
      properties: {
        repository: target.repository ?? null,
        source_ref: target.source_ref ?? null,
        run_status: runRecord.run_status ?? null,
        same_model_verification: runRecord.same_model_verification ?? null,
      },
      results,
    }],
  };
}

function main() {
  const args = process.argv.slice(2);
  const dir = args[0];
  if (!dir) {
    console.error("usage: node to-sarif.mjs <output-dir> [--out <file>]");
    process.exit(1);
  }
  const outIndex = args.indexOf("--out");
  const out = outIndex > -1 ? args[outIndex + 1] : path.join(dir, "report", "findings.sarif");
  const read = (name) => JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
  const sarif = toSarif({ findings: read("findings.json"), register: read("register.json"), runRecord: read("run-record.json") });
  fs.mkdirSync(path.dirname(out), { recursive: true });
  fs.writeFileSync(out, JSON.stringify(sarif, null, 2) + "\n");
  console.log(`Wrote ${sarif.runs[0].results.length} result(s) to ${out}`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) main();

#!/usr/bin/env node
// Write Jira and ServiceNow import files from findings.json and register.json: one row per
// promoted-finding or validation-candidate. Ticket text comes only from the records and
// their claims, so a ticket never says more than the register allows.
//
// Usage: node to-tickets.mjs <output-dir> [--routing-id <id>] [--out-dir <dir>]
// Default output directory: <output-dir>/report

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";

const JIRA_PRIORITY = { critical: "Highest", high: "High", medium: "Medium", low: "Low", informational: "Lowest" };
// ServiceNow impact and urgency: 1 high, 2 medium, 3 low.
const SN_LEVEL = { critical: "1", high: "1", medium: "2", low: "3", informational: "3" };

export const slug = (fingerprint) => fingerprint.replace(/[^A-Za-z0-9._-]+/g, "-");

// Text in a record can come from the repository under review, so a cell that a spreadsheet
// would read as a formula is prefixed with an apostrophe.
function cell(value) {
  let text = value === null || value === undefined ? "" : String(value);
  if (/^[=+\-@\t\r]/.test(text)) text = `'${text}`;
  return `"${text.replace(/"/g, '""')}"`;
}

const csv = (header, rows) => [header, ...rows].map((row) => row.map(cell).join(",")).join("\r\n") + "\r\n";

export function toTickets({ findings, register, runRecord }, { routingId = null } = {}) {
  const records = new Map(findings.map((f) => [f.fingerprint, f]));
  const rows = [];

  for (const entry of register.entries) {
    if (!["promoted-finding", "validation-candidate"].includes(entry.lifecycle)) continue;
    if (routingId && entry.routing?.routing_id !== routingId) continue;
    const finding = records.get(entry.fingerprint);
    if (!finding) continue;
    const confirmed = finding.verdict === "confirmed";
    const severity = confirmed ? finding.severity.overall_severity : null;
    const sink = finding.trace[finding.trace.length - 1];
    const folder = confirmed ? "findings" : "validation";

    const lines = [
      `Fingerprint: ${finding.fingerprint}`,
      confirmed
        ? `Status: confirmed by a local test (${entry.labels.runtime}); severity ${severity}`
        : "Status: needs validation; no severity until validated",
      `What the evidence supports: ${entry.disclosure.safe_to_say.join(" ")}`,
      `Do not say: ${entry.disclosure.not_safe_to_say.join(" ")}`,
      `Location: ${sink.file}:${sink.line}`,
    ];
    if (confirmed) {
      lines.push(`Fix: ${finding.remediation.strategy}`);
      for (const a of entry.remediation_actions) lines.push(`${a.id}: ${a.action} Done when: ${a.acceptance}`);
    } else {
      lines.push(`Blocked by: ${finding.blockers.join(" ")}`);
    }
    for (const a of entry.validation_actions) lines.push(`${a.id}: ${a.action} Evidence needed: ${a.evidence_required}`);
    if (entry.routing?.owner_confirmation_required) lines.push(`Owner not confirmed (${entry.routing.routing_id}): please confirm or reassign.`);
    lines.push(`Report: report/${folder}/${slug(finding.fingerprint)}.md`);
    lines.push(`Assessment: ${runRecord.scope?.assessment_id ?? ""} ${runRecord.run_id}`.trim());

    rows.push({
      fingerprint: finding.fingerprint,
      summary: confirmed ? `[${severity}] ${finding.title}` : `[needs validation] ${finding.title}`,
      description: lines.join("\n"),
      confirmed,
      severity,
      likelihood: confirmed ? finding.severity.likelihood.score : null,
      routingId: entry.routing?.routing_id ?? "",
      owner: entry.routing?.owner ?? "",
    });
  }

  const jira = csv(
    ["Summary", "Description", "Issue Type", "Priority", "Labels", "Labels", "Labels"],
    rows.map((r) => [
      r.summary, r.description, r.confirmed ? "Bug" : "Task", r.confirmed ? JIRA_PRIORITY[r.severity] : "",
      "ai-sast", r.confirmed ? "confirmed" : "needs-validation", r.routingId ? `routing-${r.routingId}` : "",
    ]),
  );
  const servicenow = csv(
    ["short_description", "description", "impact", "urgency", "assignment_group", "correlation_id"],
    rows.map((r) => [
      r.summary, r.description, r.confirmed ? SN_LEVEL[r.severity] : "", r.confirmed ? SN_LEVEL[r.likelihood] : "", r.owner, r.fingerprint,
    ]),
  );
  return { jira, servicenow, count: rows.length };
}

function main() {
  const args = process.argv.slice(2);
  const dir = args[0];
  if (!dir) {
    console.error("usage: node to-tickets.mjs <output-dir> [--routing-id <id>] [--out-dir <dir>]");
    process.exit(1);
  }
  const option = (name) => (args.includes(name) ? args[args.indexOf(name) + 1] : null);
  const outDir = option("--out-dir") ?? path.join(dir, "report");
  const read = (name) => JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
  const tickets = toTickets(
    { findings: read("findings.json"), register: read("register.json"), runRecord: read("run-record.json") },
    { routingId: option("--routing-id") },
  );
  fs.mkdirSync(outDir, { recursive: true });
  fs.writeFileSync(path.join(outDir, "tickets-jira.csv"), tickets.jira);
  fs.writeFileSync(path.join(outDir, "tickets-servicenow.csv"), tickets.servicenow);
  console.log(`Wrote ${tickets.count} ticket(s) to ${path.join(outDir, "tickets-jira.csv")} and tickets-servicenow.csv`);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) main();

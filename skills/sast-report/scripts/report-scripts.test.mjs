import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { toSarif } from "./to-sarif.mjs";
import { toTickets, slug } from "./to-tickets.mjs";

const sample = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "sast-assess", "examples", "sample-run");
const read = (name) => JSON.parse(fs.readFileSync(path.join(sample, name), "utf8"));
const input = () => ({ findings: read("findings.json"), register: read("register.json"), runRecord: read("run-record.json") });

test("SARIF has confirmed and needs-validation results and leaves rejected out", () => {
  const sarif = toSarif(input());
  const results = sarif.runs[0].results;
  assert.equal(sarif.version, "2.1.0");
  assert.deepEqual(results.map((r) => r.ruleId).sort(), [
    "authz/admin-export/network-only-guard",
    "authz/invoice-download/missing-owner-check",
  ]);
  const confirmed = results.find((r) => r.ruleId.startsWith("authz/invoice"));
  assert.equal(confirmed.kind, "fail");
  assert.equal(confirmed.level, "error");
  assert.deepEqual(confirmed.locations[0].physicalLocation, { artifactLocation: { uri: "src/routes/invoices.ts" }, region: { startLine: 47 } });
  assert.equal(confirmed.codeFlows[0].threadFlows[0].locations.length, 3);
  assert.equal(sarif.runs[0].tool.driver.rules[confirmed.ruleIndex].properties["security-severity"], "8.0");

  const review = results.find((r) => r.ruleId.startsWith("authz/admin"));
  assert.equal(review.kind, "review");
  assert.equal(review.level, "none");
  assert.equal(review.properties.overall_severity, null);
  assert.match(review.message.text, /Needs validation: Whether the deployed load balancer/);
});

test("SARIF adds version control provenance only when a repository URL is recorded", () => {
  const i = input();
  assert.equal(toSarif(i).runs[0].versionControlProvenance, undefined);
  i.runRecord.target.repository_url = "https://git.example.org/team/example-service";
  assert.deepEqual(toSarif(i).runs[0].versionControlProvenance, [
    { repositoryUri: "https://git.example.org/team/example-service", revisionId: i.runRecord.target.source_ref },
  ]);
});

test("tickets carry claims, not stronger wording, and leave unvalidated priority blank", () => {
  const { jira, servicenow, count } = toTickets(input());
  assert.equal(count, 2);
  const jiraLines = jira.split("\r\n");
  assert.equal(jiraLines[0], '"Summary","Description","Issue Type","Priority","Labels","Labels","Labels"');
  assert.match(jira, /"\[high\] Invoice download returns invoices belonging to other users"/);
  assert.match(jira, /What the evidence supports: Source evidence shows the invoice download route/);
  assert.match(jira, /Do not say: The live service is exposing invoices/);
  assert.match(jira, /"Task",""/);
  assert.match(servicenow, /"authz\/invoice-download\/missing-owner-check"/);
  assert.match(servicenow, /"1","1","",/);
});

test("tickets can be cut for one owner", () => {
  const { count, jira } = toTickets(input(), { routingId: "RC002" });
  assert.equal(count, 1);
  assert.match(jira, /routing-RC002/);
  assert.doesNotMatch(jira, /routing-RC001/);
});

test("cells that a spreadsheet would run as formulas are neutralised", () => {
  const i = input();
  i.findings.find((f) => f.verdict === "needs_validation").title = '=HYPERLINK("http://x","y")';
  const { jira } = toTickets(i);
  assert.match(jira, /"\[needs validation\] =HYPERLINK/);
  i.register.entries.find((e) => e.lifecycle === "validation-candidate").routing.owner = "@team";
  assert.match(toTickets(i).servicenow, /"'@team"/);
});

test("slugs are safe file names", () => {
  assert.equal(slug("authz/invoice-download/missing-owner-check"), "authz-invoice-download-missing-owner-check");
  assert.equal(slug("a:b@c+d"), "a-b-c-d");
});

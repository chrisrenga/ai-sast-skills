import assert from "node:assert/strict";
import crypto from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { checkPack, countCsvRecords } from "./check-pack.mjs";
import { toSarif } from "../../sast-report/scripts/to-sarif.mjs";
import { toTickets } from "../../sast-report/scripts/to-tickets.mjs";

const sample = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "..", "sast-assess", "examples", "sample-run");

// A complete, correct pack built from the sample run.
function buildPack() {
  const dir = fs.mkdtempSync(path.join(os.tmpdir(), "check-pack-"));
  for (const name of ["findings.json", "register.json", "run-record.json"]) fs.copyFileSync(path.join(sample, name), path.join(dir, name));
  const read = (name) => JSON.parse(fs.readFileSync(path.join(dir, name), "utf8"));
  const input = { findings: read("findings.json"), register: read("register.json"), runRecord: read("run-record.json") };
  const report = path.join(dir, "report");
  const write = (rel, text) => { fs.mkdirSync(path.dirname(path.join(report, rel)), { recursive: true }); fs.writeFileSync(path.join(report, rel), text); };

  write("findings/authz-invoice-download-missing-owner-check.md", "# Invoice download returns invoices belonging to other users\n");
  write("validation/authz-admin-export-network-only-guard.md", "# Please check: admin export\n");
  write("EXECUTIVE-SUMMARY.md", "# Security assessment: example-service\n");
  write("RECONCILIATION.md", "# Reconciliation\n");
  write("findings.sarif", JSON.stringify(toSarif(input)));
  const all = toTickets(input);
  write("tickets-jira.csv", all.jira);
  write("tickets-servicenow.csv", all.servicenow);
  for (const id of ["RC001", "RC002"]) {
    const tickets = toTickets(input, { routingId: id });
    write(`packs/${id}/README.md`, `# Pack for ${id}\n`);
    write(`packs/${id}/tickets-jira.csv`, tickets.jira);
    sealPack(path.join(report, "packs", id));
  }
  return dir;
}

function sealPack(packDir) {
  const lines = fs.readdirSync(packDir).filter((f) => f !== "SHA256SUMS").sort()
    .map((f) => `${crypto.createHash("sha256").update(fs.readFileSync(path.join(packDir, f))).digest("hex")}  ./${f}`);
  fs.writeFileSync(path.join(packDir, "SHA256SUMS"), lines.join("\n") + "\n");
}

test("a complete pack passes", () => {
  const { errors, warnings } = checkPack(buildPack());
  assert.deepEqual(errors, []);
  assert.deepEqual(warnings, []);
});

test("secrets and unfilled templates are errors", () => {
  const dir = buildPack();
  fs.appendFileSync(path.join(dir, "report", "EXECUTIVE-SUMMARY.md"), `Key: ${"-----BEGIN "}${"PRIVATE KEY-----"}\nOwner: {{owner}}\n`);
  const { errors } = checkPack(dir);
  assert.ok(errors.some((e) => e.includes("EXECUTIVE-SUMMARY.md:2: looks like a secret (private key block)")));
  assert.ok(errors.some((e) => e.includes("EXECUTIVE-SUMMARY.md:3: unfilled template marker")));
});

test("strong wording and personal data are warnings", () => {
  const dir = buildPack();
  fs.appendFileSync(path.join(dir, "report", "EXECUTIVE-SUMMARY.md"), "An attacker can read invoices. Contact jo.bloggs@department.gov.uk\n");
  const { errors, warnings } = checkPack(dir);
  assert.deepEqual(errors, []);
  assert.ok(warnings.some((w) => w.includes('strong wording ("attacker can")')));
  assert.ok(warnings.some((w) => w.includes("personal data (email address)")));
});

test("a changed or unlisted pack file fails its checksum", () => {
  const dir = buildPack();
  const pack = path.join(dir, "report", "packs", "RC001");
  fs.appendFileSync(path.join(pack, "README.md"), "edited after sealing\n");
  fs.writeFileSync(path.join(pack, "extra.md"), "not sealed\n");
  const { errors } = checkPack(dir);
  assert.ok(errors.some((e) => e.includes("RC001: README.md does not match its checksum")));
  assert.ok(errors.some((e) => e.includes("RC001: extra.md is not in SHA256SUMS")));
});

test("counts must agree with the register", () => {
  const dir = buildPack();
  fs.rmSync(path.join(dir, "report", "validation"), { recursive: true });
  fs.rmSync(path.join(dir, "report", "packs", "RC002"), { recursive: true });
  const { errors } = checkPack(dir);
  assert.ok(errors.some((e) => e.includes("report/validation/*.md is 0, register implies 1")));
  assert.ok(errors.some((e) => e.includes("report/packs/RC002 is missing")));
});

test("findings below the severity threshold need no full report", () => {
  const dir = buildPack();
  const runRecord = JSON.parse(fs.readFileSync(path.join(dir, "run-record.json"), "utf8"));
  runRecord.scope.severity_threshold = "critical";
  fs.writeFileSync(path.join(dir, "run-record.json"), JSON.stringify(runRecord));
  const { errors } = checkPack(dir);
  assert.ok(errors.some((e) => e.includes("report/findings/*.md is 1, register implies 0")));
});

test("CSV records are counted across quoted line breaks", () => {
  assert.equal(countCsvRecords('"a","b"\r\n"1","two\nlines"\r\n"3","4"\r\n'), 3);
  assert.equal(countCsvRecords('"a"'), 1);
  assert.equal(countCsvRecords(""), 0);
});

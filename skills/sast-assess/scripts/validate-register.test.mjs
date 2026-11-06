import assert from "node:assert/strict";
import fs from "node:fs";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import { validate } from "./validate-register.mjs";

const sample = path.join(path.dirname(fileURLToPath(import.meta.url)), "..", "examples", "sample-run");
const read = (name) => JSON.parse(fs.readFileSync(path.join(sample, name), "utf8"));

function input() {
  return {
    findings: read("findings.json"),
    register: read("register.json"),
    runRecord: read("run-record.json"),
    scannerLeads: read("scanner-leads.json"),
  };
}

const entry = (i, fingerprint) => i.register.entries.find((e) => e.fingerprint === fingerprint);
const INVOICE = "authz/invoice-download/missing-owner-check";
const EXPORT = "authz/admin-export/network-only-guard";
const SQLI = "sqli/report-export/order-by";

function expectError(i, fragment) {
  const { errors } = validate(i);
  assert.ok(errors.some((e) => e.includes(fragment)), `expected an error containing "${fragment}", got:\n${errors.join("\n")}`);
}

test("the sample run is valid", () => {
  const { errors, warnings } = validate(input());
  assert.deepEqual(errors, []);
  assert.deepEqual(warnings, []);
});

test("every findings.json record needs exactly one entry", () => {
  const missing = input();
  missing.register.entries = missing.register.entries.filter((e) => e.fingerprint !== SQLI);
  expectError(missing, `no entry for findings.json record ${SQLI}`);

  const extra = input();
  extra.register.entries.push({ ...structuredClone(entry(extra, SQLI)), fingerprint: "xss/not-a-record" });
  expectError(extra, "fingerprint is not in findings.json");

  const duplicate = input();
  duplicate.register.entries.push(structuredClone(entry(duplicate, SQLI)));
  expectError(duplicate, "duplicate fingerprint");
});

test("lifecycle and labels follow the verdict", () => {
  const i = input();
  entry(i, INVOICE).lifecycle = "validation-candidate";
  expectError(i, 'lifecycle must be "promoted-finding"');

  const notObserved = input();
  entry(notObserved, INVOICE).labels.runtime = "not-validated";
  expectError(notObserved, "a confirmed record needs an observed result");

  const ran = input();
  entry(ran, EXPORT).labels.runtime = "locally-validated";
  expectError(ran, "a needs_validation record has labels.runtime not-validated");

  const rejected = input();
  entry(rejected, SQLI).labels.exploitability = "hypothesis";
  expectError(rejected, "a rejected record has labels.exploitability disconfirmed");
});

test("disclosure cannot claim more than the evidence", () => {
  const classification = input();
  entry(classification, EXPORT).disclosure.classification = "locally-validated";
  expectError(classification, 'disclosure.classification must be "validation-candidate"');

  const production = input();
  entry(production, INVOICE).disclosure.production_impact = "confirmed";
  expectError(production, "production_impact confirmed needs deployed-validated");

  const deployed = input();
  entry(deployed, INVOICE).labels.runtime = "deployed-validated";
  entry(deployed, INVOICE).disclosure.classification = "deployed-validated";
  expectError(deployed, "deployed-validated needs a validation action with result vulnerable");
  entry(deployed, INVOICE).validation_actions[0].result = "vulnerable";
  assert.deepEqual(validate(deployed).errors, []);
});

test("claims are required and checked for overstatement", () => {
  const empty = input();
  entry(empty, EXPORT).disclosure.not_safe_to_say = [];
  expectError(empty, "not_safe_to_say needs at least one statement");

  const overclaim = input();
  entry(overclaim, EXPORT).disclosure.safe_to_say.push("An attacker can export every account.");
  expectError(overclaim, 'overstates an unvalidated record ("attacker can")');

  const deployedClaim = input();
  entry(deployedClaim, INVOICE).disclosure.safe_to_say.push("Production is vulnerable to invoice disclosure.");
  expectError(deployedClaim, "claims deployed impact without deployed evidence");

  const demonstratedLocally = input();
  entry(demonstratedLocally, INVOICE).disclosure.safe_to_say.push("A local test demonstrated the cross-account read.");
  assert.deepEqual(validate(demonstratedLocally).errors, []);
});

test("reachability proof uses the scope's attacker classes", () => {
  const i = input();
  entry(i, INVOICE).reachability_proof.attacker_class = "nation-state";
  expectError(i, 'attacker_class "nation-state" is not one of the run scope');

  const missing = input();
  entry(missing, EXPORT).reachability_proof = null;
  expectError(missing, "reachability_proof is required");
});

test("routing without a confirmed owner asks for confirmation", () => {
  const i = input();
  entry(i, INVOICE).routing.owner_confirmation_required = false;
  expectError(i, "needs owner_confirmation_required true");
});

test("actions have unique ids and the right minimum", () => {
  const noFix = input();
  entry(noFix, INVOICE).remediation_actions = [];
  expectError(noFix, "a promoted-finding needs at least one remediation action");

  const noCheck = input();
  entry(noCheck, EXPORT).validation_actions = [];
  expectError(noCheck, "a validation-candidate needs at least one validation action");

  const clash = input();
  entry(clash, EXPORT).remediation_actions[0].id = "A001";
  expectError(clash, "duplicate action id A001");
});

test("a chain is never stronger than its weakest link", () => {
  const i = input();
  i.register.chains.push({
    id: "C001", title: "Export then download", fingerprints: [EXPORT, INVOICE], assumptions: [], status: "validated-chain", weakest_link: EXPORT,
  });
  entry(i, EXPORT).chain_ids.push("C001");
  entry(i, INVOICE).chain_ids.push("C001");
  expectError(i, `validated-chain needs every link confirmed; ${EXPORT} is needs_validation`);
  i.register.chains[0].status = "plausible-chain";
  assert.deepEqual(validate(i).errors, []);

  const rejected = input();
  rejected.register.chains.push({
    id: "C001", title: "x", fingerprints: [SQLI], assumptions: [], status: "plausible-chain", weakest_link: SQLI,
  });
  entry(rejected, SQLI).chain_ids.push("C001");
  expectError(rejected, `cites rejected record ${SQLI}`);

  const oneWay = input();
  oneWay.register.chains.push({
    id: "C001", title: "x", fingerprints: [INVOICE], assumptions: ["a"], status: "plausible-chain", weakest_link: INVOICE,
  });
  expectError(oneWay, `entry ${INVOICE} does not list C001`);
});

test("the run record is checked", () => {
  const noApprover = input();
  delete noApprover.runRecord.scope.approved_by;
  expectError(noApprover, "scope.approved_by is required");

  const noExecution = input();
  noExecution.runRecord.scope.execution = "none";
  expectError(noExecution, "scope.execution is none, so no record can be confirmed");

  const sameModel = input();
  sameModel.runRecord.stages.find((s) => s.stage === "validate").model = "model-a";
  sameModel.runRecord.stages.find((s) => s.stage === "validate").model_version = "2026-09";
  expectError(sameModel, "same_model_verification must be true");
  sameModel.runRecord.same_model_verification = true;
  assert.deepEqual(validate(sameModel).errors, []);

  const versionDiffers = input();
  versionDiffers.runRecord.stages.find((s) => s.stage === "validate").model = "model-a";
  assert.deepEqual(validate(versionDiffers).errors, []);
});

test("scanner leads all end with a disposition", () => {
  const i = input();
  i.scannerLeads[1].reason = null;
  expectError(i, "a rejected lead states its reason");

  const dangling = input();
  dangling.scannerLeads[0].fingerprint = "nope";
  expectError(dangling, "a candidate lead names a fingerprint in findings.json");
});

test("secrets are errors, personal data and host paths are warnings", () => {
  const secret = input();
  entry(secret, INVOICE).remediation_actions[0].action = `Rotate ${"AKIA"}${"IOSFODNN7EXAMPLE"} and scope the query.`;
  expectError(secret, "looks like a secret (AWS access key id)");

  const personal = input();
  entry(personal, INVOICE).validation_actions[0].owner_type = "jo.bloggs@department.gov.uk";
  entry(personal, INVOICE).reachability_proof.entry_point = "/home/analyst/scan-copy/src/routes/invoices.ts:41";
  const { errors, warnings } = validate(personal);
  assert.deepEqual(errors, []);
  assert.ok(warnings.some((w) => w.includes("may contain personal data (email address)")));
  assert.ok(warnings.some((w) => w.includes("host home path")));
});

test("department fields must start with x_", () => {
  const i = input();
  entry(i, INVOICE).severity = "high";
  expectError(i, 'unknown field "severity"');
  delete entry(i, INVOICE).severity;
  entry(i, INVOICE).x_portfolio = "Digital services";
  assert.deepEqual(validate(i).errors, []);
});

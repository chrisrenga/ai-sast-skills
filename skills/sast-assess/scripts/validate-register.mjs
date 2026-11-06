#!/usr/bin/env node
// Check register.json, run-record.json and scanner-leads.json against findings.json and the
// evidence model in references/evidence-model.md. Zero dependencies.
//
// Usage: node validate-register.mjs <output-dir>
// Exit codes: 0 no errors (warnings may remain), 1 errors.

import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  SECRET_PATTERNS, PERSONAL_DATA_PATTERNS, HOST_PATH_PATTERN, OVERCLAIM_PATTERNS, DEPLOYED_CLAIM_NAMES, scan,
} from "./text-checks.mjs";

const ENTRY_KEYS = new Set([
  "fingerprint", "lifecycle", "labels", "disclosure", "reachability_proof", "endpoint_authorisation",
  "routing", "remediation_actions", "validation_actions", "chain_ids", "human_review",
]);
const LIFECYCLE_FOR = { confirmed: "promoted-finding", needs_validation: "validation-candidate", rejected: "disconfirmed" };
const SOURCE = ["SAST-confirmed", "SAST-likely", "SAST-suspected", "source-disconfirmed"];
const RUNTIME = ["locally-validated", "deployed-validated", "not-validated", "not-applicable"];
const REACHABILITY = ["source-visible", "config-dependent", "runtime-dependent", "private-dependent", "not-established"];
const EXPLOITABILITY = ["confirmed", "hypothesis", "config-dependent", "private-dependent", "disconfirmed"];
const CLASSIFICATION = ["locally-validated", "deployed-validated", "validation-candidate", "disconfirmed"];
const PRODUCTION_IMPACT = ["confirmed", "not-confirmed", "not-established", "not-applicable"];
const HANDLING = ["internal-only", "owner-validation-first", "coordinated-disclosure"];
const ROUTING_CONFIDENCE = ["high", "medium", "low"];
const REVIEW_STATUS = ["pending", "accepted", "changed", "rejected"];
const VALIDATION_RESULT = [null, "vulnerable", "not-vulnerable", "inconclusive"];
const CHAIN_STATUS = ["validated-chain", "plausible-chain"];
const STAGES = ["recon", "hunt", "critic", "validate", "verify", "report"];
const EXECUTION = ["none", "sandboxed-local"];
const LEAD_DISPOSITION = ["candidate", "rejected", "duplicate", "not-reviewed"];
const ENDPOINT_FIELDS = [
  "route", "authentication", "endpoint_authorisation", "object_scope", "csrf_or_session", "feature_flag", "backend_privilege", "gap",
];

const isObject = (v) => v !== null && typeof v === "object" && !Array.isArray(v);
const isText = (v) => typeof v === "string" && v.trim().length > 0;
const isTextArray = (v) => Array.isArray(v) && v.every(isText);

export function validate({ findings, register, runRecord, scannerLeads = null }) {
  const errors = [];
  const warnings = [];
  const error = (where, message) => errors.push(`${where}: ${message}`);
  const warn = (where, message) => warnings.push(`${where}: ${message}`);

  // findings.json is validated in full by the Cloudflare validator; only verdicts are needed here.
  const verdicts = new Map();
  if (!Array.isArray(findings)) {
    error("findings.json", "must be an array");
  } else {
    for (const record of findings) {
      if (isObject(record) && isText(record.fingerprint)) verdicts.set(record.fingerprint, record.verdict);
    }
  }

  const scope = isObject(runRecord) && isObject(runRecord.scope) ? runRecord.scope : null;
  const attackerClasses = new Set(scope && isTextArray(scope.attacker_classes) ? scope.attacker_classes : []);

  if (!isObject(register)) {
    error("register.json", "must be an object");
    return { errors, warnings };
  }
  if (register.register_version !== 1) error("register.json", "register_version must be 1");
  if (!isText(register.run_id)) error("register.json", "run_id is required");
  const entries = Array.isArray(register.entries) ? register.entries : [];
  if (!Array.isArray(register.entries)) error("register.json", "entries must be an array");
  const chains = Array.isArray(register.chains) ? register.chains : [];
  if (!Array.isArray(register.chains)) error("register.json", "chains must be an array");

  const byFingerprint = new Map();
  const actionIds = new Set();

  entries.forEach((entry, i) => {
    let where = `register.entries[${i}]`;
    if (!isObject(entry)) return error(where, "must be an object");
    if (isText(entry.fingerprint)) where += ` (${entry.fingerprint})`;

    for (const key of Object.keys(entry)) {
      if (!ENTRY_KEYS.has(key) && !key.startsWith("x_")) error(where, `unknown field "${key}" (department fields must start with x_)`);
    }
    if (!isText(entry.fingerprint)) return error(where, "fingerprint is required");
    if (byFingerprint.has(entry.fingerprint)) return error(where, "duplicate fingerprint");
    byFingerprint.set(entry.fingerprint, entry);

    const verdict = verdicts.get(entry.fingerprint);
    if (verdict === undefined) return error(where, "fingerprint is not in findings.json");
    if (!(verdict in LIFECYCLE_FOR)) return error(where, `findings.json verdict "${verdict}" is not recognised`);
    const live = verdict !== "rejected";

    if (entry.lifecycle !== LIFECYCLE_FOR[verdict]) {
      error(where, `lifecycle must be "${LIFECYCLE_FOR[verdict]}" for a ${verdict} record, not "${entry.lifecycle}"`);
    }

    // Labels follow the verdict.
    const labels = isObject(entry.labels) ? entry.labels : {};
    if (!isObject(entry.labels)) error(where, "labels is required");
    if (!SOURCE.includes(labels.source)) error(where, `labels.source must be one of ${SOURCE.join(", ")}`);
    if (!RUNTIME.includes(labels.runtime)) error(where, `labels.runtime must be one of ${RUNTIME.join(", ")}`);
    if (!REACHABILITY.includes(labels.reachability)) error(where, `labels.reachability must be one of ${REACHABILITY.join(", ")}`);
    if (!EXPLOITABILITY.includes(labels.exploitability)) error(where, `labels.exploitability must be one of ${EXPLOITABILITY.join(", ")}`);
    if (verdict === "confirmed") {
      if (labels.source !== "SAST-confirmed") error(where, "a confirmed record has labels.source SAST-confirmed");
      if (!["locally-validated", "deployed-validated"].includes(labels.runtime)) {
        error(where, "a confirmed record needs an observed result: labels.runtime locally-validated or deployed-validated");
      }
      if (labels.exploitability === "disconfirmed") error(where, "a confirmed record cannot be exploitability disconfirmed");
    } else if (verdict === "needs_validation") {
      if (labels.runtime !== "not-validated") error(where, "a needs_validation record has labels.runtime not-validated");
      if (!["SAST-confirmed", "SAST-likely", "SAST-suspected"].includes(labels.source)) {
        error(where, "a needs_validation record has labels.source SAST-confirmed, SAST-likely or SAST-suspected");
      }
      if (!["hypothesis", "config-dependent", "private-dependent"].includes(labels.exploitability)) {
        error(where, "a needs_validation record has labels.exploitability hypothesis, config-dependent or private-dependent");
      }
    } else if (labels.exploitability !== "disconfirmed") {
      error(where, "a rejected record has labels.exploitability disconfirmed");
    }

    // Validation actions are read before disclosure, which depends on their results.
    const validationActions = Array.isArray(entry.validation_actions) ? entry.validation_actions : [];
    if (!Array.isArray(entry.validation_actions)) error(where, "validation_actions must be an array");
    validationActions.forEach((action, j) => {
      const at = `${where}.validation_actions[${j}]`;
      if (!isObject(action)) return error(at, "must be an object");
      if (!/^V\d{3,}$/.test(action.id ?? "")) error(at, "id must look like V001");
      else if (actionIds.has(action.id)) error(at, `duplicate action id ${action.id}`);
      else actionIds.add(action.id);
      for (const field of ["action", "owner_type", "evidence_required"]) if (!isText(action[field])) error(at, `${field} is required`);
      if (typeof action.live_access_required !== "boolean") error(at, "live_access_required must be true or false");
      if (!VALIDATION_RESULT.includes(action.result ?? null)) error(at, "result must be null, vulnerable, not-vulnerable or inconclusive");
    });
    if (verdict === "needs_validation" && validationActions.length === 0) error(where, "a validation-candidate needs at least one validation action");
    const reportedVulnerable = validationActions.some((a) => isObject(a) && a.result === "vulnerable");
    if (verdict === "needs_validation" && validationActions.some((a) => isObject(a) && a.result === "not-vulnerable")) {
      warn(where, "a validation action came back not-vulnerable: the reviewer should reconsider this record");
    }
    if (labels.runtime === "deployed-validated" && !reportedVulnerable) {
      error(where, "deployed-validated needs a validation action with result vulnerable");
    }
    if (labels.runtime === "locally-validated" && reportedVulnerable) {
      warn(where, "an owner reported vulnerable: consider runtime deployed-validated");
    }

    // Disclosure and claims.
    const disclosure = isObject(entry.disclosure) ? entry.disclosure : {};
    if (!isObject(entry.disclosure)) error(where, "disclosure is required");
    const expectedClass = verdict === "confirmed" ? labels.runtime : verdict === "needs_validation" ? "validation-candidate" : "disconfirmed";
    if (!CLASSIFICATION.includes(disclosure.classification)) error(where, `disclosure.classification must be one of ${CLASSIFICATION.join(", ")}`);
    else if (disclosure.classification !== expectedClass) error(where, `disclosure.classification must be "${expectedClass}" for this record`);
    if (!PRODUCTION_IMPACT.includes(disclosure.production_impact)) {
      error(where, `disclosure.production_impact must be one of ${PRODUCTION_IMPACT.join(", ")}`);
    } else if (disclosure.production_impact === "confirmed" && labels.runtime !== "deployed-validated") {
      error(where, "production_impact confirmed needs deployed-validated runtime evidence");
    }
    if (!HANDLING.includes(disclosure.handling)) error(where, `disclosure.handling must be one of ${HANDLING.join(", ")}`);
    for (const field of ["safe_to_say", "not_safe_to_say", "safe_if_validated"]) {
      if (!isTextArray(disclosure[field])) error(where, `disclosure.${field} must be an array of statements`);
    }
    if (live) {
      if (!(disclosure.safe_to_say?.length > 0)) error(where, "disclosure.safe_to_say needs at least one statement");
      if (!(disclosure.not_safe_to_say?.length > 0)) error(where, "disclosure.not_safe_to_say needs at least one statement");
    }
    if (isTextArray(disclosure.safe_to_say)) {
      for (const statement of disclosure.safe_to_say) {
        for (const hit of scan(statement, OVERCLAIM_PATTERNS)) {
          if (verdict === "needs_validation") error(where, `safe_to_say overstates an unvalidated record ("${hit.name}")`);
          else if (verdict === "confirmed" && labels.runtime !== "deployed-validated" && DEPLOYED_CLAIM_NAMES.has(hit.name)) {
            error(where, `safe_to_say claims deployed impact without deployed evidence ("${hit.name}")`);
          }
        }
      }
    }

    // Reachability proof.
    const proof = entry.reachability_proof;
    if (live) {
      if (!isObject(proof)) {
        error(where, "reachability_proof is required");
      } else {
        for (const field of ["attacker_class", "entry_point", "delivery", "effect"]) if (!isText(proof[field])) error(where, `reachability_proof.${field} is required`);
        if (!isTextArray(proof.unvalidated_conditions)) error(where, "reachability_proof.unvalidated_conditions must be an array of statements");
        if (isText(proof.attacker_class) && !attackerClasses.has(proof.attacker_class)) {
          error(where, `attacker_class "${proof.attacker_class}" is not one of the run scope's attacker classes`);
        }
      }
    } else if (proof !== undefined && proof !== null && !isObject(proof)) {
      error(where, "reachability_proof must be an object or null");
    }

    // Endpoint authorisation map.
    const map = entry.endpoint_authorisation;
    if (map !== undefined && map !== null) {
      if (!isObject(map)) {
        error(where, "endpoint_authorisation must be an object or null");
      } else {
        for (const field of ENDPOINT_FIELDS) if (!isText(map[field])) error(where, `endpoint_authorisation.${field} is required`);
        if (!isTextArray(map.methods) || map.methods.length === 0) error(where, "endpoint_authorisation.methods must list at least one method");
      }
    }

    // Routing.
    const routing = entry.routing;
    if (live || (routing !== undefined && routing !== null)) {
      if (!isObject(routing)) {
        error(where, "routing is required");
      } else {
        if (!/^[A-Za-z0-9][A-Za-z0-9._-]*$/.test(routing.routing_id ?? "")) error(where, "routing.routing_id is required, for example RC001");
        if (routing.owner !== null && !isText(routing.owner)) error(where, "routing.owner must be a name or null");
        if (!ROUTING_CONFIDENCE.includes(routing.confidence)) error(where, "routing.confidence must be high, medium or low");
        if (!isText(routing.source)) error(where, "routing.source is required");
        if (typeof routing.owner_confirmation_required !== "boolean") error(where, "routing.owner_confirmation_required must be true or false");
        else if ((routing.confidence === "low" || routing.owner === null) && !routing.owner_confirmation_required) {
          error(where, "routing with low confidence or no owner needs owner_confirmation_required true");
        }
      }
    }

    // Remediation actions.
    const remediation = Array.isArray(entry.remediation_actions) ? entry.remediation_actions : [];
    if (!Array.isArray(entry.remediation_actions)) error(where, "remediation_actions must be an array");
    remediation.forEach((action, j) => {
      const at = `${where}.remediation_actions[${j}]`;
      if (!isObject(action)) return error(at, "must be an object");
      if (!/^A\d{3,}$/.test(action.id ?? "")) error(at, "id must look like A001");
      else if (actionIds.has(action.id)) error(at, `duplicate action id ${action.id}`);
      else actionIds.add(action.id);
      for (const field of ["action", "acceptance"]) if (!isText(action[field])) error(at, `${field} is required`);
    });
    if (verdict === "confirmed" && remediation.length === 0) error(where, "a promoted-finding needs at least one remediation action");

    if (!isTextArray(entry.chain_ids)) error(where, "chain_ids must be an array of chain ids");

    const review = entry.human_review;
    if (!isObject(review) || !REVIEW_STATUS.includes(review.status)) {
      error(where, "human_review.status must be pending, accepted, changed or rejected");
    } else if (review.status !== "pending" && (!isText(review.reviewer) || !isText(review.date))) {
      error(where, "a completed human review names the reviewer and date");
    }
  });

  for (const [fingerprint] of verdicts) {
    if (!byFingerprint.has(fingerprint)) error("register.json", `no entry for findings.json record ${fingerprint}`);
  }

  // Chains: never stronger than the weakest link, and linked both ways.
  const chainIds = new Set();
  chains.forEach((chain, i) => {
    let where = `register.chains[${i}]`;
    if (!isObject(chain)) return error(where, "must be an object");
    if (!/^C\d{3,}$/.test(chain.id ?? "")) return error(where, "id must look like C001");
    where += ` (${chain.id})`;
    if (chainIds.has(chain.id)) return error(where, "duplicate chain id");
    chainIds.add(chain.id);
    if (!isText(chain.title)) error(where, "title is required");
    if (!isText(chain.weakest_link)) error(where, "weakest_link is required");
    if (!isTextArray(chain.assumptions)) error(where, "assumptions must be an array of statements");
    if (!CHAIN_STATUS.includes(chain.status)) error(where, "status must be validated-chain or plausible-chain");
    if (!isTextArray(chain.fingerprints) || chain.fingerprints.length === 0) return error(where, "a chain cites at least one fingerprint");
    for (const fingerprint of chain.fingerprints) {
      const entry = byFingerprint.get(fingerprint);
      if (!entry) { error(where, `fingerprint ${fingerprint} is not in the register`); continue; }
      const verdict = verdicts.get(fingerprint);
      if (verdict === "rejected") error(where, `cites rejected record ${fingerprint}`);
      if (chain.status === "validated-chain" && verdict !== "confirmed") {
        error(where, `validated-chain needs every link confirmed; ${fingerprint} is ${verdict}`);
      }
      if (!(entry.chain_ids ?? []).includes(chain.id)) error(where, `entry ${fingerprint} does not list ${chain.id} in chain_ids`);
    }
    if (chain.status === "validated-chain" && chain.assumptions?.length > 0) error(where, "validated-chain cannot have open assumptions");
  });
  for (const [fingerprint, entry] of byFingerprint) {
    for (const id of Array.isArray(entry.chain_ids) ? entry.chain_ids : []) {
      const chain = chains.find((c) => isObject(c) && c.id === id);
      if (!chain) error(`register entry ${fingerprint}`, `chain ${id} does not exist`);
      else if (!(chain.fingerprints ?? []).includes(fingerprint)) error(`register entry ${fingerprint}`, `chain ${id} does not list this fingerprint`);
    }
  }

  // Notes.
  const notes = register.notes;
  if (!isObject(notes)) {
    error("register.notes", "must be an object with hardening, out_of_scope and repository_directives");
  } else {
    const shape = {
      hardening: (n) => isText(n.text) && isTextArray(n.paths),
      out_of_scope: (n) => isText(n.text) && isText(n.reason),
      repository_directives: (n) => isText(n.file) && Number.isInteger(n.line) && n.line >= 1 && isText(n.summary),
    };
    for (const [key, ok] of Object.entries(shape)) {
      if (!Array.isArray(notes[key])) { error("register.notes", `${key} must be an array`); continue; }
      notes[key].forEach((n, j) => { if (!isObject(n) || !ok(n)) error(`register.notes.${key}[${j}]`, "is missing required fields"); });
    }
  }

  // Run record.
  if (!isObject(runRecord)) {
    error("run-record.json", "must be an object");
  } else {
    if (runRecord.run_id !== register.run_id) error("run-record.json", "run_id does not match register.json");
    if (!scope) {
      error("run-record.json", "scope is required");
    } else {
      for (const field of ["assessment_id", "approved_by", "approved_on", "model_route", "output_location", "retention"]) {
        if (!isText(scope[field])) error("run-record.json", `scope.${field} is required`);
      }
      if (!isTextArray(scope.attacker_classes) || scope.attacker_classes.length === 0) error("run-record.json", "scope.attacker_classes must list at least one class");
      if (!Array.isArray(scope.repositories) || scope.repositories.length === 0) error("run-record.json", "scope.repositories must list the repository");
      if (!EXECUTION.includes(scope.execution)) error("run-record.json", "scope.execution must be none or sandboxed-local");
      if (scope.execution === "sandboxed-local" && !isText(scope.sandbox)) error("run-record.json", "scope.sandbox must describe the sandbox");
      if (scope.execution === "none" && [...verdicts.values()].includes("confirmed")) {
        error("run-record.json", "scope.execution is none, so no record can be confirmed");
      }
    }
    const target = isObject(runRecord.target) ? runRecord.target : {};
    for (const field of ["repository", "source_ref"]) if (!isText(target[field])) error("run-record.json", `target.${field} is required`);
    const tools = isObject(runRecord.tools) ? runRecord.tools : {};
    for (const field of ["agent_client", "skill_pack_version", "cloudflare_method_commit"]) if (!isText(tools[field])) error("run-record.json", `tools.${field} is required`);

    const stages = Array.isArray(runRecord.stages) ? runRecord.stages : [];
    if (!Array.isArray(runRecord.stages)) error("run-record.json", "stages must be an array");
    stages.forEach((s, i) => {
      if (!isObject(s) || !STAGES.includes(s.stage)) error(`run-record.json stages[${i}]`, `stage must be one of ${STAGES.join(", ")}`);
      else if (!isText(s.model)) error(`run-record.json stages[${i}]`, "model is required");
    });
    const modelId = (s) => `${String(s.model).trim().toLowerCase()}@${String(s.model_version ?? "").trim().toLowerCase()}`;
    const hunters = new Set(stages.filter((s) => isObject(s) && s.stage === "hunt").map(modelId));
    const checkers = stages.filter((s) => isObject(s) && (s.stage === "validate" || s.stage === "verify")).map(modelId);
    if (verdicts.size > 0 && hunters.size === 0) error("run-record.json", "no hunt stage is recorded");
    if (verdicts.size > 0 && !stages.some((s) => isObject(s) && s.stage === "validate")) error("run-record.json", "no validate stage is recorded");
    const sameModel = checkers.some((id) => hunters.has(id));
    if (runRecord.same_model_verification !== sameModel) {
      error("run-record.json", `same_model_verification must be ${sameModel}: the stages show ${sameModel ? "a" : "no"} validate or verify stage using a hunting model`);
    }
    if (!["complete", "incomplete"].includes(runRecord.run_status)) error("run-record.json", "run_status must be complete or incomplete");
    if (runRecord.run_status === "incomplete" && !isText(runRecord.incomplete_reason)) error("run-record.json", "an incomplete run states incomplete_reason");
  }

  // Scanner leads.
  if (scannerLeads !== null) {
    if (!Array.isArray(scannerLeads)) {
      error("scanner-leads.json", "must be an array");
    } else {
      const leadIds = new Set();
      scannerLeads.forEach((lead, i) => {
        const where = `scanner-leads.json[${i}]`;
        if (!isObject(lead)) return error(where, "must be an object");
        if (!/^L\d{3,}$/.test(lead.lead_id ?? "")) error(where, "lead_id must look like L001");
        else if (leadIds.has(lead.lead_id)) error(where, `duplicate lead_id ${lead.lead_id}`);
        else leadIds.add(lead.lead_id);
        for (const field of ["tool", "rule_id", "file"]) if (!isText(lead[field])) error(where, `${field} is required`);
        if (!LEAD_DISPOSITION.includes(lead.disposition)) error(where, `disposition must be one of ${LEAD_DISPOSITION.join(", ")}`);
        else if (lead.disposition === "candidate" && !verdicts.has(lead.fingerprint)) error(where, "a candidate lead names a fingerprint in findings.json");
        else if (lead.disposition !== "candidate" && !isText(lead.reason)) error(where, `a ${lead.disposition} lead states its reason`);
      });
    }
  }

  // Text hygiene across everything this pack writes.
  const visit = (value, where, checkHostPaths) => {
    if (typeof value === "string") {
      for (const hit of scan(value, SECRET_PATTERNS)) error(where, `looks like a secret (${hit.name}); redact it as <REDACTED:purpose>`);
      for (const hit of scan(value, PERSONAL_DATA_PATTERNS)) warn(where, `may contain personal data (${hit.name})`);
      if (checkHostPaths) for (const hit of scan(value, [HOST_PATH_PATTERN])) warn(where, `contains a ${hit.name}; use repository-relative paths`);
    } else if (Array.isArray(value)) {
      value.forEach((v, i) => visit(v, `${where}[${i}]`, checkHostPaths));
    } else if (isObject(value)) {
      for (const [k, v] of Object.entries(value)) visit(v, `${where}.${k}`, checkHostPaths);
    }
  };
  visit(register, "register", true);
  if (isObject(runRecord)) visit(runRecord, "run-record", false);

  return { errors, warnings };
}

function readJson(file, required) {
  if (!fs.existsSync(file)) {
    if (required) throw new Error(`${path.basename(file)} not found in the output directory`);
    return null;
  }
  return JSON.parse(fs.readFileSync(file, "utf8"));
}

function main() {
  const dir = process.argv[2];
  if (!dir) {
    console.error("usage: node validate-register.mjs <output-dir>");
    process.exit(1);
  }
  let input;
  try {
    input = {
      findings: readJson(path.join(dir, "findings.json"), true),
      register: readJson(path.join(dir, "register.json"), true),
      runRecord: readJson(path.join(dir, "run-record.json"), true),
      scannerLeads: readJson(path.join(dir, "scanner-leads.json"), false),
    };
  } catch (e) {
    console.error(`validate-register: ${e.message}`);
    process.exit(1);
  }
  const { errors, warnings } = validate(input);
  for (const e of errors) console.log(`ERROR   ${e}`);
  for (const w of warnings) console.log(`WARNING ${w}`);
  console.log(`${errors.length} error(s), ${warnings.length} warning(s)`);
  process.exit(errors.length > 0 ? 1 : 0);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) main();

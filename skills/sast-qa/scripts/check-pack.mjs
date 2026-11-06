#!/usr/bin/env node
// Mechanical checks on a report pack before it is shared: secrets, unfilled templates,
// checksums and counts are errors; personal data, host paths and strong wording are warnings
// for the reviewer to clear. Zero dependencies.
//
// Usage: node check-pack.mjs <output-dir>
// Exit codes: 0 no errors (warnings may remain), 1 errors.

import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import {
  SECRET_PATTERNS, PERSONAL_DATA_PATTERNS, HOST_PATH_PATTERN, OVERCLAIM_PATTERNS, scan, lineOf,
} from "../../sast-assess/scripts/text-checks.mjs";

const TEXT_EXTENSIONS = new Set([".md", ".json", ".csv", ".sarif", ".txt"]);
const SEVERITY_ORDER = ["informational", "low", "medium", "high", "critical"];

function walk(dir, rel = "") {
  const files = [];
  for (const entry of fs.readdirSync(path.join(dir, rel), { withFileTypes: true })) {
    const child = rel ? `${rel}/${entry.name}` : entry.name;
    if (entry.isDirectory()) files.push(...walk(dir, child));
    else if (entry.isFile()) files.push(child);
  }
  return files;
}

// Number of records in a CSV file, allowing quoted fields that contain line breaks.
export function countCsvRecords(text) {
  let records = 0;
  let inQuotes = false;
  let sawField = false;
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') { inQuotes = !inQuotes; sawField = true; }
    else if (!inQuotes && c === "\n") { if (sawField) records++; sawField = false; }
    else if (!inQuotes && c !== "\r") sawField = true;
  }
  return records + (sawField ? 1 : 0);
}

export function checkPack(outputDir) {
  const errors = [];
  const warnings = [];
  const reportDir = path.join(outputDir, "report");
  if (!fs.existsSync(reportDir)) return { errors: [`${reportDir} does not exist`], warnings };
  const files = walk(reportDir);

  for (const rel of files) {
    if (!TEXT_EXTENSIONS.has(path.extname(rel)) && path.basename(rel) !== "SHA256SUMS") continue;
    const text = fs.readFileSync(path.join(reportDir, rel), "utf8");
    const at = (index) => `report/${rel}:${lineOf(text, index)}`;
    for (const hit of scan(text, SECRET_PATTERNS)) errors.push(`${at(hit.index)}: looks like a secret (${hit.name})`);
    for (let i = text.indexOf("{{"); i !== -1; i = text.indexOf("{{", i + 2)) errors.push(`${at(i)}: unfilled template marker`);
    for (const hit of scan(text, PERSONAL_DATA_PATTERNS)) warnings.push(`${at(hit.index)}: may contain personal data (${hit.name})`);
    for (const hit of scan(text, [HOST_PATH_PATTERN])) warnings.push(`${at(hit.index)}: contains a ${hit.name}`);
    if (path.extname(rel) === ".md") {
      for (const hit of scan(text, OVERCLAIM_PATTERNS)) warnings.push(`${at(hit.index)}: strong wording ("${hit.name}"); check it is supported or only quoted as not safe to say`);
    }
  }

  // Checksums in every owner pack.
  const packsDir = path.join(reportDir, "packs");
  const packs = fs.existsSync(packsDir) ? fs.readdirSync(packsDir, { withFileTypes: true }).filter((d) => d.isDirectory()).map((d) => d.name) : [];
  for (const pack of packs) {
    const dir = path.join(packsDir, pack);
    const sums = path.join(dir, "SHA256SUMS");
    if (!fs.existsSync(sums)) { errors.push(`report/packs/${pack}: SHA256SUMS is missing`); continue; }
    const listed = new Set();
    for (const line of fs.readFileSync(sums, "utf8").split("\n").filter(Boolean)) {
      const match = line.match(/^([0-9a-f]{64}) [ *](.+)$/);
      if (!match) { errors.push(`report/packs/${pack}/SHA256SUMS: unreadable line "${line}"`); continue; }
      const file = path.normalize(match[2]);
      listed.add(file);
      const target = path.join(dir, file);
      if (!fs.existsSync(target)) { errors.push(`report/packs/${pack}: ${file} is listed but missing`); continue; }
      const digest = crypto.createHash("sha256").update(fs.readFileSync(target)).digest("hex");
      if (digest !== match[1]) errors.push(`report/packs/${pack}: ${file} does not match its checksum`);
    }
    for (const file of walk(dir)) {
      if (file !== "SHA256SUMS" && !listed.has(path.normalize(file))) errors.push(`report/packs/${pack}: ${file} is not in SHA256SUMS`);
    }
  }

  // Counts against the register, when the run's records are present.
  const read = (name) => {
    const file = path.join(outputDir, name);
    return fs.existsSync(file) ? JSON.parse(fs.readFileSync(file, "utf8")) : null;
  };
  const findings = read("findings.json");
  const register = read("register.json");
  const runRecord = read("run-record.json");
  if (findings && register) {
    const verdicts = new Map(findings.map((f) => [f.fingerprint, f]));
    const live = register.entries.filter((e) => ["promoted-finding", "validation-candidate"].includes(e.lifecycle));
    const threshold = SEVERITY_ORDER.indexOf(runRecord?.scope?.severity_threshold ?? "informational");
    const fullReports = live.filter((e) => e.lifecycle === "promoted-finding" &&
      SEVERITY_ORDER.indexOf(verdicts.get(e.fingerprint)?.severity?.overall_severity) >= Math.max(threshold, 0));
    const count = (sub) => (fs.existsSync(path.join(reportDir, sub)) ? fs.readdirSync(path.join(reportDir, sub)).filter((f) => f.endsWith(".md")).length : 0);
    const expect = (label, actual, wanted) => { if (actual !== wanted) errors.push(`counts: ${label} is ${actual}, register implies ${wanted}`); };

    expect("report/findings/*.md", count("findings"), fullReports.length);
    expect("report/validation/*.md", count("validation"), live.filter((e) => e.lifecycle === "validation-candidate").length);
    const sarifFile = path.join(reportDir, "findings.sarif");
    if (fs.existsSync(sarifFile)) expect("SARIF results", JSON.parse(fs.readFileSync(sarifFile, "utf8")).runs[0].results.length, live.length);
    else errors.push("report/findings.sarif is missing");
    for (const name of ["tickets-jira.csv", "tickets-servicenow.csv"]) {
      const file = path.join(reportDir, name);
      if (fs.existsSync(file)) expect(`${name} rows`, countCsvRecords(fs.readFileSync(file, "utf8")) - 1, live.length);
      else errors.push(`report/${name} is missing`);
    }
    const routingIds = new Set(live.map((e) => e.routing?.routing_id).filter(Boolean));
    for (const id of routingIds) if (!packs.includes(id)) errors.push(`report/packs/${id} is missing`);
    for (const pack of packs) if (!routingIds.has(pack)) warnings.push(`report/packs/${pack} matches no routing id in the register`);
    if (!fs.existsSync(path.join(reportDir, "RECONCILIATION.md"))) errors.push("report/RECONCILIATION.md is missing");
    if (!fs.existsSync(path.join(reportDir, "EXECUTIVE-SUMMARY.md"))) errors.push("report/EXECUTIVE-SUMMARY.md is missing");
  }

  return { errors, warnings };
}

function main() {
  const dir = process.argv[2];
  if (!dir) {
    console.error("usage: node check-pack.mjs <output-dir>");
    process.exit(1);
  }
  const { errors, warnings } = checkPack(dir);
  for (const e of errors) console.log(`ERROR   ${e}`);
  for (const w of warnings) console.log(`WARNING ${w}`);
  console.log(`${errors.length} error(s), ${warnings.length} warning(s)`);
  process.exit(errors.length > 0 ? 1 : 0);
}

if (import.meta.url === pathToFileURL(process.argv[1] ?? "").href) main();

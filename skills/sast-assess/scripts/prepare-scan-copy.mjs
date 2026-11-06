#!/usr/bin/env node
// Make a sanitised scan copy of a repository at one commit, for sast-assess.
//
// Usage: node prepare-scan-copy.mjs --repo <path-to-clone> --out <new-dir> [--ref <commit-or-branch>] [--name <repo-name>]
//
// Exit codes: 0 clean, 2 copy made but the secret scan found something to redact, 1 error.

import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { SECRET_PATTERNS, POSSIBLE_SECRET_PATTERNS, scan, lineOf, looksLikeText } from "./text-checks.mjs";

// Files that usually hold credentials. Examples and templates are kept for review.
const SECRET_FILES = [
  /^\.env$/, /^\.env\..+/, /\.pem$/, /\.key$/, /\.p12$/, /\.pfx$/, /\.jks$/, /\.keystore$/, /\.kdbx$/,
  /^id_(?:rsa|dsa|ecdsa|ed25519)$/, /^\.npmrc$/, /^\.pypirc$/, /^\.netrc$/, /^\.git-credentials$/,
  /^credentials(?:\.json)?$/, /\.tfstate(?:\.backup)?$/, /^\.htpasswd$/,
];
const KEEP_SUFFIXES = [".example", ".sample", ".dist", ".template"];

// Files and directories that agent clients load as instructions.
const AGENT_FILES = new Set([
  "AGENTS.md", "AGENTS.override.md", "CLAUDE.md", "CLAUDE.local.md", "GEMINI.md", "SKILL.md",
  ".cursorrules", ".windsurfrules", ".clinerules", "copilot-instructions.md",
]);
const AGENT_DIRS = new Set([".claude", ".cursor", ".codex", ".gemini", ".windsurf", ".clinerules", ".agents", ".github/instructions", ".github/prompts"]);
const AGENT_SUFFIXES = [".instructions.md", ".prompt.md", ".mdc"];
const RENAME_SUFFIX = ".under-review";

const MAX_SCAN_BYTES = 2 * 1024 * 1024;

function fail(message) {
  console.error(`prepare-scan-copy: ${message}`);
  process.exit(1);
}

function parseArgs(argv) {
  const args = { ref: "HEAD" };
  for (let i = 0; i < argv.length; i += 2) {
    const key = argv[i];
    const value = argv[i + 1];
    if (!["--repo", "--out", "--ref", "--name"].includes(key) || value === undefined) {
      fail("usage: node prepare-scan-copy.mjs --repo <path-to-clone> --out <new-dir> [--ref <commit-or-branch>] [--name <repo-name>]");
    }
    args[key.slice(2)] = value;
  }
  if (!args.repo || !args.out) fail("--repo and --out are required");
  return args;
}

function git(repo, args) {
  return execFileSync("git", ["-C", repo, ...args], { encoding: "utf8" }).trim();
}

// Every entry under root, without following symbolic links. Paths are relative to root.
function walk(root, rel = "") {
  const entries = [];
  for (const name of fs.readdirSync(path.join(root, rel))) {
    const child = rel ? `${rel}/${name}` : name;
    const stat = fs.lstatSync(path.join(root, child));
    entries.push({ rel: child, name, stat });
    if (stat.isDirectory()) entries.push(...walk(root, child));
  }
  return entries;
}

function isSecretFile(name) {
  if (KEEP_SUFFIXES.some((suffix) => name.endsWith(suffix))) return false;
  return SECRET_FILES.some((pattern) => pattern.test(name));
}

function isAgentFile(rel, name) {
  return AGENT_FILES.has(name) || AGENT_SUFFIXES.some((suffix) => name.endsWith(suffix)) || rel === ".github/copilot-instructions.md";
}

function runGitleaks(dir) {
  const version = spawnSync("gitleaks", ["version"], { encoding: "utf8" });
  if (version.error || version.status !== 0) return null;
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "scan-copy-"));
  const report = path.join(tmp, "gitleaks.json");
  const common = ["--no-banner", "--redact", "--exit-code", "0", "--report-format", "json", "--report-path", report];
  try {
    let run = spawnSync("gitleaks", ["dir", dir, ...common], { encoding: "utf8" });
    if (run.status !== 0) run = spawnSync("gitleaks", ["detect", "--no-git", "--source", dir, ...common], { encoding: "utf8" });
    if (run.status !== 0) return { version: version.stdout.trim(), error: (run.stderr || "").trim().split("\n").pop() };
    const results = JSON.parse(fs.readFileSync(report, "utf8") || "[]");
    return {
      version: version.stdout.trim(),
      findings: results.map((r) => ({ file: path.relative(dir, path.resolve(dir, r.File)), line: r.StartLine, rule: r.RuleID })),
    };
  } finally {
    fs.rmSync(tmp, { recursive: true, force: true });
  }
}

const args = parseArgs(process.argv.slice(2));
const repo = path.resolve(args.repo);
const out = path.resolve(args.out);

if (fs.existsSync(out) && fs.readdirSync(out).length > 0) fail(`${out} already exists and is not empty`);
if (out.startsWith(repo + path.sep)) fail("--out must be outside the repository");

let commit;
try {
  commit = git(repo, ["rev-parse", "--verify", `${args.ref}^{commit}`]);
} catch {
  fail(`cannot resolve ${args.ref} in ${repo}`);
}

// git archive exports tracked files at the commit: no .git/, no untracked or ignored files.
const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "scan-copy-"));
const tarball = path.join(tmp, "tree.tar");
git(repo, ["archive", "--format=tar", "-o", tarball, commit]);
fs.mkdirSync(out, { recursive: true });
execFileSync("tar", ["-xf", tarball, "-C", out]);
fs.rmSync(tmp, { recursive: true, force: true });

const manifest = {
  manifest_version: 1,
  created_at: new Date().toISOString(),
  repository: args.name || path.basename(repo),
  source_ref_requested: args.ref,
  commit,
  scan_copy: out,
  removed_files: [],
  renamed_agent_files: [],
  replaced_symlinks: [],
  coverage_notes: [],
  secret_scan: { builtin: { high: [], possible: [] }, gitleaks: null },
  notes: [],
};

// Symbolic links could lead a reader outside the scan copy, so each becomes a plain note.
for (const entry of walk(out)) {
  if (!entry.stat.isSymbolicLink()) continue;
  const full = path.join(out, entry.rel);
  const target = fs.readlinkSync(full);
  fs.unlinkSync(full);
  fs.writeFileSync(full, `Symbolic link to: ${target}\nReplaced by prepare-scan-copy so that readers stay inside the scan copy.\n`);
  manifest.replaced_symlinks.push({ path: entry.rel, target });
}

for (const entry of walk(out)) {
  if (entry.stat.isFile() && isSecretFile(entry.name)) {
    fs.rmSync(path.join(out, entry.rel));
    manifest.removed_files.push(entry.rel);
  }
}

// Rename deepest first so that a renamed directory does not invalidate paths below it.
const toRename = walk(out)
  .filter((e) => (e.stat.isDirectory() ? AGENT_DIRS.has(e.name) || AGENT_DIRS.has(e.rel) : e.stat.isFile() && isAgentFile(e.rel, e.name)))
  .sort((a, b) => b.rel.split("/").length - a.rel.split("/").length);
for (const entry of toRename) {
  const from = path.join(out, entry.rel);
  fs.renameSync(from, from + RENAME_SUFFIX);
  manifest.renamed_agent_files.push({ from: entry.rel, to: entry.rel + RENAME_SUFFIX });
}

let lfsPointers = 0;
for (const entry of walk(out)) {
  if (!entry.stat.isFile() || entry.stat.size > MAX_SCAN_BYTES) continue;
  const buffer = fs.readFileSync(path.join(out, entry.rel));
  if (!looksLikeText(buffer)) continue;
  const text = buffer.toString("utf8");
  if (text.startsWith("version https://git-lfs.github.com/spec/v1")) lfsPointers++;
  if (entry.name === ".gitmodules") manifest.coverage_notes.push(`${entry.rel}: submodule contents are not in the scan copy.`);
  if (entry.name === ".gitattributes" && /export-ignore/.test(text)) {
    manifest.coverage_notes.push(`${entry.rel} uses export-ignore: git archive left some tracked files out of the scan copy.`);
  }
  for (const hit of scan(text, SECRET_PATTERNS)) manifest.secret_scan.builtin.high.push({ file: entry.rel, line: lineOf(text, hit.index), pattern: hit.name });
  for (const hit of scan(text, POSSIBLE_SECRET_PATTERNS)) manifest.secret_scan.builtin.possible.push({ file: entry.rel, line: lineOf(text, hit.index), pattern: hit.name });
}
if (lfsPointers > 0) manifest.coverage_notes.push(`${lfsPointers} Git LFS pointer file(s): their contents are not in the scan copy.`);

manifest.secret_scan.gitleaks = runGitleaks(out);
if (manifest.secret_scan.gitleaks === null) {
  manifest.notes.push("gitleaks was not found. Run control requires a full secret scan; run one before the assessment and record the result here.");
}

const manifestPath = `${out}.manifest.json`;
fs.writeFileSync(manifestPath, JSON.stringify(manifest, null, 2) + "\n");

const high = manifest.secret_scan.builtin.high.length + (manifest.secret_scan.gitleaks?.findings?.length || 0);
console.log(`Scan copy of ${manifest.repository} at ${commit} written to ${out}`);
console.log(`Manifest: ${manifestPath}`);
console.log(`Removed ${manifest.removed_files.length} secret-bearing file(s), renamed ${manifest.renamed_agent_files.length} agent instruction file(s), replaced ${manifest.replaced_symlinks.length} symbolic link(s).`);
for (const note of [...manifest.coverage_notes, ...manifest.notes]) console.log(`Note: ${note}`);
if (manifest.secret_scan.gitleaks?.error) console.log(`Note: gitleaks failed: ${manifest.secret_scan.gitleaks.error}`);
if (manifest.secret_scan.builtin.possible.length > 0) {
  console.log(`Review ${manifest.secret_scan.builtin.possible.length} possible secret(s) listed in the manifest.`);
}
if (high > 0) {
  console.log(`Secret scan found ${high} likely secret(s). Redact them in the scan copy as <REDACTED:purpose> and record that in the manifest notes before the run.`);
  process.exit(2);
}

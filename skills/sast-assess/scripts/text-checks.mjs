// Text checks shared by prepare-scan-copy, validate-register and sast-qa's check-pack.
// Patterns are deliberately high-signal: they flag material for a human to look at,
// they do not prove that a value is or is not a live secret.

// Formats that are almost never anything but a credential.
export const SECRET_PATTERNS = [
  ["private key block", /-----BEGIN [A-Z ]*PRIVATE KEY-----/g],
  ["AWS access key id", /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g],
  ["GitHub token", /\b(?:gh[pousr]_[A-Za-z0-9]{36,}|github_pat_[A-Za-z0-9_]{50,})\b/g],
  ["Slack token", /\bxox[abposr]-[A-Za-z0-9-]{10,}\b/g],
  ["Google API key", /\bAIza[0-9A-Za-z_-]{35}\b/g],
  ["Stripe live key", /\b[rs]k_live_[0-9A-Za-z]{20,}\b/g],
  ["Anthropic API key", /\bsk-ant-[A-Za-z0-9_-]{20,}/g],
  ["OpenAI-style API key", /\bsk-(?:proj-)?[A-Za-z0-9]{32,}\b/g],
  ["Azure storage account key", /AccountKey=[A-Za-z0-9+/=]{40,}/g],
  ["JSON web token", /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g],
];

// Formats that are often placeholders in documentation, so they are reported for review.
export const POSSIBLE_SECRET_PATTERNS = [
  ["credentials in a URL", /\b[a-z][a-z0-9+.-]*:\/\/[^\s:@/]+:[^\s@/<>]{6,}@/gi],
  ["assigned secret", /\b[A-Za-z_]*(?:api[_-]?key|secret|passw(?:or)?d|token)[A-Za-z_]*["']?\s*[:=]\s*["'][^"'\s<>{}$]{12,}["']/gi],
];

export const PERSONAL_DATA_PATTERNS = [
  ["email address", /\b[A-Za-z0-9._%+-]+@(?!example\.(?:com|org|net)\b)(?![A-Za-z0-9.-]*noreply)[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b/g],
  ["UK National Insurance number", /\b(?!BG|GB|NK|KN|TN|NT|ZZ)[A-CEGHJ-PR-TW-Z][A-CEGHJ-NPR-TW-Z] ?\d{2} ?\d{2} ?\d{2} ?[A-D]\b/g],
];

export const HOST_PATH_PATTERN = ["host home path", /(?:\/Users\/[^/\s"']+|\/home\/[^/\s"']+|[A-Za-z]:\\Users\\[^\\\s"']+)/g];

// Wording that overstates evidence that has not been validated in a deployment.
export const OVERCLAIM_PATTERNS = [
  ["confirmed exploitable", /\bconfirmed[ -]exploitable\b/gi],
  ["attacker can", /\b(?:an |the )?attackers? can\b/gi],
  ["will allow", /\bwill allow\b/gi],
  ["production is affected", /\bproduction (?:is|was|has been) (?:vulnerable|affected|impacted|compromised)\b/gi],
  ["live issue", /\blive (?:issue|exploit|compromise)\b/gi],
  ["has been exploited", /\b(?:has|have) been exploited\b/gi],
  ["demonstrated", /\bdemonstrated\b/gi],
];

// Wording that claims deployed impact; only deployed-validated evidence supports it.
export const DEPLOYED_CLAIM_NAMES = new Set(["production is affected", "live issue", "has been exploited"]);

export function scan(text, patterns) {
  const hits = [];
  for (const [name, regex] of patterns) {
    regex.lastIndex = 0;
    let match;
    while ((match = regex.exec(text)) !== null) {
      if (/<REDACTED:/.test(match[0])) continue;
      hits.push({ name, index: match.index });
      if (match[0].length === 0) regex.lastIndex++;
    }
  }
  return hits;
}

export function lineOf(text, index) {
  let line = 1;
  for (let i = 0; i < index; i++) if (text.charCodeAt(i) === 10) line++;
  return line;
}

// True when the buffer looks like text rather than a binary file.
export function looksLikeText(buffer) {
  const sample = buffer.subarray(0, 8192);
  return !sample.includes(0);
}

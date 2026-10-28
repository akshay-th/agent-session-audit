import { createHash } from 'node:crypto';

// Each detector: id, label, severity, regex (global), group = capture group that
// holds the secret (0 = whole match). Patterns stop at quotes and backslashes so
// they never swallow JSON escapes in .jsonl transcripts.
export const DETECTORS = [
  { id: 'private-key', label: 'Private key', severity: 'high', re: /-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----(?:(?!-----END)[\s\S]){16,12000}?-----END (?:[A-Z0-9]+ )*PRIVATE KEY-----/g },
  { id: 'aws-access-key', label: 'AWS access key ID', severity: 'high', re: /\b(?:AKIA|ASIA)[0-9A-Z]{16}\b/g },
  { id: 'aws-secret-key', label: 'AWS secret access key', severity: 'high', re: /aws_secret_access_key["'\s]*[:=]\s*["']?([A-Za-z0-9/+]{40})(?![A-Za-z0-9/+])/gi, group: 1 },
  { id: 'github-token', label: 'GitHub token', severity: 'high', re: /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,255}\b|\bgithub_pat_[A-Za-z0-9_]{60,255}\b/g },
  { id: 'gitlab-token', label: 'GitLab token', severity: 'high', re: /\bglpat-[A-Za-z0-9_-]{20,}\b/g },
  { id: 'anthropic-key', label: 'Anthropic API key', severity: 'high', re: /\bsk-ant-(?:api|admin|oat)\d{2}-[A-Za-z0-9_-]{40,}/g },
  { id: 'openai-key', label: 'OpenAI API key', severity: 'high', re: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{40,}|\bsk-[A-Za-z0-9]{20}T3BlbkFJ[A-Za-z0-9]{20}\b/g },
  { id: 'google-api-key', label: 'Google API key', severity: 'medium', re: /\bAIza[0-9A-Za-z_-]{35}(?![0-9A-Za-z_-])/g },
  { id: 'slack-token', label: 'Slack token', severity: 'high', re: /\bxox[baprse]-[A-Za-z0-9-]{10,}/g },
  { id: 'slack-webhook', label: 'Slack webhook', severity: 'medium', re: /https:\/\/hooks\.slack\.com\/services\/T[A-Z0-9]+\/B[A-Z0-9]+\/[A-Za-z0-9]{20,}/g },
  { id: 'stripe-live-key', label: 'Stripe live key', severity: 'high', re: /\b(?:sk|rk)_live_[A-Za-z0-9]{20,}\b/g },
  { id: 'stripe-test-key', label: 'Stripe test key', severity: 'low', re: /\b(?:sk|rk)_test_[A-Za-z0-9]{20,}\b/g },
  { id: 'npm-token', label: 'npm token', severity: 'high', re: /\bnpm_[A-Za-z0-9]{36}\b/g },
  { id: 'pypi-token', label: 'PyPI token', severity: 'high', re: /\bpypi-AgEIcHlwaS5vcmc[A-Za-z0-9_-]{50,}/g },
  { id: 'huggingface-token', label: 'Hugging Face token', severity: 'high', re: /\bhf_[A-Za-z0-9]{34,}\b/g },
  { id: 'sendgrid-key', label: 'SendGrid key', severity: 'high', re: /\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}\b/g },
  { id: 'jwt', label: 'JWT', severity: 'medium', re: /\beyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}/g },
  {
    id: 'database-url',
    label: 'Database URL with password',
    severity: 'high',
    re: /\b(?:postgres(?:ql)?|mysql|mariadb|mongodb(?:\+srv)?|rediss?|amqps?|mssql):\/\/[^\s:@/"'\\]+:([^\s@/"'\\]{3,})@[^\s"'\\]+/g,
    group: 1,
    validate: (v) => !isPlaceholder(v),
  },
  {
    id: 'env-assignment',
    label: 'Secret-looking assignment',
    severity: 'medium',
    re: /\b[A-Z][A-Z0-9_]*(?:SECRET|TOKEN|PASSWORD|PASSWD|API_KEY|APIKEY|PRIVATE_KEY|ACCESS_KEY|CLIENT_SECRET)[A-Z0-9_]*\s*[=:]\s*["']?([^\s"'\\,;]{8,})/g,
    group: 1,
    generic: true,
    validate: (v) => !isPlaceholder(v) && entropy(v) >= 3,
  },
];

// Whole-value placeholders ("****", "<password>", "${TOKEN}") and prefixes ("your_key_here").
const PLACEHOLDER_FULL = /^(x+|\*+|\.+|<.*>|\[.*\]|\{.*\}|%.*%|\$\{.+\}|\$[A-Za-z_][A-Za-z0-9_]*|password|passw0rd|pass|pwd|secret|admin|root|postgres|mysql|test|user|guest|null|undefined|none|true|false)$/i;
const PLACEHOLDER_PREFIX = /^(your[_-]|changeme|change[_-]me|example|placeholder|dummy|redacted|todo|process\.env|os\.environ|env\(|\[REDACTED)/i;

export function isPlaceholder(v) {
  return PLACEHOLDER_FULL.test(v) || PLACEHOLDER_PREFIX.test(v) || /^(.)\1+$/.test(v);
}

export function entropy(s) {
  const freq = new Map();
  for (const c of s) freq.set(c, (freq.get(c) || 0) + 1);
  let h = 0;
  for (const n of freq.values()) {
    const p = n / s.length;
    h -= p * Math.log2(p);
  }
  return h;
}

export function fingerprint(secret) {
  return createHash('sha256').update(secret).digest('hex').slice(0, 10);
}

export function mask(secret) {
  if (secret.startsWith('-----BEGIN')) return secret.slice(0, secret.indexOf('KEY-----') + 8) + '…';
  if (secret.length <= 10) return `${secret.slice(0, 2)}…`;
  return `${secret.slice(0, Math.min(6, Math.floor(secret.length / 4)))}…${secret.slice(-2)}`;
}

/**
 * Find secrets in a chunk of text. Returns [{ detector, secret, index, length }]
 * where index/length cover just the secret (the capture group when there is one).
 * Overlapping matches keep the earliest/longest one.
 */
export function findSecrets(text, { detectors = DETECTORS, allow = new Set() } = {}) {
  const hits = [];
  for (const d of detectors) {
    // the "d" flag gives exact offsets for the capture group
    const re = d.group ? (d.reIndexed ||= new RegExp(d.re.source, `${d.re.flags}d`)) : d.re;
    re.lastIndex = 0;
    for (const m of text.matchAll(re)) {
      const secret = d.group ? m[d.group] : m[0];
      if (!secret) continue;
      if (d.validate && !d.validate(secret)) continue;
      if (secret.includes('[REDACTED:')) continue;
      const fp = fingerprint(secret);
      if (allow.has(fp)) continue;
      const index = d.group ? m.indices[d.group][0] : m.index;
      hits.push({ detector: d, secret, fp, index, length: secret.length });
    }
  }
  // earliest first, then longest, then specific detectors over the generic one
  hits.sort((a, b) => a.index - b.index || b.length - a.length || !!a.detector.generic - !!b.detector.generic);
  const out = [];
  let end = -1;
  for (const h of hits) {
    if (h.index < end) continue;
    out.push(h);
    end = h.index + h.length;
  }
  return out;
}

export function redactText(text, hits) {
  let out = '';
  let pos = 0;
  for (const h of hits) {
    out += text.slice(pos, h.index) + `[REDACTED:${h.detector.id}:${h.fp}]`;
    pos = h.index + h.length;
  }
  return out + text.slice(pos);
}

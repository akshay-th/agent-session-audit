#!/usr/bin/env node
import { homedir } from 'node:os';
import { resolve } from 'node:path';
import { parseArgs } from 'node:util';
import { fixPermissions, redactFile, scan } from '../src/scan.js';
import { sources } from '../src/sources.js';

const HELP = `agent-session-audit — find secrets and loose permissions in AI coding agent session data

Usage
  agent-session-audit [options]

Scans transcripts, history, shell snapshots and file backups written by Claude Code,
Codex, Gemini CLI, Qwen Code, Copilot CLI, OpenCode, Pi, Crush, Goose and Aider.

Options
      --agent <ids>       comma-separated: ${sources().map((s) => s.id).join(',')}
      --path <p>          also scan this file or directory (repeatable)
      --since <dur>       only files modified in the last 7d / 12h / 30m
      --allow <fp>        ignore a secret by fingerprint (repeatable)
      --fix-perms         chmod 600 files / 700 dirs that other users can read
      --redact            replace secrets in place with [REDACTED:<type>:<fingerprint>]
      --include-active    also redact files modified in the last 2 minutes
  -n, --dry-run           with --fix-perms/--redact: show what would change
      --show <n>          locations to print per secret (default 3)
      --json              machine-readable output (never contains the secrets)
  -h, --help

Exit code: 1 if secrets were found (after --redact: if any remain), else 0.
`;

const color = process.stdout.isTTY && !process.env.NO_COLOR;
const paint = (c) => (s) => (color ? `\x1b[${c}m${s}\x1b[0m` : String(s));
const red = paint(31);
const green = paint(32);
const yellow = paint(33);
const dim = paint(2);
const bold = paint(1);
const tilde = (p) => (p.startsWith(homedir()) ? `~${p.slice(homedir().length)}` : p);
const SEV = { high: red('high  '), medium: yellow('medium'), low: dim('low   ') };

function parseSince(s) {
  if (!s) return 0;
  const m = /^(\d+)\s*(m|h|d|w)$/.exec(s.trim());
  if (!m) throw new Error(`bad --since "${s}" (try 30m, 12h, 7d, 2w)`);
  return Date.now() - Number(m[1]) * { m: 60e3, h: 3600e3, d: 86400e3, w: 604800e3 }[m[2]];
}

const fmtBytes = (n) => (n > 1e9 ? `${(n / 1e9).toFixed(1)} GB` : n > 1e6 ? `${(n / 1e6).toFixed(1)} MB` : `${Math.round(n / 1e3)} KB`);

async function main(argv) {
  const { values } = parseArgs({
    args: argv,
    options: {
      agent: { type: 'string' },
      path: { type: 'string', multiple: true },
      since: { type: 'string' },
      allow: { type: 'string', multiple: true },
      'fix-perms': { type: 'boolean' },
      redact: { type: 'boolean' },
      'include-active': { type: 'boolean' },
      'dry-run': { type: 'boolean', short: 'n' },
      show: { type: 'string' },
      json: { type: 'boolean' },
      help: { type: 'boolean', short: 'h' },
    },
  });
  if (values.help) {
    process.stdout.write(HELP);
    return 0;
  }
  let list = sources();
  if (values.agent) {
    const want = new Set(values.agent.split(',').map((s) => s.trim().toLowerCase()));
    list = list.filter((s) => want.has(s.id));
  }
  for (const p of values.path || []) list.push({ agent: 'Custom', id: 'custom', root: resolve(p), include: [''], ownsRoot: false });
  const allow = new Set(values.allow || []);
  const show = Number(values.show ?? 3);
  const dryRun = values['dry-run'];

  const started = Date.now();
  const result = scan(list, { since: parseSince(values.since), allow });
  const secrets = [...result.secrets.values()].sort((a, b) => rank(a) - rank(b) || b.count - a.count);
  const exposed = result.files.filter((f) => f.exposure?.effective);
  const nominal = result.files.filter((f) => f.exposure?.nominal && !f.exposure.effective);
  const agents = [...new Set(result.files.map((f) => f.agent))];

  const actions = {};
  if (values['fix-perms']) actions.permissions = fixPermissions(list, { dryRun });
  if (values.redact) {
    const activeCutoff = Date.now() - 120e3;
    actions.redacted = [];
    actions.skippedActive = [];
    for (const f of result.files.filter((x) => x.hits.length)) {
      if (!values['include-active'] && f.mtimeMs > activeCutoff) {
        actions.skippedActive.push(f.path);
        continue;
      }
      actions.redacted.push(redactFile(f.path, { allow, dryRun }));
    }
  }

  if (values.json) {
    console.log(
      JSON.stringify(
        {
          scanned: { files: result.files.length, bytes: result.bytes, agents },
          secrets: secrets.map((s) => ({ ...s, agents: [...s.agents] })),
          permissions: { exposed: exposed.map((f) => ({ path: f.path, mode: f.mode.toString(8), group: f.exposure.group, other: f.exposure.other })), nominalOnly: nominal.length },
          skipped: result.skipped,
          actions,
        },
        null,
        2,
      ),
    );
  } else {
    report({ result, secrets, exposed, nominal, agents, show, actions, dryRun, ms: Date.now() - started });
  }

  const redactedAll = values.redact && !dryRun && actions.redacted.every((r) => !r.error) && !actions.skippedActive.length;
  return secrets.length && !redactedAll ? 1 : 0;
}

function rank(s) {
  return { high: 0, medium: 1, low: 2 }[s.severity];
}

function report({ result, secrets, exposed, nominal, agents, show, actions, dryRun, ms }) {
  if (!result.files.length) {
    console.log('No agent session data found.');
    return;
  }
  console.log(dim(`Scanned ${result.files.length} files (${fmtBytes(result.bytes)}) from ${agents.join(', ')} in ${(ms / 1000).toFixed(1)}s`));

  console.log(`\n${bold('Secrets')}`);
  if (!secrets.length) console.log(`  ${green('✓')} none found`);
  else {
    const total = secrets.reduce((n, s) => n + s.count, 0);
    console.log(dim(`  ${secrets.length} distinct secret(s), ${total} occurrence(s). Values are masked; fingerprints let you --allow known-public ones.`));
    for (const s of secrets) {
      const files = new Set(s.locations.map((l) => l.path)).size;
      console.log(`  ${SEV[s.severity]} ${bold(s.label.padEnd(26))} ${s.preview.padEnd(14)} ${String(s.count).padStart(4)}× in ${files}${s.locations.length >= 50 ? '+' : ''} file(s)  ${dim(`fp ${s.fp}`)}`);
      for (const l of s.locations.slice(0, show)) console.log(dim(`           ${tilde(l.path)}:${l.line}`));
    }
  }

  console.log(`\n${bold('Permissions')}`);
  if (process.platform === 'win32') console.log(dim('  skipped on Windows'));
  else if (!exposed.length) {
    console.log(`  ${green('✓')} no session files readable by other users${nominal.length ? dim(` (${nominal.length} have loose modes but sit in a private directory)`) : ''}`);
  } else {
    const byOther = exposed.filter((f) => f.exposure.other).length;
    console.log(`  ${red('✗')} ${exposed.length} file(s) readable by ${byOther ? 'any local user' : 'your group'}:`);
    for (const f of exposed.slice(0, show)) console.log(dim(`      ${f.mode.toString(8)}  ${tilde(f.path)}`));
    if (exposed.length > show) console.log(dim(`      … and ${exposed.length - show} more`));
  }

  if (result.skipped.length) console.log(dim(`\n${result.skipped.length} file(s) skipped (too large or unreadable)`));

  if (actions.permissions) {
    console.log(`\n${dryRun ? 'Would fix' : green('Fixed')} permissions on ${actions.permissions.length} path(s)`);
  }
  if (actions.redacted) {
    const ok = actions.redacted.filter((r) => !r.error);
    const n = ok.reduce((a, r) => a + r.replaced, 0);
    console.log(`\n${dryRun ? 'Would redact' : green('Redacted')} ${n} secret(s) in ${ok.length} file(s)`);
    for (const r of actions.redacted.filter((x) => x.error)) console.log(`  ${yellow('!')} ${tilde(r.path)}: ${r.error}`);
    if (actions.skippedActive.length) console.log(`  ${yellow('!')} ${actions.skippedActive.length} file(s) changed in the last 2 minutes were skipped (session may be active; use --include-active)`);
  }

  if (secrets.length && !actions.redacted) {
    console.log(`\n${bold('Next steps')}`);
    console.log('  1. Rotate the high-severity keys: anything that reached a transcript may also have reached the model provider and backups.');
    console.log('  2. Run with --redact to scrub local copies (add -n to preview).');
    if (exposed.length) console.log('  3. Run with --fix-perms so other local users cannot read session data.');
  } else if (exposed.length && !actions.permissions) {
    console.log(`\nRun with ${bold('--fix-perms')} to restrict access.`);
  }
}

main(process.argv.slice(2)).then(
  (code) => (process.exitCode = code),
  (e) => {
    console.error(`agent-session-audit: ${e.message}`);
    process.exitCode = 2;
  },
);

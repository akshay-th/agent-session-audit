import test from 'node:test';
import assert from 'node:assert/strict';
import { spawnSync } from 'node:child_process';
import { readFileSync, utimesSync } from 'node:fs';
import { fileURLToPath } from 'node:url';
import { FAKE, fakeAgentHome } from './helpers.js';

const CLI = fileURLToPath(new URL('../bin/cli.js', import.meta.url));

function run(home, args) {
  const env = { ...process.env, HOME: home, USERPROFILE: home, NO_COLOR: '1' };
  delete env.CLAUDE_CONFIG_DIR;
  delete env.CODEX_HOME;
  delete env.XDG_DATA_HOME;
  return spawnSync(process.execPath, [CLI, ...args], { env, encoding: 'utf8' });
}

test('report never prints secret values and exits 1', () => {
  const { home } = fakeAgentHome();
  const r = run(home, []);
  assert.equal(r.status, 1, r.stderr);
  assert.match(r.stdout, /GitHub token/);
  assert.match(r.stdout, /Anthropic API key/);
  for (const v of [FAKE.github, FAKE.anthropic, FAKE.dbPassword]) assert.ok(!r.stdout.includes(v));
  const j = run(home, ['--json']);
  for (const v of [FAKE.github, FAKE.anthropic, FAKE.dbPassword]) assert.ok(!j.stdout.includes(v));
  const out = JSON.parse(j.stdout);
  assert.deepEqual(out.scanned.agents.sort(), ['Claude Code', 'Codex']);
});

test('--agent filter and --allow', () => {
  const { home } = fakeAgentHome();
  const codex = JSON.parse(run(home, ['--agent', 'codex', '--json']).stdout);
  assert.deepEqual(codex.secrets.map((s) => s.detector), ['anthropic-key']);
  const allowed = run(home, ['--agent', 'codex', '--allow', codex.secrets[0].fp]);
  assert.equal(allowed.status, 0);
  assert.match(allowed.stdout, /none found/);
});

test('--redact skips active files, then cleans them with --include-active', () => {
  const { home, transcript } = fakeAgentHome();
  const first = run(home, ['--redact']);
  assert.equal(first.status, 1, 'fresh files are treated as active sessions');
  assert.match(first.stdout, /changed in the last 2 minutes were skipped/);
  assert.ok(readFileSync(transcript, 'utf8').includes(FAKE.github));

  const dry = run(home, ['--redact', '--include-active', '-n']);
  assert.match(dry.stdout, /Would redact 5 secret\(s\) in 3 file\(s\)/);
  assert.ok(readFileSync(transcript, 'utf8').includes(FAKE.github));

  const old = new Date(Date.now() - 3600e3);
  utimesSync(transcript, old, old);
  const real = run(home, ['--redact', '--include-active']);
  assert.equal(real.status, 0, real.stdout);
  assert.ok(!readFileSync(transcript, 'utf8').includes(FAKE.github));
  assert.equal(run(home, []).status, 0);
});

test('--path scans extra locations', () => {
  const { home, snapshot } = fakeAgentHome();
  const r = JSON.parse(run(home, ['--agent', 'none', '--path', snapshot, '--json']).stdout);
  assert.deepEqual(r.secrets.map((s) => s.detector), ['private-key']);
});

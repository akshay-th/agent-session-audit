import test from 'node:test';
import assert from 'node:assert/strict';
import { chmodSync, mkdtempSync, readFileSync, statSync, utimesSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { exposure, fixPermissions, redactFile, scan } from '../src/scan.js';
import { sources } from '../src/sources.js';
import { FAKE, fakeAgentHome } from './helpers.js';

const unix = process.platform !== 'win32';

test('scan finds secrets across agents, with line numbers and dedupe', () => {
  const { home, transcript, snapshot } = fakeAgentHome();
  const { secrets, files } = scan(sources({ home, env: {} }));
  const byType = [...secrets.values()].map((s) => `${s.detector}:${s.count}`).sort();
  assert.deepEqual(byType, ['anthropic-key:1', 'database-url:1', 'github-token:2', 'private-key:1']);
  const gh = [...secrets.values()].find((s) => s.detector === 'github-token');
  assert.deepEqual(gh.locations, [{ path: transcript, line: 2 }, { path: transcript, line: 3 }]);
  assert.deepEqual([...gh.agents], ['Claude Code']);
  const pem = [...secrets.values()].find((s) => s.detector === 'private-key');
  assert.deepEqual(pem.locations, [{ path: snapshot, line: 3 }]);
  assert.ok(files.some((f) => f.path.endsWith('binary.bin') && f.hits.length === 0), 'binary files are not scanned');
});

test('since filter skips old files', () => {
  const { home, transcript } = fakeAgentHome();
  const old = new Date(Date.now() - 10 * 86400e3);
  utimesSync(transcript, old, old);
  const { secrets } = scan(sources({ home, env: {} }), { since: Date.now() - 86400e3 });
  assert.ok(![...secrets.values()].some((s) => s.detector === 'github-token'));
});

test('exposure follows the directory chain', () => {
  const modes = { '/a': 0o755, '/a/private': 0o700, '/a/open': 0o755, '/': 0o755 };
  const modeOf = (d) => modes[d] ?? 0o755;
  assert.deepEqual(exposure('/a/private/f', 0o644, { modeOf }), { group: false, other: false, nominal: true, effective: false });
  assert.deepEqual(exposure('/a/open/f', 0o644, { modeOf }), { group: true, other: true, nominal: true, effective: true });
  assert.deepEqual(exposure('/a/open/f', 0o600, { modeOf }), { group: false, other: false, nominal: false, effective: false });
  const groupOnly = { ...modes, '/a/g': 0o750 };
  assert.equal(exposure('/a/g/f', 0o640, { modeOf: (d) => groupOnly[d] ?? 0o755 }).group, true);
  assert.equal(exposure('/a/g/f', 0o640, { modeOf: (d) => groupOnly[d] ?? 0o755 }).other, false);
});

test('redactFile keeps JSONL valid and removes every occurrence', () => {
  const { transcript } = fakeAgentHome();
  const r = redactFile(transcript);
  assert.equal(r.replaced, 3);
  const text = readFileSync(transcript, 'utf8');
  assert.ok(!text.includes(FAKE.github) && !text.includes(FAKE.dbPassword));
  for (const line of text.trim().split('\n')) assert.doesNotThrow(() => JSON.parse(line));
  assert.match(text, /\[REDACTED:github-token:[0-9a-f]{10}\]/);
  if (unix) assert.equal(statSync(transcript).mode & 0o777, 0o600);
  assert.equal(redactFile(transcript).replaced, 0, 'idempotent');
});

test('redactFile dry run leaves the file alone', () => {
  const { transcript } = fakeAgentHome();
  const before = readFileSync(transcript, 'utf8');
  assert.equal(redactFile(transcript, { dryRun: true }).replaced, 3);
  assert.equal(readFileSync(transcript, 'utf8'), before);
});

test('a corrupt JSONL line does not block redacting the others', () => {
  const dir = mkdtempSync(join(tmpdir(), 'audit-json-'));
  const p = join(dir, 'x.jsonl');
  writeFileSync(p, `{"partial": "line cut off by a crash\n${JSON.stringify({ a: FAKE.github })}\n`);
  const r = redactFile(p);
  assert.equal(r.replaced, 1);
  const lines = readFileSync(p, 'utf8').trim().split('\n');
  assert.equal(lines[0], '{"partial": "line cut off by a crash');
  assert.match(JSON.parse(lines[1]).a, /^\[REDACTED:github-token:/);
});

test('fixPermissions tightens agent dirs and keeps owner exec bits', { skip: !unix }, () => {
  const { home, claude, transcript, snapshot } = fakeAgentHome();
  chmodSync(claude, 0o755);
  chmodSync(join(claude, 'projects'), 0o755);
  chmodSync(transcript, 0o644);
  chmodSync(snapshot, 0o755);
  const list = sources({ home, env: {} });
  // $TMPDIR itself is private on macOS, so check the modes rather than effective exposure
  const looseBefore = scan(list).files.filter((f) => f.exposure.nominal).map((f) => f.path);
  assert.ok(looseBefore.includes(transcript));
  const dry = fixPermissions(list, { dryRun: true });
  assert.ok(dry.length >= 4);
  assert.equal(statSync(transcript).mode & 0o777, 0o644);
  fixPermissions(list);
  assert.equal(statSync(transcript).mode & 0o777, 0o600);
  assert.equal(statSync(snapshot).mode & 0o777, 0o700);
  assert.equal(statSync(claude).mode & 0o777, 0o700);
  assert.deepEqual(scan(list).files.filter((f) => f.exposure.nominal), []);
});

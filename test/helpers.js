import { mkdirSync, mkdtempSync, writeFileSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';

// Fake credentials, assembled at runtime so this file itself never matches a
// secret scanner (and GitHub push protection stays quiet).
const r = (n, chars = 'abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ23456789') => {
  let s = '';
  for (let i = 0; i < n; i++) s += chars[(i * 7 + n) % chars.length];
  return s;
};

export const FAKE = {
  github: ['gh', 'p_'].join('') + r(36),
  githubPat: ['github', '_pat_'].join('') + r(70),
  anthropic: ['sk', '-ant-', 'api03-'].join('') + r(90),
  openai: ['sk', '-proj-'].join('') + r(64),
  aws: ['AK', 'IA'].join('') + r(16, 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567'),
  awsSecret: r(40, 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789/+'),
  google: ['AI', 'za'].join('') + r(35),
  slack: ['xo', 'xb-'].join('') + '1234567890-' + r(24),
  stripeLive: ['sk', '_live_'].join('') + r(24),
  stripeTest: ['sk', '_test_'].join('') + r(24),
  npm: ['np', 'm_'].join('') + r(36),
  hf: ['h', 'f_'].join('') + r(34),
  jwt: ['ey', 'JhbGciOiJIUzI1NiJ9'].join('') + '.' + ['ey', 'JzdWIiOiIxMjM0In0'].join('') + '.' + r(43),
  dbPassword: 'Xk9' + r(14),
  pem: ['-----BEGIN ', 'OPENSSH PRIVATE KEY-----'].join('') + '\n' + r(64) + '\n' + r(64) + '\n' + ['-----END ', 'OPENSSH PRIVATE KEY-----'].join(''),
};

// A HOME with Claude Code and Codex session data containing FAKE secrets.
export function fakeAgentHome() {
  const home = mkdtempSync(join(tmpdir(), 'audit-home-'));
  const claude = join(home, '.claude');
  const proj = join(claude, 'projects', '-Users-me-app');
  mkdirSync(proj, { recursive: true });
  mkdirSync(join(claude, 'shell-snapshots'));
  const transcript = join(proj, 'session.jsonl');
  writeFileSync(
    transcript,
    [
      JSON.stringify({ type: 'user', message: { content: 'deploy it' } }),
      JSON.stringify({ type: 'user', toolUseResult: { stdout: `GITHUB_TOKEN=${FAKE.github}\nDATABASE_URL=postgres://app:${FAKE.dbPassword}@db:5432/app` } }),
      JSON.stringify({ type: 'assistant', message: { content: [{ type: 'text', text: `Using ${FAKE.github} again` }] } }),
    ].join('\n') + '\n',
  );
  const snapshot = join(claude, 'shell-snapshots', 'snapshot-zsh.sh');
  writeFileSync(snapshot, `export PATH=/usr/bin\nexport DEPLOY_KEY_FILE=~/.ssh/id\n${FAKE.pem}\n`);
  const codex = join(home, '.codex', 'sessions', '2026', '10', '28');
  mkdirSync(codex, { recursive: true });
  writeFileSync(join(codex, 'rollout-1.jsonl'), `${JSON.stringify({ type: 'response_item', payload: { output: `export ANTHROPIC_API_KEY=${FAKE.anthropic}` } })}\n`);
  writeFileSync(join(codex, 'binary.bin'), Buffer.from([0, 1, 2, 3, ...Buffer.from(FAKE.github)]));
  return { home, claude, transcript, snapshot };
}

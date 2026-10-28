import test from 'node:test';
import assert from 'node:assert/strict';
import { entropy, findSecrets, fingerprint, isPlaceholder, mask, redactText } from '../src/detectors.js';
import { FAKE } from './helpers.js';

const ids = (text) => findSecrets(text).map((h) => h.detector.id);

test('each provider pattern is detected', () => {
  const cases = {
    'github-token': [FAKE.github, FAKE.githubPat],
    'anthropic-key': [FAKE.anthropic],
    'openai-key': [FAKE.openai],
    'aws-access-key': [FAKE.aws],
    'google-api-key': [FAKE.google],
    'slack-token': [FAKE.slack],
    'stripe-live-key': [FAKE.stripeLive],
    'stripe-test-key': [FAKE.stripeTest],
    'npm-token': [FAKE.npm],
    'huggingface-token': [FAKE.hf],
    jwt: [FAKE.jwt],
    'private-key': [FAKE.pem],
  };
  for (const [id, values] of Object.entries(cases)) {
    for (const v of values) assert.deepEqual(ids(`before ${v} after`), [id], `${id}: ${v.slice(0, 12)}`);
  }
});

test('secrets inside JSON-escaped transcript text are cut at the escape', () => {
  const line = JSON.stringify({ type: 'user', content: `cat .env\nOPENAI_API_KEY=${FAKE.openai}\nDATABASE_URL=postgres://app:${FAKE.dbPassword}@db.internal:5432/app\n` });
  const hits = findSecrets(line);
  assert.deepEqual(hits.map((h) => h.detector.id), ['openai-key', 'database-url']);
  assert.equal(hits[0].secret, FAKE.openai);
  assert.equal(hits[1].secret, FAKE.dbPassword); // only the password, not the whole URL
  const red = redactText(line, hits);
  assert.doesNotThrow(() => JSON.parse(red));
  assert.ok(!red.includes(FAKE.openai) && !red.includes(FAKE.dbPassword));
  assert.match(red, /postgres:\/\/app:\[REDACTED:database-url:[0-9a-f]{10}\]@db\.internal/);
});

test('PEM blocks inside JSON strings (\\n escapes) are matched whole', () => {
  const line = JSON.stringify({ out: `key:\n${FAKE.pem}\ndone` });
  const [h] = findSecrets(line);
  assert.equal(h.detector.id, 'private-key');
  assert.ok(h.secret.endsWith('PRIVATE KEY-----'));
  assert.doesNotThrow(() => JSON.parse(redactText(line, [h])));
});

test('AWS secret key needs its label', () => {
  assert.deepEqual(ids(`aws_secret_access_key = ${FAKE.awsSecret}`), ['aws-secret-key']);
  assert.deepEqual(ids(`random ${FAKE.awsSecret}`), []);
});

test('generic assignments: entropy and placeholders', () => {
  assert.deepEqual(ids('MY_SERVICE_TOKEN=q8Zr2LmP0vXt7Ka9'), ['env-assignment']);
  for (const v of ['MY_SERVICE_TOKEN=your_token_here', 'API_KEY=xxxxxxxxxxxx', 'DB_PASSWORD=${DB_PASSWORD}', 'SECRET_KEY=changeme123', 'GITHUB_TOKEN=aaaaaaaaaaaa', 'AUTH_TOKEN=process.env.TOKEN']) {
    assert.deepEqual(ids(v), [], v);
  }
});

test('database URLs with placeholder passwords are ignored', () => {
  for (const pw of ['password', '<password>', '[YOUR-PASSWORD]', '****', 'postgres', '${PGPASSWORD}']) {
    assert.deepEqual(ids(`postgresql://postgres:${pw}@db.example.co:5432/postgres`), [], pw);
  }
  assert.deepEqual(ids(`mongodb+srv://admin:${FAKE.dbPassword}@cluster0.abc.mongodb.net/db`), ['database-url']);
});

test('specific detectors win over the generic assignment rule', () => {
  assert.deepEqual(ids(`ANTHROPIC_API_KEY=${FAKE.anthropic}`), ['anthropic-key']);
  assert.deepEqual(ids(`STRIPE_SECRET_KEY="${FAKE.stripeLive}"`), ['stripe-live-key']);
});

test('allowlist by fingerprint and already-redacted text', () => {
  assert.deepEqual(findSecrets(`k ${FAKE.google}`, { allow: new Set([fingerprint(FAKE.google)]) }), []);
  assert.deepEqual(ids('TOKEN=[REDACTED:github-token:0123456789]'), []);
});

test('mask never reveals more than a few characters', () => {
  const m = mask(FAKE.github);
  assert.ok(m.length < 12);
  assert.ok(!FAKE.github.slice(6, -2).includes(m.replace('…', '')));
  assert.equal(mask(FAKE.pem), '-----BEGIN OPENSSH PRIVATE KEY-----…');
});

test('helpers', () => {
  assert.ok(entropy('aaaaaaaa') < 1);
  assert.ok(entropy('q8Zr2LmP0vXt7Ka9') > 3.5);
  assert.ok(isPlaceholder('<your-key>'));
  assert.ok(!isPlaceholder('q8Zr2LmP0vXt'));
});

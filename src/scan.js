import { chmodSync, existsSync, lstatSync, readdirSync, readFileSync, renameSync, statSync, writeFileSync } from 'node:fs';
import { basename, dirname, join } from 'node:path';
import { findSecrets, mask, redactText } from './detectors.js';

/** Recursively list regular files (no symlinks) under the given paths. */
export function* walk(path, depth = 0) {
  let st;
  try {
    st = lstatSync(path);
  } catch {
    return;
  }
  if (st.isSymbolicLink()) return;
  if (st.isFile()) {
    yield { path, size: st.size, mtimeMs: st.mtimeMs, mode: st.mode & 0o777 };
    return;
  }
  if (!st.isDirectory() || depth > 25) return;
  let names;
  try {
    names = readdirSync(path);
  } catch {
    return;
  }
  for (const n of names) yield* walk(join(path, n), depth + 1);
}

export function* dirsUnder(path, depth = 0) {
  let st;
  try {
    st = lstatSync(path);
  } catch {
    return;
  }
  if (!st.isDirectory() || st.isSymbolicLink() || depth > 25) return;
  yield { path, mode: st.mode & 0o777 };
  let names = [];
  try {
    names = readdirSync(path);
  } catch {}
  for (const n of names) yield* dirsUnder(join(path, n), depth + 1);
}

const dirModeCache = new Map();
function dirMode(p) {
  if (!dirModeCache.has(p)) {
    try {
      dirModeCache.set(p, statSync(p).mode & 0o777);
    } catch {
      dirModeCache.set(p, 0);
    }
  }
  return dirModeCache.get(p);
}

/**
 * Who else can actually read this file? A 0644 file inside a 0700 directory is
 * not exposed, so every ancestor must be searchable by the same class too.
 */
export function exposure(path, mode, { modeOf = dirMode } = {}) {
  const res = { group: (mode & 0o040) !== 0, other: (mode & 0o004) !== 0 };
  const nominal = res.group || res.other;
  for (let d = dirname(path); ; d = dirname(d)) {
    const m = modeOf(d);
    if (!(m & 0o010)) res.group = false;
    if (!(m & 0o001)) res.other = false;
    if (!res.group && !res.other) break;
    if (dirname(d) === d) break;
  }
  return { ...res, nominal, effective: res.group || res.other };
}

function isBinary(buf) {
  const n = Math.min(buf.length, 8000);
  for (let i = 0; i < n; i++) if (buf[i] === 0) return true;
  return false;
}

function lineOf(text, index, starts) {
  // binary search over line start offsets
  let lo = 0;
  let hi = starts.length - 1;
  while (lo < hi) {
    const mid = (lo + hi + 1) >> 1;
    if (starts[mid] <= index) lo = mid;
    else hi = mid - 1;
  }
  return lo + 1;
}

function lineStarts(text) {
  const s = [0];
  for (let i = text.indexOf('\n'); i !== -1; i = text.indexOf('\n', i + 1)) s.push(i + 1);
  return s;
}

/**
 * Scan the given sources.
 * Returns { files: [...], secrets: Map<fp, {...}>, skipped: [...], bytes }
 */
export function scan(sourceList, { since = 0, maxSize = 256 * 1024 * 1024, allow = new Set(), platform = process.platform } = {}) {
  const files = [];
  const secrets = new Map();
  const skipped = [];
  let bytes = 0;
  dirModeCache.clear();
  for (const src of sourceList) {
    if (!existsSync(src.root)) continue;
    for (const item of src.include) {
      for (const f of walk(join(src.root, item))) {
        if (since && f.mtimeMs < since) continue;
        const rec = { ...f, agent: src.agent, hits: [] };
        if (platform !== 'win32') rec.exposure = exposure(f.path, f.mode);
        files.push(rec);
        if (f.size > maxSize) {
          skipped.push({ path: f.path, reason: `larger than ${Math.round(maxSize / 1048576)} MB` });
          continue;
        }
        let buf;
        try {
          buf = readFileSync(f.path);
        } catch (e) {
          skipped.push({ path: f.path, reason: e.code || e.message });
          continue;
        }
        bytes += buf.length;
        if (isBinary(buf)) continue;
        const text = buf.toString('utf8');
        const hits = findSecrets(text, { allow });
        if (!hits.length) continue;
        const starts = lineStarts(text);
        for (const h of hits) {
          const line = lineOf(text, h.index, starts);
          rec.hits.push({ fp: h.fp, detector: h.detector.id, line });
          let s = secrets.get(h.fp);
          if (!s) {
            s = { fp: h.fp, detector: h.detector.id, label: h.detector.label, severity: h.detector.severity, preview: mask(h.secret), count: 0, agents: new Set(), locations: [] };
            secrets.set(h.fp, s);
          }
          s.count++;
          s.agents.add(src.agent);
          if (s.locations.length < 50) s.locations.push({ path: f.path, line });
        }
      }
    }
  }
  return { files, secrets, skipped, bytes };
}

function validJson(text, path) {
  if (path.endsWith('.jsonl')) {
    return text.split('\n').map((l) => {
      if (!l.trim()) return true;
      try {
        JSON.parse(l);
        return true;
      } catch {
        return false;
      }
    });
  }
  if (path.endsWith('.json')) {
    try {
      JSON.parse(text);
      return [true];
    } catch {
      return [false];
    }
  }
  return null;
}

/**
 * Rewrite one file with every secret replaced by [REDACTED:<detector>:<fingerprint>].
 * JSON/JSONL files are checked so a redaction never turns a valid line invalid.
 * The file is replaced atomically and left at mode 0600.
 */
export function redactFile(path, { allow = new Set(), dryRun = false } = {}) {
  const text = readFileSync(path, 'utf8');
  const hits = findSecrets(text, { allow });
  if (!hits.length) return { path, replaced: 0 };
  const out = redactText(text, hits);
  const before = validJson(text, path);
  const after = validJson(out, path);
  if (before && after && before.some((ok, i) => ok && !after[i])) {
    return { path, replaced: 0, error: 'redaction would break JSON; left unchanged' };
  }
  if (!dryRun) {
    const tmp = join(dirname(path), `.${basename(path)}.redact-${process.pid}`);
    writeFileSync(tmp, out, { mode: 0o600 });
    renameSync(tmp, path);
    chmodSync(path, 0o600);
  }
  return { path, replaced: hits.length };
}

/**
 * Strip group/other access: files keep only their owner bits (so u+x survives),
 * directories become 0700. Extra --path locations are never touched.
 */
export function fixPermissions(sourceList, { dryRun = false } = {}) {
  const changed = [];
  for (const src of sourceList) {
    if (src.id === 'custom' || !existsSync(src.root)) continue;
    for (const item of src.include) {
      const top = join(src.root, item);
      for (const d of dirsUnder(top)) {
        if (d.mode & 0o077) {
          if (!dryRun) chmodSync(d.path, 0o700);
          changed.push({ path: d.path, from: d.mode, to: 0o700 });
        }
      }
      for (const f of walk(top)) {
        if (f.mode & 0o077) {
          const to = f.mode & 0o700;
          if (!dryRun) chmodSync(f.path, to);
          changed.push({ path: f.path, from: f.mode, to });
        }
      }
    }
    // the agent's own data dir (e.g. ~/.claude), never a shared one like $HOME
    if (src.ownsRoot !== false) {
      const m = statSync(src.root).mode & 0o777;
      if (m & 0o077) {
        if (!dryRun) chmodSync(src.root, 0o700);
        changed.push({ path: src.root, from: m, to: 0o700 });
      }
    }
  }
  return changed;
}

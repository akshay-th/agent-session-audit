# agent-session-audit

**Your AI coding agent keeps a full transcript of every session. Anything it ever saw is in there: `cat .env` output, pasted API keys, database URLs, private keys. This tool finds those secrets, checks who else can read the files, and redacts them in place.**

Coding agents write a lot of session data to your home directory:

| Agent | What's stored (and scanned) |
|---|---|
| Claude Code | `~/.claude/projects/**/*.jsonl` transcripts and subagent transcripts, `history.jsonl`, `file-history/` (copies of files it edited), `shell-snapshots/` (your shell env), `session-env/`, `todos/`, `paste-cache/`, `debug/` |
| Codex | `~/.codex/sessions/**`, `archived_sessions/`, `history.jsonl`, `log/` |
| Gemini CLI / Qwen Code | `~/.gemini/tmp/**`, `~/.qwen/tmp/**` |
| Copilot CLI | `~/.copilot/session-state/**`, logs |
| OpenCode, Crush, Goose | `~/.local/share/{opencode,crush,goose}/…` |
| Pi | `~/.pi/agent/sessions/**`. These were created world-readable (0644) until recently. |
| Aider | `~/.aider.chat.history.md`, `~/.aider.input.history`, plus any `--path` you add |

These files are plain text, never expire, and get swept into backups, dotfile syncs and support bundles. Other tools cover part of this: a macOS menu-bar app for Claude Code only, an MCP tool, and general-purpose secret scanners that don't know where agents keep data or how to edit JSONL safely. `agent-session-audit` is one CLI for all of these agents that **finds, fixes and redacts**.

## Usage

```bash
npx -y github:akshay-th/agent-session-audit            # report only
npx -y github:akshay-th/agent-session-audit --fix-perms
npx -y github:akshay-th/agent-session-audit --redact -n # preview
npx -y github:akshay-th/agent-session-audit --redact
```

```
Scanned 1846 files (1.2 GB) from Claude Code, Codex in 9.8s

Secrets
  6 distinct secret(s), 19 occurrence(s). Values are masked; fingerprints let you --allow known-public ones.
  high   GitHub token               ghp_MU…X6          8× in 3 file(s)  fp 1a3b9aa9a2
           ~/.claude/projects/-Users-me-app/4d8e….jsonl:209
           ~/.claude/file-history/3c7a…/8f1d2a7c90b3e4a1@v1:4
  high   Database URL with password Xk9p…SZ            6× in 3 file(s)  fp 7c21e0d4b9
           ~/.claude/projects/-Users-me-api/9b2e….jsonl:967
  high   Private key                -----BEGIN OPENSSH PRIVATE KEY-----…    1× in 1 file(s)  fp 8a68986908
           ~/.claude/shell-snapshots/snapshot-zsh-1790000000000.sh:3
  medium JWT                        eyJhbG…Qx          5× in 1 file(s)  fp e83f1a6c20
  ...

Permissions
  ✓ no session files readable by other users (1512 have loose modes but sit in a private directory)

Next steps
  1. Rotate the high-severity keys: anything that reached a transcript may also have reached the model provider and backups.
  2. Run with --redact to scrub local copies (add -n to preview).
```

## What it detects

Provider-specific patterns, all **high** severity unless noted:

- Private keys (PEM blocks, including inside JSON strings)
- AWS access key IDs, and secret keys when they appear with their label
- GitHub, GitLab, Anthropic, OpenAI, Slack, Stripe (live keys; test keys are *low*), npm, PyPI, Hugging Face and SendGrid tokens
- Google API keys and Slack webhooks (*medium*)
- JWTs (*medium*)
- Database URLs with passwords: Postgres, MySQL, MongoDB, Redis, AMQP, MSSQL. Only the password is redacted.
- `SOMETHING_SECRET=…` / `_TOKEN` / `_PASSWORD` / `_API_KEY` assignments with high-entropy values (*medium*)

Placeholders are ignored: `<password>`, `[YOUR-PASSWORD]`, `****`, `${TOKEN}`, `your_key_here`, `changeme`, and so on. Each distinct secret is reported once, with a count, a masked preview and a **fingerprint** (the first 10 hex digits of its SHA-256). Pass `--allow <fp>` for values you know are public, such as a Supabase anon key.

The output, including `--json`, **never contains a secret value**.

## Permissions, done properly

A `0644` transcript inside a `0700` directory isn't exposed, so the tool checks the **whole directory chain** for group and other access. It only reports files another local user could actually read. On macOS, home directories are often group-readable by `staff`, which every user belongs to, so this matters.

`--fix-perms` removes group and other access from the agents' data directories only: directories become `0700`, and files keep only the owner bits, so executable scripts stay executable. Paths you add with `--path` are never chmod-ed.

## Redaction, done safely

`--redact` replaces each secret with `[REDACTED:<type>:<fingerprint>]`. You can still tell which key was used where, so you know what to rotate.

- **JSON/JSONL stay valid.** Every line that parsed before must still parse, or the file is left untouched.
- **Live sessions are skipped.** Files modified in the last 2 minutes may belong to an active session, so they are left alone unless you pass `--include-active`.
- **Writes are atomic.** It writes a temp file in the same directory, renames it over the original, and sets mode `0600`. No backup copies are made, because backups would keep the secrets.
- `-n/--dry-run` shows counts without writing anything.

Redaction protects the local copies only. **Rotate the keys anyway.** They were already sent to the model provider as part of the conversation.

## Options

| Flag | |
|---|---|
| `--agent claude,codex,…` | Limit to some agents (`claude`, `codex`, `gemini`, `qwen`, `copilot`, `opencode`, `pi`, `crush`, `goose`, `aider`). |
| `--path <p>` | Also scan a file or directory (repeatable). |
| `--since 7d` | Only files modified recently (`30m`, `12h`, `7d`, `2w`). |
| `--allow <fp>` | Ignore a fingerprint (repeatable). |
| `--fix-perms` / `--redact` / `--include-active` / `-n` | See above. |
| `--show <n>` | Locations printed per secret (default 3). |
| `--json` | Machine-readable output. |

Exit code is `1` while secrets remain, so you can run it from cron or a shell hook:

```bash
# weekly: scrub sessions older than 2 minutes and tighten permissions
0 9 * * 1 npx -y github:akshay-th/agent-session-audit --redact --fix-perms >> ~/agent-audit.log
```

Respects `CLAUDE_CONFIG_DIR`, `CODEX_HOME` and `XDG_DATA_HOME`. No dependencies, Node 18.3+.

## License

MIT

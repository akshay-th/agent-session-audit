import { homedir } from 'node:os';
import { join } from 'node:path';

/**
 * Where coding agents keep transcripts and other session data that can contain
 * whatever passed through the conversation: pasted keys, `cat .env` output,
 * tool results, shell environment snapshots, copies of edited files.
 */
export function sources({ home = homedir(), env = process.env } = {}) {
  const claude = env.CLAUDE_CONFIG_DIR || join(home, '.claude');
  const codex = env.CODEX_HOME || join(home, '.codex');
  const xdgData = env.XDG_DATA_HOME || join(home, '.local', 'share');
  return [
    { agent: 'Claude Code', id: 'claude', root: claude, include: ['projects', 'history.jsonl', 'file-history', 'shell-snapshots', 'session-env', 'todos', 'paste-cache', 'debug'] },
    { agent: 'Codex', id: 'codex', root: codex, include: ['sessions', 'archived_sessions', 'history.jsonl', 'log'] },
    { agent: 'Gemini CLI', id: 'gemini', root: join(home, '.gemini'), include: ['tmp', 'history'] },
    { agent: 'Qwen Code', id: 'qwen', root: join(home, '.qwen'), include: ['tmp'] },
    { agent: 'Copilot CLI', id: 'copilot', root: join(home, '.copilot'), include: ['session-state', 'history-session-state', 'logs'] },
    { agent: 'OpenCode', id: 'opencode', root: join(xdgData, 'opencode'), include: ['storage', 'log'] },
    { agent: 'Pi', id: 'pi', root: join(home, '.pi', 'agent'), include: ['sessions'] },
    { agent: 'Crush', id: 'crush', root: join(xdgData, 'crush'), include: ['logs'] },
    { agent: 'Goose', id: 'goose', root: join(xdgData, 'goose'), include: ['sessions'] },
    { agent: 'Aider', id: 'aider', root: home, include: ['.aider.chat.history.md', '.aider.input.history'], ownsRoot: false },
  ];
}

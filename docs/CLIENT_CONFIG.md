# Client Configuration — Closing the Bypass Path (PRD §5.5 / §13.1)

**English** | [Bahasa Indonesia](./CLIENT_CONFIG.id.md)

> **A hard requirement, not optional.** Samar's security guarantee is **void** if
> the AI client can still read files / run commands through its built-in tools.
> If the LLM calls the built-in `fs_read`/`execute_bash` instead of Samar's tools,
> secrets never pass through the masking engine and leak as-is.

Goal: ensure **all** file & shell I/O goes through Samar's tools
(`samar_read_file`, `samar_get_env`), and the client's **built-in** I/O tools are
disabled.

## Principle

| Path | Desired state |
| --- | --- |
| `samar_read_file`, `samar_get_env`, `samar_write_file`, `samar_execute_command` (Samar) | **ACTIVE** |
| Built-in read tool (`fs_read`/`Read`) on sensitive files | **DENY** (force through Samar) |
| Built-in write tool (`fs_write`/`Write`/`Edit`) on sensitive files | **DENY** |
| Built-in exec tool (`shell`/`Bash`/`execute_bash`) | **DENY/Supervised** (route to `samar_execute_command`) |

## Registering the Samar server (file locations verified Oct 2026)

Build first: `go build -o bin/samar ./cmd/samar`. Ready-to-use templates live in
`docs/clients/` (`kiro.mcp.json`, `cursor.mcp.json`, `claude.mcp.json`).

| Client | Config location | Disable/approve field | Env syntax |
| --- | --- | --- | --- |
| **Kiro** | `.kiro/settings/mcp.json` (workspace) or `~/.kiro/settings/mcp.json` (user) | `disabled`, `autoApprove`, `disabledTools` | `${VAR}` |
| **Cursor** | `.cursor/mcp.json` (project) or `~/.cursor/mcp.json` (global) | none (configure in UI Settings) | `${env:VAR}` |
| **Claude Code** | `~/.claude.json` (via `claude mcp add`) or `.mcp.json` (project) | `permissions.deny`, `hooks.PreToolUse` | `${env:VAR}` |
| **Claude Desktop** | `claude_desktop_config.json` → `mcpServers` | none | none |

The base shape is the same across all clients: `mcpServers.<name>.{command,args,env}`. Note that **Claude Code** (CLI) does not read `mcpServers` from `~/.claude/settings.json`; register it using `claude mcp add` or a project `.mcp.json`.

### Disabling / restricting built-in tools — per-client steps

The mechanism differs per client (verified Oct 2026). A realistic note:
**fully denying** `fs_read`/Read will cripple the agent (it can't read code).
The practical approach: **deny built-in tools specifically for sensitive
files/paths** (`.env`, `*.pem`, `*.key`, secret dirs) so the agent is forced to
use Samar for those, then route execution through `samar_execute_command`. For
full isolation (deny all built-in read/write/exec), only do it if the agent is
truly meant to do I/O exclusively through Samar.

#### Kiro — `permissions.yaml` (deny-overrides)

##### ⚡ 1-Step Automated Setup (Recommended)
Run Samar's built-in idempotent setup command:
```bash
samar setup kiro
```
This automatically registers Samar in `~/.kiro/settings/mcp.json`, writes the deny rules to `~/.kiro/settings/permissions.yaml`, and creates agent steering instructions in `~/.kiro/steering/samar.md`.

##### 🛠️ Manual Hardening

Location: `~/.kiro/settings/permissions.yaml` (user) or workspace-scope.
`deny` always wins over `allow`. Capabilities: `fs_read`, `fs_write`, `shell`.

```yaml
rules:
  # Close the built-in path to sensitive files -> force through Samar.
  - capability: fs_read
    match: ["**/.env", "**/.env.*", "**/*.pem", "**/*.key", "secrets/**"]
    effect: deny
  - capability: fs_write
    match: ["**/.env", "**/.env.*", "**/*.pem", "**/*.key", "secrets/**"]
    effect: deny
  # Full isolation (optional, aggressive): disable the built-in shell entirely.
  # - capability: shell
    # effect: deny
```

Also: set **Settings → Agent → Agent Autonomy = Supervised** so built-in actions
still prompt for confirmation. The MCP `disabledTools` field does NOT disable
Kiro's built-in tools — it only applies to MCP server tools.

See also the dedicated step-by-step guide: [`KIRO_SETUP.md`](./KIRO_SETUP.md).

#### Claude Code — Automated & Manual Hardening

##### ⚡ 1-Step Automated Setup (Recommended)
Run Samar's built-in idempotent setup command:
```bash
samar setup claude-code
```
This registers the server, configures recursive glob deny rules, installs the Bash secret guard hook (`~/.claude/hooks/guard-secrets.py`), and appends routing rules to `~/.claude/CLAUDE.md`.

##### 🛠️ Manual Hardening (Closing the Bash Bypass)
Claude Code requires three synchronized layers to prevent built-in tool bypasses:

1. **Glob Deny Rules** (`~/.claude/settings.json`): Use `**/` globs so nested `.env` files (e.g. `packages/api/.env`) are covered:
```json
{
  "permissions": {
    "deny": [
      "Read(**/.env)", "Read(**/.env.*)", "Read(**/*.pem)", "Read(**/*.key)",
      "Edit(**/.env)", "Edit(**/.env.*)", "Write(**/.env)", "Write(**/.env.*)"
    ]
  }
}
```

2. **PreToolUse Hook for Bash** (`guard-secrets.py`):
When `Read` is denied, agents often fallback to built-in `Bash` (`cat .env`, `grep KEY .env`, `source .env`). Register a PreToolUse hook in `settings.json` that catches shell commands accessing secret files and redirects the agent to Samar tools:
```json
"hooks": {
  "PreToolUse": [
    {
      "matcher": "Bash",
      "hooks": [{ "type": "command", "command": "python3 $HOME/.claude/hooks/guard-secrets.py", "timeout": 10 }]
    }
  ]
}
```

3. **Steering Instructions** (`~/.claude/CLAUDE.md`):
Instructs the agent and subagents to proactively select `mcp__samar__*` tools for any credentialed files.

Ready-to-use template files are available in [`docs/clients/claude/`](./clients/claude/).

#### Cursor — Automated & UI Settings

##### ⚡ 1-Step Automated Setup
Run Samar's built-in idempotent setup command:
```bash
samar setup cursor
```
This automatically registers Samar in `~/.cursor/mcp.json` and installs steering rules in `~/.cursor/rules/samar.mdc` and `~/.cursorrules`.

##### 🛠️ Manual UI Settings
Cursor has no config file field to disable built-in tools. Open
**Settings → (Features/Tools / Agent)** and turn off the built-in
filesystem/terminal tools there. Verify with the "Quick verification" steps below.

#### Google Antigravity (Gemini) — Automated Setup

##### ⚡ 1-Step Automated Setup
Run Samar's built-in idempotent setup command:
```bash
samar setup antigravity
```
This automatically registers Samar in `~/.gemini/config/mcp_config.json` and installs privacy steering rules in `~/.gemini/config/rules/samar.md`.

> **If a client offers no adequate deny mechanism:** Samar still runs, but the
> security model drops to *best-effort + disclosure* (the server prints a warning
> to stderr). Treat it as not yet safe for production secrets until the built-in
> path to sensitive files is genuinely closed.

## Quick verification

1. Run the server; confirm the security warning appears on stderr.
2. Ask the AI to read a test `.env` file containing a fake secret.
3. Confirm the output contains a `__SAMAR_SECRET_XXXX__` token, **not** the real
   value.
4. Try asking the AI to read the same file **without** naming a Samar tool. If
   the real value appears, the built-in tool is still active → close that path.

## Egress allowlist (outbound path)

Before restoring a secret, Samar blocks detected URLs outside the allowlist and known network tools whose destination it cannot identify. The check only reads the command text; a shell command can still use a network path the check misses. Samar therefore asks for MCP elicitation before restoring a token. If the client cannot request approval, Samar rejects the command. Setting `SAMAR_REQUIRE_CONFIRM=off` skips approval and can expose real secrets. Samar reloads the host lists below automatically.

- **Global:** `~/.samar/allowlist` (fallback: `~/.safeenv/allowlist`)
- **Per-project:** `.samar/allowlist` (fallback: `.safeenv/allowlist`) at the project root

### Resolution modes (§13.3)

- **Union (default):** `effective = global ∪ per-project`.
- **Strict:** set env `SAMAR_STRICT_ALLOWLIST=1`. Per-project **narrows** the
  global → `effective = global ∩ per-project`. If the project file is empty/absent,
  strict falls back to the global list as-is. Use strict for projects that may
  only contact a subset of trusted organizational hosts.

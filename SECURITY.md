# Security Policy

## Supported Versions

Only the latest release of Samar MCP Server receives security patches and updates.

| Version | Supported          |
| ------- | ------------------ |
| 1.x.x   | :white_check_mark: |
| < 1.0.0 | :x:                |

---

## Reporting a Vulnerability

We take the security of Samar seriously. Samar is designed as a defense-in-depth privacy middleware to safeguard secrets from leaking into LLM contexts and external unauthorized destinations.

If you believe you have found a security vulnerability in Samar (such as a token evasion technique, regex bypass, or egress allowlist leak):

1. **Do NOT open a public GitHub issue.**
2. Report the vulnerability privately via [GitHub Security Advisories](https://github.com/hanifalkauni/samar-mcp/security/advisories/new) or directly contact the maintainer:
   - **Maintainer:** Hanif Al-Kauni
   - **Repository:** `https://github.com/hanifalkauni/samar-mcp`
3. Please include:
   - A detailed description of the vulnerability.
   - Minimal reproduction steps or sample file / prompt causing the bypass.
   - Affected Samar version and environment details.
   - Expected vs. actual behavior.

### Response Timeline
- **Initial acknowledgment:** within 48 hours.
- **Triage & validation:** within 5 business days.
- **Fix and release:** prioritized based on severity and coordinated disclosure.

---

## Security Scope & Threat Model

### In Scope
- **Regex / Detector Bypasses**: Sensitive patterns that evade detection in supported formats (`.env`, config files, standard key formats) when following Samar guidelines.
- **Token Leakage**: Situations where reversible tokens (`__SAMAR_SECRET_<ID>__`) resolve to real secrets in unauthorized outbound directions.
- **Egress Allowlist Evasion**: Bypassing outbound network restrictions or DNS/host validation during `samar_execute_command`.
- **Fail-Closed Failures**: Mutated or missing tokens failing to abort with hard errors during disk restoration or command execution.

### Out of Scope
- Local attacks where an unprivileged attacker already has full root/administrator access or local debugger attachments to the process memory.
- Secrets intentionally piped into arbitrary shell scripts via native non-MCP terminal access (outside Samar's oversight).
- Custom proprietary tokens with non-standard randomness not matching any configured regexes and outside `.env` style key-value declarations.

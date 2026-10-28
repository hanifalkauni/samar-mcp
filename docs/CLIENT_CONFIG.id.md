# Konfigurasi Client — Penutupan Jalur Bypass (PRD §5.5 / §13.1)

[English](./CLIENT_CONFIG.md) | **Bahasa Indonesia**

> **Syarat mutlak, bukan opsional.** Jaminan keamanan Samar **batal** jika
> client AI masih bisa membaca file / menjalankan perintah lewat tool bawaannya.
> Jika LLM memanggil `fs_read`/`execute_bash` bawaan alih-alih tool Samar,
> secret tidak pernah melewati masking engine dan bocor apa adanya.

Tujuan: pastikan **semua** I/O file & shell melewati tool Samar
(`samar_read_file`, `samar_get_env`), dan tool I/O **bawaan** client dinonaktifkan.

## Prinsip

| Jalur | Status yang diinginkan |
| --- | --- |
| `samar_read_file`, `samar_get_env`, `samar_write_file`, `samar_execute_command` (Samar) | **AKTIF** |
| Tool baca bawaan (`fs_read`/`Read`) pada file sensitif | **DENY** (paksa lewat Samar) |
| Tool tulis bawaan (`fs_write`/`Write`/`Edit`) pada file sensitif | **DENY** |
| Tool exec bawaan (`shell`/`Bash`/`execute_bash`) | **DENY/Supervised** (arahkan ke `samar_execute_command`) |

## Registrasi server Samar (lokasi file terverifikasi, Okt 2026)

Build dulu: `go build -o bin/samar ./cmd/samar`. Template siap pakai ada di
`docs/clients/` (`kiro.mcp.json`, `cursor.mcp.json`, `claude.mcp.json`).

| Client | Lokasi config | Field disable/approve | Env syntax |
| --- | --- | --- | --- |
| **Kiro** | `.kiro/settings/mcp.json` (workspace) atau `~/.kiro/settings/mcp.json` (user) | `disabled`, `autoApprove`, `disabledTools` | `${VAR}` |
| **Cursor** | `.cursor/mcp.json` (project) atau `~/.cursor/mcp.json` (global) | tidak ada (atur di UI Settings) | `${env:VAR}` |
| **Claude Code** | `~/.claude.json` (via `claude mcp add`) atau `.mcp.json` (project) | `permissions.deny`, `hooks.PreToolUse` | `${env:VAR}` |
| **Claude Desktop** | `claude_desktop_config.json` → `mcpServers` | tidak ada | tidak ada |

Shape dasar sama di seluruh client: `mcpServers.<nama>.{command,args,env}`. Perhatikan bahwa **Claude Code** (CLI) tidak membaca `mcpServers` dari `~/.claude/settings.json`; daftarkan memakai perintah `claude mcp add` atau file root `.mcp.json`.

### Menonaktifkan / membatasi tool bawaan — langkah per client

Mekanisme berbeda per client (terverifikasi Okt 2026). Catatan realistis:
men-**deny total** `fs_read`/Read akan melumpuhkan agen (tak bisa baca kode).
Pendekatan praktis: **deny tool bawaan khusus untuk file/jalur sensitif**
(`.env`, `*.pem`, `*.key`, dir secret) sehingga agen terpaksa memakai Samar
untuk itu, lalu arahkan eksekusi lewat `samar_execute_command`. Untuk isolasi
penuh (deny semua baca/tulis/exec bawaan), lakukan hanya bila agen memang hanya
boleh ber-I/O lewat Samar.

#### Kiro — `permissions.yaml` (deny-overrides)

##### ⚡ Setup Otomatis 1 Perintah (Direkomendasikan)
Jalankan perintah setup bawaan Samar yang idempoten:
```bash
samar setup kiro
```
Perintah ini otomatis mendaftarkan server Samar di `~/.kiro/settings/mcp.json`, memasang aturan deny di `~/.kiro/settings/permissions.yaml`, dan menambahkan panduan pengalihan agen ke `~/.kiro/steering/samar.md`.

##### 🛠️ Pengamanan Manual

Lokasi: `~/.kiro/settings/permissions.yaml` (user) atau workspace-scope.
`deny` selalu menang atas `allow`. Capability: `fs_read`, `fs_write`, `shell`.

```yaml
rules:
  # Tutup jalur bawaan ke file sensitif -> paksa lewat Samar.
  - capability: fs_read
    match: ["**/.env", "**/.env.*", "**/*.pem", "**/*.key", "secrets/**"]
    effect: deny
  - capability: fs_write
    match: ["**/.env", "**/.env.*", "**/*.pem", "**/*.key", "secrets/**"]
    effect: deny
  # Isolasi penuh (opsional, agresif): matikan shell bawaan sepenuhnya.
  # - capability: shell
    # effect: deny
```

Tambahan: set **Settings → Agent → Agent Autonomy = Supervised** agar aksi
bawaan tetap minta konfirmasi. Field MCP `disabledTools` TIDAK mematikan tool
bawaan Kiro — itu hanya untuk tool server MCP.

#### Claude Code — Pengamanan Otomatis & Manual

##### ⚡ Setup Otomatis 1 Perintah (Direkomendasikan)
Jalankan perintah setup bawaan Samar yang idempoten:
```bash
samar setup claude-code
```
Perintah ini otomatis mendaftarkan server MCP, mengonfigurasi aturan deny rekursif (`**/`), memasang hook pencegah bypass Bash (`~/.claude/hooks/guard-secrets.py`), dan menambahkan instruksi perutean agen ke `~/.claude/CLAUDE.md`.

##### 🛠️ Pengamanan Manual (Menutup Celah Bypass Bash)
Claude Code memerlukan tiga lapisan sinkron untuk mencegah agen membypass tool Samar:

1. **Aturan Glob Deny** (`~/.claude/settings.json`): Gunakan glob `**/` agar file `.env` di subfolder (misal `packages/api/.env`) ikut terlindungi:
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

2. **Hook PreToolUse untuk Bash** (`guard-secrets.py`):
Ketika `Read` di-deny, model AI cenderung beralih memakai tool `Bash` bawaan (`cat .env`, `grep KEY .env`, `source .env`). Daftarkan hook PreToolUse di `settings.json` yang mencegat perintah shell menyentuh file secret dan mengarahkannya kembali ke Samar:
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

3. **Instruksi Pengarah Agen** (`~/.claude/CLAUDE.md`):
Menginstruksikan Claude Code dan subagent untuk secara proaktif memilih tool `mcp__samar__*` setiap kali berinteraksi dengan file kredensial.

Template lengkap tersedia di folder [`docs/clients/claude/`](./clients/claude/).

#### Cursor — Setup Otomatis & UI Settings

##### ⚡ Setup Otomatis 1 Perintah
Jalankan perintah setup bawaan Samar yang idempoten:
```bash
samar setup cursor
```
Perintah ini otomatis mendaftarkan Samar di `~/.cursor/mcp.json` serta memasang aturan pengarah agen di `~/.cursor/rules/samar.mdc` dan `~/.cursorrules`.

##### 🛠️ Pengaturan UI Manual
Cursor tidak punya field file untuk menonaktifkan tool bawaan. Buka
**Settings → (Features/Tools / Agent)** dan matikan tool filesystem/terminal
bawaan di sana. Verifikasi dengan langkah "Verifikasi cepat" di bawah.

#### Google Antigravity (Gemini) — Setup Otomatis

##### ⚡ Setup Otomatis 1 Perintah
Jalankan perintah setup bawaan Samar yang idempoten:
```bash
samar setup antigravity
```
Perintah ini otomatis mendaftarkan Samar di `~/.gemini/config/mcp_config.json` dan memasang aturan privasi agen di `~/.gemini/config/rules/samar.md`.

> **Jika client tidak menyediakan mekanisme deny yang memadai:** Samar tetap
> berjalan tetapi model keamanan turun jadi *best-effort + disclosure* (server
> mencetak peringatan ke stderr). Perlakukan sebagai belum aman untuk secret
> produksi sampai jalur bawaan ke file sensitif benar-benar tertutup.

## Verifikasi cepat

1. Jalankan server; pastikan peringatan keamanan muncul di stderr.
2. Minta AI membaca sebuah file `.env` uji berisi secret palsu.
3. Konfirmasi output berisi token `__SAMAR_SECRET_XXXX__`, **bukan** nilai asli.
4. Coba minta AI membaca file yang sama **tanpa** menyebut tool Samar. Jika
   nilai asli muncul, berarti tool bawaan masih aktif → tutup jalur itu.

## Egress allowlist (jalur outbound)

Sebelum memulihkan secret, Samar memblokir URL non-allowlist yang terdeteksi dan utilitas jaringan yang tujuannya tidak dapat dikenali. Pemeriksaan ini hanya membaca teks command; shell masih dapat memakai jalur jaringan yang tidak terlihat. Karena itu, Samar meminta persetujuan melalui MCP elicitation sebelum memulihkan token. Jika client tidak mendukung elicitation, command ditolak. `SAMAR_REQUIRE_CONFIRM=off` melewati persetujuan dan dapat membuka secret asli. Samar memuat ulang daftar host di bawah ini secara otomatis.

- **Global:** `~/.samar/allowlist` (fallback: `~/.safeenv/allowlist`)
- **Per-project:** `.samar/allowlist` (fallback: `.safeenv/allowlist`) di root project

### Mode resolusi (§13.3)

- **Union (default):** `effective = global ∪ per-project`.
- **Strict:** set env `SAMAR_STRICT_ALLOWLIST=1`. Per-project **mempersempit**
  global → `effective = global ∩ per-project`. Bila file project kosong/absen,
  strict jatuh ke global apa adanya. Gunakan strict untuk proyek yang hanya
  boleh menghubungi subset host tepercaya organisasi.

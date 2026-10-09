# Konfigurasi Client — Penutupan Jalur Bypass (PRD §5.5 / §13.1)

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
| **Claude Code** | `~/.claude/settings.json` → `mcpServers` | tidak ada (permission settings) | `${env:VAR}` |

Shape dasar sama di ketiganya: `mcpServers.<nama>.{command,args,env}`.

### Menonaktifkan / membatasi tool bawaan — langkah per client

Mekanisme berbeda per client (terverifikasi Okt 2026). Catatan realistis:
men-**deny total** `fs_read`/Read akan melumpuhkan agen (tak bisa baca kode).
Pendekatan praktis: **deny tool bawaan khusus untuk file/jalur sensitif**
(`.env`, `*.pem`, `*.key`, dir secret) sehingga agen terpaksa memakai Samar
untuk itu, lalu arahkan eksekusi lewat `samar_execute_command`. Untuk isolasi
penuh (deny semua baca/tulis/exec bawaan), lakukan hanya bila agen memang hanya
boleh ber-I/O lewat Samar.

#### Kiro — `permissions.yaml` (deny-overrides)

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

#### Claude Code — `~/.claude/settings.json` (`permissions.deny`)

`deny` → `ask` → `allow`; `deny` adalah hard gate (tanpa prompt/override).

```json
{
  "permissions": {
    "deny": [
      "Read(./.env)", "Read(./.env.*)", "Read(./**/*.pem)", "Read(./**/*.key)",
      "Edit(./.env)", "Write(./.env)"
    ]
  }
}
```

Untuk isolasi penuh, tambahkan `"Bash(*)"` ke `deny` (agresif: mematikan semua
shell bawaan; pastikan `samar_execute_command` menutupi kebutuhan eksekusi).

#### Cursor — UI Settings

Cursor tidak punya field file untuk menonaktifkan tool bawaan. Buka
**Settings → (Features/Tools / Agent)** dan matikan tool filesystem/terminal
bawaan di sana. Verifikasi dengan langkah "Verifikasi cepat" di bawah.

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

`samar_execute_command` memblokir pengiriman secret ke host eksternal yang tidak
ada di allowlist (PRD §5.6). Daftar host (satu per baris, `#` komentar) dibaca
dari dua lokasi dan di-reload otomatis tanpa restart:

- **Global:** `~/.samar/allowlist` (fallback: `~/.safeenv/allowlist`)
- **Per-project:** `.samar/allowlist` (fallback: `.safeenv/allowlist`) di root project

### Mode resolusi (§13.3)

- **Union (default):** `effective = global ∪ per-project`.
- **Strict:** set env `SAMAR_STRICT_ALLOWLIST=1`. Per-project **mempersempit**
  global → `effective = global ∩ per-project`. Bila file project kosong/absen,
  strict jatuh ke global apa adanya. Gunakan strict untuk proyek yang hanya
  boleh menghubungi subset host tepercaya organisasi.

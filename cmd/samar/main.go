// Command samar adalah entry point Samar MCP Server.
//
// Ini adalah composition root: satu-satunya tempat implementasi konkret
// dirakit menjadi graf dependency. Lapisan lain hanya bergantung pada
// interface, sesuai Dependency Inversion.
package main

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/hanifalkauni/samar-mcp/internal/allowlist"
	"github.com/hanifalkauni/samar-mcp/internal/audit"
	"github.com/hanifalkauni/samar-mcp/internal/detector"
	"github.com/hanifalkauni/samar-mcp/internal/idgen"
	"github.com/hanifalkauni/samar-mcp/internal/leakscan"
	"github.com/hanifalkauni/samar-mcp/internal/masking"
	"github.com/hanifalkauni/samar-mcp/internal/policy"
	"github.com/hanifalkauni/samar-mcp/internal/restore"
	"github.com/hanifalkauni/samar-mcp/internal/safeio"
	"github.com/hanifalkauni/samar-mcp/internal/server"
	"github.com/hanifalkauni/samar-mcp/internal/vault"
)

const version = "1.3.0"

// policyGuard mengadaptasi *policy.Policy ke interface server.Guard.
type policyGuard struct {
	p *policy.Policy
}

// Evaluate menerjemahkan Decision policy menjadi server.GuardResult.
func (g *policyGuard) Evaluate(command string, containsToken bool) server.GuardResult {
	d := g.p.EvaluateCommand(command, containsToken)
	if !d.Allow {
		return server.GuardResult{Allow: false, Err: policy.DenyError(d)}
	}
	return server.GuardResult{Allow: true, NeedsConfirmation: d.NeedsConfirmation, Hosts: d.Hosts}
}

// getEnvWithFallback mengambil nilai environment variable dengan prioritas utama
// key baru (SAMAR_*), lalu fallback ke key lama (SAFEENV_*).
func getEnvWithFallback(primary, fallback string) string {
	if v := os.Getenv(primary); v != "" {
		return v
	}
	return os.Getenv(fallback)
}

// confirmer menegakkan human-in-the-loop berdasarkan env SAMAR_REQUIRE_CONFIRM (atau SAFEENV_REQUIRE_CONFIRM):
//   - "" (default) / "elicit": minta persetujuan via MCP elicitation sebelum
//                command bertoken; kegagalan/tidak didukung berarti ditolak.
//   - "off" : auto-approve secara eksplisit; hanya gunakan bila command tepercaya.
//   - "deny"   : tolak SEMUA command bertoken tanpa prompt (fail-closed).
type confirmer struct {
	mode string
	srv  *mcpserver.MCPServer // untuk mode elicit; di-set setelah server dibuat
}

func newConfirmer() *confirmer {
	mode := getEnvWithFallback("SAMAR_REQUIRE_CONFIRM", "SAFEENV_REQUIRE_CONFIRM")
	if mode == "" {
		mode = "elicit"
	}
	return &confirmer{mode: mode}
}

// confirmationOff true hanya bila pengguna secara eksplisit menonaktifkan prompt.
func (c *confirmer) confirmationOff() bool {
	return c.mode == "off"
}

func (c *confirmer) Confirm(ctx context.Context, command string, hosts []string) bool {
	switch c.mode {
	case "off":
		return true
	case "deny":
		return false
	case "elicit":
		if c.srv == nil {
			return false // tak bisa minta konfirmasi -> fail-closed
		}
		msg := fmt.Sprintf("Samar: command berikut membawa secret yang akan direstorasi sebelum dijalankan:\n%s\nHost jaringan yang terdeteksi: %v. Daftar kosong tidak membuktikan command tidak memakai jaringan. Izinkan?", command, hosts)
		res, err := c.srv.RequestElicitation(ctx, mcp.ElicitationRequest{
			Params: mcp.ElicitationParams{
				Mode:            "form",
				Message:         msg,
				RequestedSchema: map[string]any{"type": "object", "properties": map[string]any{}},
			},
		})
		if err != nil || res == nil {
			return false // elicitation gagal / tak didukung -> fail-closed
		}
		return res.Action == mcp.ElicitationResponseActionAccept
	default: // Nilai kosong atau tidak dikenal fail-closed.
		return false
	}
}

// auditAdapter menautkan audit.Logger ke interface server.Auditor.
type auditAdapter struct {
	log      *audit.Logger
	warnOnce sync.Once
}

// newAuditor menginisialisasi audit logger per sesi.
// File dan direktori dibuat secara lazy saat event audit pertama ditulis.
// Lokasi default: ~/.samar/audit/<project-slug>-<hash8>/<ts>.jsonl
// Dapat di-override via env SAMAR_AUDIT_DIR / SAFEENV_AUDIT_DIR.
func newAuditor() server.Auditor {
	dir := resolveAuditDir("")
	sess := time.Now().Format("20060102-150405")
	w := newLazyFileWriter(dir, sess+".jsonl")
	l := audit.New(w, audit.Options{SessionID: sess, Gen: idgen.NewCryptoGen(), HashChain: true})
	return &auditAdapter{log: l}
}

// Event memformat panggilan server menjadi audit.Event.
func (a *auditAdapter) Event(eventType, tool, decision, reason string) {
	if err := a.log.Log(audit.Event{
		EventType: audit.EventType(eventType),
		Tool:      tool,
		Decision:  decision,
		Reason:    reason,
		Actor:     "llm_client",
	}); err != nil {
		a.warnOnce.Do(func() {
			fmt.Fprintf(os.Stderr, "samar: audit logging failed; audit events may be missing: %v\n", err)
		})
	}
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version", "-v", "version":
			fmt.Println("samar", version)
			return
		case "--help", "-h", "help":
			printHelp()
			return
		case "setup":
			targetClient := ""
			if len(os.Args) > 2 {
				targetClient = os.Args[2]
			}
			switch targetClient {
			case "claude-code", "claude":
				if err := runSetupClaudeCode("", ""); err != nil {
					fmt.Fprintln(os.Stderr, "samar setup claude-code: error:", err)
					os.Exit(1)
				}
				return
			case "kiro":
				if err := runSetupKiro("", ""); err != nil {
					fmt.Fprintln(os.Stderr, "samar setup kiro: error:", err)
					os.Exit(1)
				}
				return
			case "cursor":
				if err := runSetupCursor("", ""); err != nil {
					fmt.Fprintln(os.Stderr, "samar setup cursor: error:", err)
					os.Exit(1)
				}
				return
			case "antigravity", "gemini", "agy":
				if err := runSetupAntigravity("", ""); err != nil {
					fmt.Fprintln(os.Stderr, "samar setup antigravity: error:", err)
					os.Exit(1)
				}
				return
			case "all":
				if err := runSetupAll(""); err != nil {
					fmt.Fprintln(os.Stderr, "samar setup all: error:", err)
					os.Exit(1)
				}
				return
			default:
				fmt.Println(`Pemakaian: samar setup <target>

Target yang didukung:
  claude-code   Setup otomatis Claude Code (settings.json deny rules, guard hook, CLAUDE.md)
  kiro          Setup otomatis Kiro IDE (mcp.json, permissions.yaml deny rules, steering)
  cursor        Setup otomatis Cursor IDE (mcp.json, .cursorrules / samar.mdc)
  antigravity   Setup otomatis Antigravity / Gemini (mcp_config.json, rules/samar.md)
  all           Setup seluruh client yang didukung sekaligus`)
				os.Exit(1)
			}
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "samar: fatal:", err)
		os.Exit(1)
	}
}

// printHelp menulis ringkasan pemakaian ke stdout.
func printHelp() {
	fmt.Printf(`samar %s — Samar MCP Server

Server Model Context Protocol (stdio) yang memasking kredensial sebelum
mencapai LLM (inbound) dan merestorasinya di bawah policy keamanan (outbound).

PEMAKAIAN
  samar                    Jalankan server MCP di stdio (mode normal).
  samar setup <target>     Setup otomatis integrasi client MCP:
                             claude-code (deny rules, hook, CLAUDE.md)
                             kiro        (mcp.json, permissions.yaml deny rules, steering)
                             cursor      (mcp.json, .cursorrules / samar.mdc)
                             antigravity (mcp_config.json, rules/samar.md)
                             all         (seluruh client di atas)
  samar --version          Cetak versi.
  samar --help             Cetak bantuan ini.

ENVIRONMENT
  SAMAR_AUDIT_DIR              Direktori log audit kustom (override).
                               Default: ~/.samar/audit/<project-slug>-<hash8>/
  SAMAR_STRICT_ALLOWLIST=1     Egress allowlist strict: per-project mempersempit
                               global (global ∩ project). Default: union.
	SAMAR_REQUIRE_CONFIRM        Konfirmasi untuk command yang membawa token:
	                               "" / "elicit" (DEFAULT) = minta persetujuan MCP
	                               (fail-closed bila client tak mendukung).
	                               "off" = auto-approve secara eksplisit (berisiko).
	                               "deny" = selalu tolak command bertoken.
  SAMAR_ENTROPY=1              Aktifkan deteksi entropi (OPT-IN): tangkap secret
                               berentropi tinggi tanpa kata-kunci. Default nonaktif
                               (bisa menambah false-positive pada hash/UUID/base64).
  SAMAR_PII=1                  Aktifkan deteksi PII (OPT-IN): email, kartu kredit
                               (Luhn), IBAN (mod-97), IPv4. Default nonaktif.

POLA KUSTOM (detektor, jalur inbound)
  Global:      ~/.samar/patterns (fallback: ~/.safeenv/patterns)
  Per-project: ./.samar/patterns (fallback: ./.safeenv/patterns)
  Satu regex per baris; '#' komentar; grup bernama 'secret' = mask grup saja.

ALLOWLIST (egress, jalur outbound)
  Global:      ~/.samar/allowlist (fallback: ~/.safeenv/allowlist)
  Per-project: ./.samar/allowlist (fallback: ./.safeenv/allowlist)

Konfigurasi client & penonaktifan tool bawaan: lihat docs/CLIENT_CONFIG.md
`, version)
}

func run() error {
	// Disclosure keamanan ke STDERR (bukan stdout; stdout dipakai transport MCP).
	// PRD §5.5 / §13.1: server tidak dapat memaksa client mematikan tool I/O
	// bawaannya, jadi pengguna harus sadar risikonya.
	printRiskDisclosure()

	// --- Rakit graf dependency (composition root) ---
	v := vault.New(idgen.NewCryptoGen())

	// Pola kustom yang didefinisikan pengguna via file config (hot-reload),
	// untuk secret berformat khusus/organisasi yang tak dikenali rule-set
	// default. Global (~/.samar/patterns) + per-project (./.samar/patterns),
	// dengan fallback nama lama (~/.safeenv, ./.safeenv) demi kompatibilitas.
	homeDir, _ := os.UserHomeDir()
	customDet := detector.NewCustomRegex(5*time.Second,
		filepath.Join(homeDir, ".samar", "patterns"),
		filepath.Join(homeDir, ".safeenv", "patterns"),
		filepath.Join(".samar", "patterns"),
		filepath.Join(".safeenv", "patterns"),
	)

	// Detektor dasar: dotenv + regex bawaan + pola kustom pengguna.
	detectors := []detector.Detector{
		detector.NewDotEnv(), // .env* -> mask semua value (PRD §7)
		detector.NewRegex(),  // pola kredensial dikenal (PRD §5.2)
		customDet,            // pola kustom pengguna (hot-reload via config)
	}

	// Mode entropi OPT-IN (SAMAR_ENTROPY=1): jaring tambahan untuk secret
	// "telanjang" berentropi tinggi yang tak punya kata-kunci. Nonaktif secara
	// default karena berpotensi false-positive (hash, UUID, base64 data).
	if getEnvWithFallback("SAMAR_ENTROPY", "SAFEENV_ENTROPY") == "1" {
		detectors = append(detectors, detector.NewEntropy())
		fmt.Fprintln(os.Stderr, "samar: MODE ENTROPI AKTIF — deteksi secret berentropi tinggi tanpa kata-kunci (bisa menambah false-positive).")
	}

	// Mode PII OPT-IN (SAMAR_PII=1): deteksi data pribadi (email, kartu kredit
	// via Luhn, IBAN via mod-97, IPv4). Nonaktif secara default karena PII lebih
	// rentan false-positive; validasi struktural menekan sebagian besar.
	if getEnvWithFallback("SAMAR_PII", "SAFEENV_PII") == "1" {
		detectors = append(detectors, detector.NewPii())
		fmt.Fprintln(os.Stderr, "samar: MODE PII AKTIF — deteksi email/kartu kredit/IBAN/IPv4 (bisa menambah false-positive).")
	}

	det := detector.NewRegistry(detectors...)
	engine := masking.New(det, v)

	// --- Jalur outbound (M1) ---
	rst := restore.New(v)

	// Allowlist egress bertingkat: global (user config) + per-project (.samar).
	// Mode strict (project mempersempit global) via SAMAR_STRICT_ALLOWLIST=1.
	globalAllow := filepath.Join(homeDir, ".samar", "allowlist")
	projectAllow := filepath.Join(".samar", "allowlist")
	strict := getEnvWithFallback("SAMAR_STRICT_ALLOWLIST", "SAFEENV_STRICT_ALLOWLIST") == "1"
	al := allowlist.NewLayered(5*time.Second, strict, []string{globalAllow, filepath.Join(homeDir, ".safeenv", "allowlist")}, []string{projectAllow, filepath.Join(".safeenv", "allowlist")})

	guard := &policyGuard{p: policy.New(al)}

	// --- Audit log per sesi (PRD §10) ---
	auditor := newAuditor()

	// config_reload audit: dipicu saat file allowlist / pola kustom berubah
	// & dimuat ulang.
	if auditor != nil {
		al.SetOnReload(func() {
			auditor.Event("config_reload", "allowlist", "allow", "reloaded")
		})
		customDet.SetOnReload(func() {
			auditor.Event("config_reload", "custom_patterns", "allow", "reloaded")
		})
	}

	conf := newConfirmer()
	if conf.confirmationOff() {
		fmt.Fprintln(os.Stderr, "samar: KONFIRMASI MANUSIA DINONAKTIFKAN SECARA EKSPLISIT. Semua command bertoken berjalan tanpa persetujuan; pemeriksaan host adalah heuristik dan dapat melewatkan jalur jaringan. Gunakan hanya untuk command tepercaya.")
	}

	// Safety-net runtime: verifikasi terakhir bahwa output tool tak membocorkan
	// secret vault; secret yang bocor di-tokenisasi ulang (ditambal). Memakai
	// vault yang sama (Secrets() + Tokenize). Selalu aktif (defense-in-depth).
	safetyNet := leakscan.NewSafetyNet(v, v)

	samarSrv, err := server.New(server.Deps{
		Masker:    engine,
		Files:     safeio.OSFileReader{},
		Env:       safeio.OSEnvReader{},
		Writer:    safeio.OSFileWriter{},
		Runner:    safeio.OSCommandRunner{},
		Restorer:  rst,
		Guard:     guard,
		Audit:     auditor,
		Confirm:   conf,
		SafetyNet: safetyNet,
	})
	if err != nil {
		return err
	}

	mcpSrv := mcpserver.NewMCPServer("Samar", version)
	conf.srv = mcpSrv // mode elicit butuh ref server untuk RequestElicitation
	samarSrv.Register(mcpSrv)

	// Blok selama sesi; vault hangus saat proses berhenti (zero-persistence).
	return mcpserver.ServeStdio(mcpSrv)
}

// printRiskDisclosure menulis peringatan ke stderr. Non-blocking (stdio MCP
// tidak punya TTY interaktif).
func printRiskDisclosure() {
	const msg = `Samar MCP Server ` + version + `
PERINGATAN KEAMANAN: Samar hanya melindungi I/O yang melewati tool-nya.
Jika client masih bisa membaca file sensitif lewat tool BAWAAN-nya, secret
bocor tanpa masking. Terapkan deny-selektif tool bawaan pada file sensitif
(.env, *.pem, dsb.) — lihat docs/CLIENT_CONFIG.md.
`
	fmt.Fprint(os.Stderr, msg)
}

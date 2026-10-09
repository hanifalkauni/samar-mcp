// Command safeenv adalah entry point SafeEnv MCP Server (M0).
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
	"time"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/hanifalkauni/samar-mcp/internal/allowlist"
	"github.com/hanifalkauni/samar-mcp/internal/audit"
	"github.com/hanifalkauni/samar-mcp/internal/detector"
	"github.com/hanifalkauni/samar-mcp/internal/idgen"
	"github.com/hanifalkauni/samar-mcp/internal/masking"
	"github.com/hanifalkauni/samar-mcp/internal/policy"
	"github.com/hanifalkauni/samar-mcp/internal/restore"
	"github.com/hanifalkauni/samar-mcp/internal/safeio"
	"github.com/hanifalkauni/samar-mcp/internal/server"
	"github.com/hanifalkauni/samar-mcp/internal/vault"
)

const version = "1.1.0"

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

// confirmer menegakkan human-in-the-loop berdasarkan env SAFEENV_REQUIRE_CONFIRM:
//   - "" (default) / "off" : auto-approve. Allowlist fail-closed TETAP jadi
//                lapisan utama (host asing tetap diblokir). Konfirmasi adalah
//                defense-in-depth kedua yang di-OPT-IN karena elicitation belum
//                didukung luas oleh client MCP. Peringatan dicetak ke stderr.
//   - "elicit" : minta persetujuan interaktif ke client via MCP elicitation;
//                fail-closed bila client tak mendukung / error / bukan "accept".
//   - "deny"   : tolak SEMUA aksi jaringan bertoken tanpa prompt (fail-closed).
type confirmer struct {
	mode string
	srv  *mcpserver.MCPServer // untuk mode elicit; di-set setelah server dibuat
}

func newConfirmer() *confirmer {
	return &confirmer{mode: os.Getenv("SAFEENV_REQUIRE_CONFIRM")}
}

// confirmationOff true bila konfirmasi manusia tidak aktif (default/off).
func (c *confirmer) confirmationOff() bool {
	return c.mode == "" || c.mode == "off"
}

func (c *confirmer) Confirm(ctx context.Context, command string, hosts []string) bool {
	switch c.mode {
	case "deny":
		return false
	case "elicit":
		if c.srv == nil {
			return false // tak bisa minta konfirmasi -> fail-closed
		}
		msg := fmt.Sprintf("SafeEnv: perintah akan mengirim secret (ter-unmask) ke host %v. Izinkan?", hosts)
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
	default: // "" (default) dan "off": auto-approve (allowlist tetap fail-closed).
		return true
	}
}

// auditAdapter menautkan audit.Logger ke interface server.Auditor.
type auditAdapter struct {
	log *audit.Logger
}

// newAuditor membuat file audit per sesi di .safeenv/audit/<ts>.jsonl.
// Bila direktori tak bisa dibuat, audit menjadi no-op yang aman (tidak boleh
// menggagalkan server), ditandai lewat stderr.
func newAuditor() server.Auditor {
	dir := filepath.Join(".safeenv", "audit")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		fmt.Fprintln(os.Stderr, "safeenv: audit nonaktif (tidak bisa membuat dir):", err)
		return nil // server.New akan memasang no-op
	}
	sess := time.Now().Format("20060102-150405")
	f, err := os.OpenFile(filepath.Join(dir, sess+".jsonl"), os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		fmt.Fprintln(os.Stderr, "safeenv: audit nonaktif (tidak bisa membuka file):", err)
		return nil
	}
	l := audit.New(f, audit.Options{SessionID: sess, Gen: idgen.NewCryptoGen(), HashChain: true})
	return &auditAdapter{log: l}
}

// Event memformat panggilan server menjadi audit.Event.
func (a *auditAdapter) Event(eventType, tool, decision, reason string) {
	_ = a.log.Log(audit.Event{
		EventType: audit.EventType(eventType),
		Tool:      tool,
		Decision:  decision,
		Reason:    reason,
		Actor:     "llm_client",
	})
}

func main() {
	for _, a := range os.Args[1:] {
		switch a {
		case "--version", "-v", "version":
			fmt.Println("safeenv", version)
			return
		case "--help", "-h", "help":
			printHelp()
			return
		}
	}
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "safeenv: fatal:", err)
		os.Exit(1)
	}
}

// printHelp menulis ringkasan pemakaian ke stdout.
func printHelp() {
	fmt.Printf(`safeenv %s — SafeEnv MCP Server

Server Model Context Protocol (stdio) yang memasking kredensial sebelum
mencapai LLM (inbound) dan merestorasinya di bawah policy keamanan (outbound).

PEMAKAIAN
  safeenv                 Jalankan server MCP di stdio (mode normal).
  safeenv --version       Cetak versi.
  safeenv --help          Cetak bantuan ini.

ENVIRONMENT
  SAFEENV_STRICT_ALLOWLIST=1   Egress allowlist strict: per-project mempersempit
                               global (global ∩ project). Default: union.
  SAFEENV_REQUIRE_CONFIRM      Konfirmasi manusia untuk kirim secret ke jaringan:
                               "" / "off" (DEFAULT) = auto-approve (allowlist tetap
                               fail-closed; peringatan dicetak ke stderr).
                               "elicit" = minta persetujuan via MCP elicitation
                               (fail-closed bila client tak mendukung).
                               "deny" = selalu tolak aksi jaringan bertoken.

ALLOWLIST (egress, jalur outbound)
  Global:      ~/.safeenv/allowlist
  Per-project: ./.safeenv/allowlist

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

	det := detector.NewRegistry(
		detector.NewDotEnv(), // .env* -> mask semua value (PRD §7)
		detector.NewRegex(),  // pola kredensial dikenal (PRD §5.2)
	)
	engine := masking.New(det, v)

	// --- Jalur outbound (M1) ---
	rst := restore.New(v)

	// Allowlist egress bertingkat: global (user config) + per-project (.safeenv).
	// Mode strict (project mempersempit global) via SAFEENV_STRICT_ALLOWLIST=1.
	home, _ := os.UserHomeDir()
	globalAllow := filepath.Join(home, ".safeenv", "allowlist")
	projectAllow := filepath.Join(".safeenv", "allowlist")
	strict := os.Getenv("SAFEENV_STRICT_ALLOWLIST") == "1"
	al := allowlist.NewLayered(5*time.Second, strict, []string{globalAllow}, []string{projectAllow})

	guard := &policyGuard{p: policy.New(al)}

	// --- Audit log per sesi (PRD §10) ---
	auditor := newAuditor()

	// config_reload audit: dipicu saat file allowlist berubah & dimuat ulang.
	if auditor != nil {
		al.SetOnReload(func() {
			auditor.Event("config_reload", "allowlist", "allow", "reloaded")
		})
	}

	conf := newConfirmer()
	if conf.confirmationOff() {
		fmt.Fprintln(os.Stderr, "safeenv: KONFIRMASI MANUSIA NONAKTIF (default). Secret ke host yang SUDAH di allowlist dikirim tanpa prompt. Allowlist tetap memblokir host asing. Untuk lapisan konfirmasi: set SAFEENV_REQUIRE_CONFIRM=elicit (butuh client yang mendukung MCP elicitation).")
	}

	safeEnv, err := server.New(server.Deps{
		Masker:   engine,
		Files:    safeio.OSFileReader{},
		Env:      safeio.OSEnvReader{},
		Writer:   safeio.OSFileWriter{},
		Runner:   safeio.OSCommandRunner{},
		Restorer: rst,
		Guard:    guard,
		Audit:    auditor,
		Confirm:  conf,
	})
	if err != nil {
		return err
	}

	mcpSrv := mcpserver.NewMCPServer("SafeEnv", version)
	conf.srv = mcpSrv // mode elicit butuh ref server untuk RequestElicitation
	safeEnv.Register(mcpSrv)

	// Blok selama sesi; vault hangus saat proses berhenti (zero-persistence).
	return mcpserver.ServeStdio(mcpSrv)
}

// printRiskDisclosure menulis peringatan ke stderr. Non-blocking (stdio MCP
// tidak punya TTY interaktif).
func printRiskDisclosure() {
	const msg = `SafeEnv MCP Server ` + version + `
PERINGATAN KEAMANAN: SafeEnv hanya melindungi I/O yang melewati tool-nya.
Jika client masih bisa membaca file sensitif lewat tool BAWAAN-nya, secret
bocor tanpa masking. Terapkan deny-selektif tool bawaan pada file sensitif
(.env, *.pem, dsb.) — lihat docs/CLIENT_CONFIG.md.
`
	fmt.Fprint(os.Stderr, msg)
}

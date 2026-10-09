// Package server merakit tool MCP Samar dan mengekspos handler-nya. Server
// bergantung pada abstraksi (Masker, FileReader, EnvReader) yang di-inject,
// bukan implementasi konkret (Dependency Inversion), sehingga tiap handler
// dapat ditest tanpa proses MCP atau filesystem nyata.
package server

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/mark3labs/mcp-go/mcp"
	mcpserver "github.com/mark3labs/mcp-go/server"

	"github.com/hanifalkauni/samar-mcp/internal/masking"
	"github.com/hanifalkauni/samar-mcp/internal/safeio"
)

// Masker adalah kontrak minimal yang dibutuhkan handler dari mesin masking
// (Interface Segregation). Dipenuhi oleh *masking.Engine.
type Masker interface {
	Mask(filename, content string) masking.Result
}

// Restorer membalik token menjadi secret asli pada jalur outbound. Dipenuhi
// oleh *restore.Restorer. Mengembalikan error bila ada token korup (fail-closed).
type Restorer interface {
	Restore(content string) (string, error)
	HasTruncatedToken(content string) bool
}

// GuardResult membawa keputusan policy ke handler, termasuk apakah aksi butuh
// konfirmasi manusia (§5.6/§13.2).
type GuardResult struct {
	Allow             bool
	NeedsConfirmation bool
	Hosts             []string
	Err               error // non-nil bila diblokir (deny)
}

// Guard mengevaluasi policy exfiltration untuk sebuah command. Dipenuhi oleh
// *policy.Policy (via adapter di composition root).
type Guard interface {
	// Evaluate mengembalikan hasil terstruktur: Allow + apakah perlu konfirmasi.
	Evaluate(command string, containsToken bool) GuardResult
}

// Confirmer meminta persetujuan manusia untuk unmask-and-execute yang menyentuh
// jaringan (§5.6/§13.2). Dipenuhi oleh adapter elicitation di composition root.
// OPSIONAL: bila nil, server memakai autoApproveConfirmer (perilaku v1.0.0:
// allowlist fail-closed tanpa prompt), sehingga menambahkan Confirmer tidak
// memaksa klien yang belum mendukung elicitation.
type Confirmer interface {
	// Confirm mengembalikan true bila manusia menyetujui pengiriman secret ke hosts.
	// ctx membawa sesi client (dibutuhkan adapter elicitation).
	Confirm(ctx context.Context, command string, hosts []string) bool
}

// autoApproveConfirmer adalah default: menyetujui (perilaku kompatibel v1.0.0).
type autoApproveConfirmer struct{}

func (autoApproveConfirmer) Confirm(_ context.Context, _ string, _ []string) bool { return true }

// Auditor mencatat kejadian keamanan (PRD §10). OPSIONAL: bila nil, server
// memakai no-op sehingga audit tidak pernah menggagalkan operasi inti.
type Auditor interface {
	Event(eventType, tool, decision, reason string)
}

// nopAuditor adalah Auditor default yang tidak melakukan apa-apa.
type nopAuditor struct{}

func (nopAuditor) Event(_, _, _, _ string) {}

// Deps mengumpulkan dependency Samar. Dependency inbound (Masker/Files/Env)
// wajib; dependency outbound (Writer/Runner/Restorer/Guard) wajib untuk M1.
// Audit & Confirm opsional (default no-op / auto-approve).
type Deps struct {
	Masker   Masker
	Files    safeio.FileReader
	Env      safeio.EnvReader
	Writer   safeio.FileWriter
	Runner   safeio.CommandRunner
	Restorer Restorer
	Guard    Guard
	Audit    Auditor
	Confirm  Confirmer
}

// Samar memegang dependency terwiring dan mendaftarkan tool ke MCPServer.
type Samar struct {
	deps Deps
}

// SafeEnv adalah alias kompatibilitas untuk Samar.
type SafeEnv = Samar

// New memvalidasi dependency dan mengembalikan Samar siap pakai.
func New(d Deps) (*Samar, error) {
	if d.Masker == nil || d.Files == nil || d.Env == nil {
		return nil, fmt.Errorf("server: Deps inbound tidak lengkap (Masker/Files/Env wajib)")
	}
	if d.Writer == nil || d.Runner == nil || d.Restorer == nil || d.Guard == nil {
		return nil, fmt.Errorf("server: Deps outbound tidak lengkap (Writer/Runner/Restorer/Guard wajib)")
	}
	if d.Audit == nil {
		d.Audit = nopAuditor{}
	}
	if d.Confirm == nil {
		d.Confirm = autoApproveConfirmer{}
	}
	return &Samar{deps: d}, nil
}

// Register memasang keempat tool Samar pada server MCP.
func (s *Samar) Register(m *mcpserver.MCPServer) {
	m.AddTool(
		mcp.NewTool("samar_read_file",
			mcp.WithDescription("Baca file lokal, masking kredensial sensitif, kembalikan teks tersanitasi. Nilai asli tidak pernah dikirim ke LLM."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("path", mcp.Required(), mcp.Description("Path file yang dibaca.")),
		),
		s.handleReadFile,
	)
	m.AddTool(
		mcp.NewTool("samar_get_env",
			mcp.WithDescription("Baca variabel environment sistem dengan value termasking. Nama variabel TIDAK dimasking."),
			mcp.WithReadOnlyHintAnnotation(true),
			mcp.WithString("env_var", mcp.Description("Nama variabel tunggal. Kosongkan untuk membaca seluruh environment.")),
		),
		s.handleGetEnv,
	)
	m.AddTool(
		mcp.NewTool("samar_write_file",
			mcp.WithDescription("Tulis file: token placeholder direstorasi ke secret asli sebelum ditulis ke disk. Dibatalkan bila ada token korup."),
			mcp.WithString("path", mcp.Required(), mcp.Description("Path file tujuan.")),
			mcp.WithString("content", mcp.Required(), mcp.Description("Isi file; boleh mengandung token __SAMAR_SECRET_...__.")),
		),
		s.handleWriteFile,
	)
	m.AddTool(
		mcp.NewTool("samar_execute_command",
			mcp.WithDescription("Jalankan perintah shell lokal. Token di-unmask setelah lolos policy exfiltration; perintah yang mengirim secret ke host non-allowlist diblokir."),
			mcp.WithString("command", mcp.Required(), mcp.Description("Perintah shell; boleh mengandung token __SAMAR_SECRET_...__.")),
			mcp.WithString("cwd", mcp.Description("Direktori kerja opsional.")),
		),
		s.handleExecuteCommand,
	)
}

// handleReadFile mengimplementasikan tool samar_read_file.
func (s *Samar) handleReadFile(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError("parameter 'path' wajib berupa string"), nil
	}
	content, err := s.deps.Files.ReadFile(path)
	if err != nil {
		// Pesan error aman: tidak membocorkan isi file.
		return mcp.NewToolResultErrorf("gagal membaca file: %v", err), nil
	}
	res := s.deps.Masker.Mask(path, content)
	s.deps.Audit.Event("read", "samar_read_file", "allow", "ok")
	return mcp.NewToolResultText(res.Masked), nil
}

// handleGetEnv mengimplementasikan tool samar_get_env. Value dimasking; NAMA
// variabel sengaja dibiarkan apa adanya (PRD §5.4 catatan).
func (s *Samar) handleGetEnv(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	if name := req.GetString("env_var", ""); name != "" {
		val, ok := s.deps.Env.Lookup(name)
		if !ok {
			return mcp.NewToolResultErrorf("variabel environment %q tidak ditemukan", name), nil
		}
		masked := s.deps.Masker.Mask(".env", name+"="+val)
		s.deps.Audit.Event("read", "samar_get_env", "allow", "ok")
		return mcp.NewToolResultText(masked.Masked), nil
	}

	// Seluruh environment: masking tiap value, output deterministik (urut nama).
	all := s.deps.Env.All()
	keys := make([]string, 0, len(all))
	for k := range all {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	for _, k := range keys {
		// Masking per-baris dengan konteks .env agar seluruh value diperlakukan rahasia.
		line := s.deps.Masker.Mask(".env", k+"="+all[k])
		b.WriteString(line.Masked)
		b.WriteByte('\n')
	}
	s.deps.Audit.Event("read", "samar_get_env", "allow", "all_env")
	return mcp.NewToolResultText(b.String()), nil
}

// handleWriteFile mengimplementasikan tool samar_write_file: restorasi token ->
// secret asli (fail-closed bila korup), lalu tulis ke disk.
func (s *Samar) handleWriteFile(_ context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	path, err := req.RequireString("path")
	if err != nil {
		return mcp.NewToolResultError("parameter 'path' wajib berupa string"), nil
	}
	content, err := req.RequireString("content")
	if err != nil {
		return mcp.NewToolResultError("parameter 'content' wajib berupa string"), nil
	}
	// Deteksi dini token terpotong untuk pesan yang jelas (PRD §7).
	if s.deps.Restorer.HasTruncatedToken(content) {
		s.deps.Audit.Event("abort", "samar_write_file", "abort", "truncated_token")
		return mcp.NewToolResultError("corrupted token placeholder detected: token terpotong/termutasi; penulisan dibatalkan"), nil
	}
	restored, err := s.deps.Restorer.Restore(content)
	if err != nil {
		s.deps.Audit.Event("abort", "samar_write_file", "abort", "corrupted_token")
		return mcp.NewToolResultErrorf("%v", err), nil
	}
	if werr := s.deps.Writer.WriteFile(path, restored); werr != nil {
		return mcp.NewToolResultErrorf("gagal menulis file: %v", werr), nil
	}
	s.deps.Audit.Event("write", "samar_write_file", "allow", "ok")
	return mcp.NewToolResultText(fmt.Sprintf("ok: %d byte ditulis ke %s", len(restored), path)), nil
}

// handleExecuteCommand mengimplementasikan tool samar_execute_command. Urutan
// WAJIB: cek token korup -> evaluasi policy exfiltration (SEBELUM unmask) ->
// unmask -> eksekusi (PRD §5.6).
func (s *Samar) handleExecuteCommand(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
	command, err := req.RequireString("command")
	if err != nil {
		return mcp.NewToolResultError("parameter 'command' wajib berupa string"), nil
	}
	cwd := req.GetString("cwd", "")

	if s.deps.Restorer.HasTruncatedToken(command) {
		return mcp.NewToolResultError("corrupted token placeholder detected: token terpotong/termutasi; eksekusi dibatalkan"), nil
	}

	// Policy dievaluasi pada command yang MASIH bertoken, sebelum unmask.
	containsToken := s.commandHasToken(command)
	gr := s.deps.Guard.Evaluate(command, containsToken)
	if !gr.Allow {
		reason := "blocked"
		if gr.Err != nil {
			reason = gr.Err.Error()
		}
		s.deps.Audit.Event("policy_block", "samar_execute_command", "deny", reason)
		if gr.Err != nil {
			return mcp.NewToolResultErrorf("%v", gr.Err), nil
		}
		return mcp.NewToolResultError("exfiltration policy: eksekusi dibatalkan"), nil
	}

	// Human-in-the-loop (§5.6/§13.2): bila secret akan keluar ke jaringan,
	// minta konfirmasi SEBELUM unmask. Default Confirmer auto-approve.
	if gr.NeedsConfirmation {
		if !s.deps.Confirm.Confirm(ctx, command, gr.Hosts) {
			s.deps.Audit.Event("policy_block", "samar_execute_command", "deny", "human_denied")
			return mcp.NewToolResultError("eksekusi dibatalkan: konfirmasi manusia ditolak untuk pengiriman secret ke jaringan"), nil
		}
		s.deps.Audit.Event("consent", "samar_execute_command", "allow", "human_approved")
	}

	restored, err := s.deps.Restorer.Restore(command)
	if err != nil {
		s.deps.Audit.Event("abort", "samar_execute_command", "abort", "corrupted_token")
		return mcp.NewToolResultErrorf("%v", err), nil
	}

	res, rerr := s.deps.Runner.Run(restored, cwd)
	if rerr != nil {
		return mcp.NewToolResultErrorf("gagal menjalankan perintah: %v", rerr), nil
	}
	s.deps.Audit.Event("execute", "samar_execute_command", "allow", "ok")
	// Keluaran perintah DI-MASK ULANG: output bisa berisi secret (mis. echo).
	out := s.deps.Masker.Mask("", res.Stdout).Masked
	errOut := s.deps.Masker.Mask("", res.Stderr).Masked
	return mcp.NewToolResultText(fmt.Sprintf("exit=%d\n--- stdout ---\n%s\n--- stderr ---\n%s", res.ExitCode, out, errOut)), nil
}

// commandHasToken true bila command mengandung minimal satu placeholder utuh.
func (s *Samar) commandHasToken(command string) bool {
	// Restorasi tiruan: jika Restore mengubah string, berarti ada token valid.
	// Namun Restore gagal-closed pada token korup; di sini token korup sudah
	// disaring HasTruncatedToken, jadi aman memanggil Restore untuk cek.
	restored, err := s.deps.Restorer.Restore(command)
	if err != nil {
		return true // korup = ada token (akan ditangani jalur error terpisah)
	}
	return restored != command
}

package detector

import (
	"path/filepath"
	"strings"
)

// DotEnv memasking SEMUA value pada file berekstensi ".env*" tanpa bergantung
// pada regex (PRD §7 "Partial Secret Leak"): satu-satunya cara aman untuk file
// yang per definisi berisi rahasia. Hanya VALUE yang dimasking; nama variabel
// dan komentar dibiarkan agar konteks tetap berguna bagi LLM.
type DotEnv struct{}

// NewDotEnv membuat detektor .env.
func NewDotEnv() *DotEnv { return &DotEnv{} }

// Name memenuhi Detector.
func (d *DotEnv) Name() string { return "dotenv" }

// appliesTo true untuk .env, .env.local, .env.production, dst. Pencocokan
// case-insensitive pada basename.
func (d *DotEnv) appliesTo(filename string) bool {
	if filename == "" {
		return false
	}
	base := strings.ToLower(filepath.Base(filename))
	return base == ".env" || strings.HasPrefix(base, ".env.") || strings.HasPrefix(base, ".env")
}

// Detect mem-parsing baris "KEY=VALUE" dan mengembalikan rentang byte VALUE.
// Mendukung value ber-quote (tanda kutip di-mask termasuk/tanpa isinya) dan
// komentar inline sederhana. Baris komentar (#) dan baris tanpa '=' diabaikan.
func (d *DotEnv) Detect(filename, content string) []Finding {
	if !d.appliesTo(filename) {
		return nil
	}
	var findings []Finding
	offset := 0
	for _, line := range splitKeepLen(content) {
		raw := content[offset : offset+len(line)]
		trimmed := strings.TrimSpace(raw)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			offset += len(line)
			continue
		}
		eq := strings.IndexByte(raw, '=')
		if eq < 0 {
			offset += len(line)
			continue
		}
		// Opsional "export " prefix tidak mempengaruhi posisi value.
		valStart := eq + 1
		// Lewati spasi setelah '='.
		for valStart < len(raw) && (raw[valStart] == ' ' || raw[valStart] == '\t') {
			valStart++
		}
		valEnd := len(raw)
		// Pangkas newline trailing (sudah termasuk di line).
		for valEnd > valStart && (raw[valEnd-1] == '\n' || raw[valEnd-1] == '\r') {
			valEnd--
		}
		if valEnd > valStart {
			findings = append(findings, Finding{
				Start:    offset + valStart,
				End:      offset + valEnd,
				Detector: d.Name(),
			})
		}
		offset += len(line)
	}
	return findings
}

// splitKeepLen memecah teks menjadi baris-baris SAMBIL mempertahankan pemisah
// baris di setiap elemen, sehingga penjumlahan panjang == len(content). Ini
// menjaga akurasi offset byte untuk CRLF maupun LF.
func splitKeepLen(s string) []string {
	var lines []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			lines = append(lines, s[start:i+1])
			start = i + 1
		}
	}
	if start < len(s) {
		lines = append(lines, s[start:])
	}
	return lines
}

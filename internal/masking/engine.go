// Package masking mengorkestrasi alur inbound: deteksi secret -> simpan ke
// vault -> ganti dengan token. Engine bergantung pada ABSTRAKSI (Detector dan
// Tokenizer), bukan implementasi konkret (Dependency Inversion), sehingga mudah
// ditest dan diperluas.
package masking

import "github.com/hanifalkauni/samar-mcp/internal/detector"

// Tokenizer adalah bagian dari vault.Vault yang dibutuhkan engine. Dengan
// mempersempit kontrak (Interface Segregation), engine tidak tahu detail vault.
type Tokenizer interface {
	Tokenize(secret string) string
}

// Engine mengubah konten mentah menjadi konten tersanitasi.
type Engine struct {
	det detector.Detector
	tok Tokenizer
}

// New membuat Engine dari sebuah Detector dan Tokenizer.
func New(det detector.Detector, tok Tokenizer) *Engine {
	return &Engine{det: det, tok: tok}
}

// Result membawa konten yang sudah dimasking beserta ringkasan temuan untuk
// audit (PRD §10). Nilai asli TIDAK disertakan di sini.
type Result struct {
	Masked      string
	SecretCount int
	Detectors   []string // nama detektor per secret, selaras urutan kemunculan
}

// Mask memindai content, men-tokenisasi tiap secret, dan mengembalikan konten
// dengan secret diganti token. Penggantian dilakukan dari belakang ke depan
// agar offset byte temuan tetap valid saat string dimodifikasi.
func (e *Engine) Mask(filename, content string) Result {
	findings := e.det.Detect(filename, content)
	if len(findings) == 0 {
		return Result{Masked: content}
	}

	// findings sudah terurut & non-overlap dari Registry; proses mundur.
	out := content
	dets := make([]string, 0, len(findings))
	for i := len(findings) - 1; i >= 0; i-- {
		f := findings[i]
		if f.Start < 0 || f.End > len(content) || f.Start >= f.End {
			continue // defensif terhadap offset tak valid
		}
		secret := content[f.Start:f.End]
		token := e.tok.Tokenize(secret)
		out = out[:f.Start] + token + out[f.End:]
		dets = append(dets, f.Detector)
	}

	// Balik dets agar urut maju (kita mengisi saat iterasi mundur).
	for i, j := 0, len(dets)-1; i < j; i, j = i+1, j-1 {
		dets[i], dets[j] = dets[j], dets[i]
	}
	return Result{Masked: out, SecretCount: len(dets), Detectors: dets}
}

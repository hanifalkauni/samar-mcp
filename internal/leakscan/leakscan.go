// Package leakscan menyediakan pemeriksaan sederhana untuk memastikan nilai
// rahasia yang diketahui tidak bocor ke sebuah teks (output tool, isi log).
// Dipakai oleh corpus adversarial (PRD §12) dan self-test redaksi audit (§10).
package leakscan

import "strings"

// Scan mengembalikan daftar secret (dari secrets) yang DITEMUKAN di dalam text.
// Hasil kosong berarti tidak ada kebocoran. Secret kosong diabaikan.
func Scan(text string, secrets []string) []string {
	var leaked []string
	for _, s := range secrets {
		if s == "" {
			continue
		}
		if strings.Contains(text, s) {
			leaked = append(leaked, s)
		}
	}
	return leaked
}

// Clean adalah helper boolean: true bila tidak ada secret yang bocor.
func Clean(text string, secrets []string) bool {
	return len(Scan(text, secrets)) == 0
}

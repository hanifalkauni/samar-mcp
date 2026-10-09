// Package vault menyimpan pemetaan dua arah antara nilai rahasia (secret) dan
// token placeholder-nya, strictly di dalam RAM (zero-persistence).
//
// Desain (PRD §5.3, §5.2):
//   - Token TIDAK diturunkan dari nilai asli (anti brute-force). Token dibuat
//     acak oleh TokenGenerator yang di-inject (DIP) sehingga mudah ditest.
//   - Determinisme per-sesi dicapai lewat reverse-map (secret -> token): nilai
//     yang sama menghasilkan token yang sama dalam satu instance Vault.
//   - Nilai asli tidak pernah ditulis ke disk/log oleh paket ini.
package vault

import (
	"fmt"
	"sync"
)

// TokenGenerator menghasilkan ID acak untuk token baru. Di-inject agar bisa
// dipalsukan deterministik saat test (Dependency Inversion).
type TokenGenerator interface {
	// NewID mengembalikan ID unik, singkat, dan URL-safe.
	NewID() string
}

// Vault adalah penyimpanan secret<->token in-memory yang aman untuk konkurensi.
//
// Zero value TIDAK siap pakai; gunakan New.
type Vault struct {
	mu          sync.RWMutex
	tokenToSec  map[string]string // token -> secret asli
	secToToken  map[string]string // secret asli -> token (reverse-map)
	gen         TokenGenerator
	tokenPrefix string
	tokenSuffix string
}

// New membuat Vault kosong dengan generator token yang diberikan.
func New(gen TokenGenerator) *Vault {
	return &Vault{
		tokenToSec:  make(map[string]string),
		secToToken:  make(map[string]string),
		gen:         gen,
		tokenPrefix: "__SAMAR_SECRET_",
		tokenSuffix: "__",
	}
}

// Tokenize mengembalikan token placeholder untuk sebuah secret. Jika secret
// sudah pernah dilihat dalam sesi ini, token yang sama dikembalikan (determinisme
// via reverse-map). Secret kosong tidak di-tokenisasi dan dikembalikan apa adanya.
func (v *Vault) Tokenize(secret string) string {
	if secret == "" {
		return ""
	}

	// Fast path: cek apakah secret sudah punya token (read lock).
	v.mu.RLock()
	if tok, ok := v.secToToken[secret]; ok {
		v.mu.RUnlock()
		return tok
	}
	v.mu.RUnlock()

	// Slow path: buat token baru di bawah write lock. Cek ulang untuk menghindari
	// race di mana dua goroutine men-tokenisasi secret yang sama bersamaan.
	v.mu.Lock()
	defer v.mu.Unlock()
	if tok, ok := v.secToToken[secret]; ok {
		return tok
	}
	tok := v.tokenPrefix + v.gen.NewID() + v.tokenSuffix
	v.tokenToSec[tok] = secret
	v.secToToken[secret] = tok
	return tok
}

// Detokenize mengembalikan secret asli untuk sebuah token. Jika token tidak
// dikenal (mis. terpotong/termutasi oleh LLM), ok bernilai false — pemanggil
// WAJIB memperlakukan ini sebagai kondisi fail-closed (PRD §7).
func (v *Vault) Detokenize(token string) (secret string, ok bool) {
	v.mu.RLock()
	defer v.mu.RUnlock()
	secret, ok = v.tokenToSec[token]
	return secret, ok
}

// TokenPattern mengembalikan prefix dan suffix token sehingga pemanggil
// (mis. restorer outbound) dapat memindai token tanpa menebak formatnya.
func (v *Vault) TokenPattern() (prefix, suffix string) {
	return v.tokenPrefix, v.tokenSuffix
}

// Len mengembalikan jumlah secret unik yang tersimpan. Berguna untuk metrik/test.
func (v *Vault) Len() int {
	v.mu.RLock()
	defer v.mu.RUnlock()
	return len(v.tokenToSec)
}

// Fingerprint tidak disediakan di sini; audit log (PRD §10) bertanggung jawab
// menghitung fingerprint agar Vault tetap murni sebagai penyimpanan.

// assert bahwa format token internal selalu konsisten (dipakai di test).
func (v *Vault) debugString() string {
	return fmt.Sprintf("vault(entries=%d, format=%s<id>%s)", v.Len(), v.tokenPrefix, v.tokenSuffix)
}

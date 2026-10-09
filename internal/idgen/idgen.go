// Package idgen menyediakan generator ID acak kriptografis untuk token vault.
package idgen

import (
	"crypto/rand"
	"encoding/hex"
)

// CryptoGen menghasilkan ID acak menggunakan crypto/rand. Memenuhi
// vault.TokenGenerator. Token acak (bukan hash dari nilai) mencegah
// brute-force/rainbow terhadap secret berentropi rendah (PRD §5.2).
type CryptoGen struct {
	// Bytes adalah jumlah byte acak per ID (default 4 => 8 hex chars).
	Bytes int
}

// NewCryptoGen membuat generator dengan panjang default yang aman dan ringkas.
func NewCryptoGen() *CryptoGen {
	return &CryptoGen{Bytes: 4}
}

// NewID mengembalikan ID heksadesimal acak huruf besar (mis. "7F3A9C21").
// Panik hanya jika sumber entropi OS gagal total — kondisi yang tidak dapat
// dipulihkan dan lebih baik fail-fast daripada menghasilkan token lemah.
func (g *CryptoGen) NewID() string {
	n := g.Bytes
	if n <= 0 {
		n = 4
	}
	buf := make([]byte, n)
	if _, err := rand.Read(buf); err != nil {
		panic("idgen: sumber entropi OS gagal: " + err.Error())
	}
	s := hex.EncodeToString(buf)
	return toUpper(s)
}

// toUpper menaikkan huruf hex a-f menjadi A-F tanpa alokasi tabel unicode.
func toUpper(s string) string {
	b := []byte(s)
	for i := range b {
		if b[i] >= 'a' && b[i] <= 'f' {
			b[i] -= 'a' - 'A'
		}
	}
	return string(b)
}

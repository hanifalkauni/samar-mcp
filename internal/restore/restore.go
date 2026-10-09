// Package restore membalik proses masking pada jalur outbound: menemukan token
// placeholder di dalam konten dan menggantinya dengan secret asli dari vault.
//
// Prinsip fail-closed (PRD §7): bila ditemukan token yang BENTUKNYA seperti
// placeholder SafeEnv tetapi tidak ada di vault (terpotong/termutasi oleh LLM),
// restorasi DIBATALKAN dengan error — tidak pernah mengeksekusi/menulis parsial.
package restore

import (
	"fmt"
	"regexp"
	"strings"
)

// Detokenizer adalah kontrak minimal dari vault yang dibutuhkan restorer
// (Interface Segregation).
type Detokenizer interface {
	Detokenize(token string) (string, bool)
	TokenPattern() (prefix, suffix string)
}

// ErrCorruptedToken dikembalikan saat ada placeholder yang tidak cocok dengan
// vault. Pesan sengaja deskriptif namun tidak membocorkan isi vault.
type ErrCorruptedToken struct {
	Token string
}

func (e *ErrCorruptedToken) Error() string {
	return fmt.Sprintf("corrupted token placeholder detected: %q tidak ada di vault (restorasi dibatalkan)", e.Token)
}

// Restorer mengganti token dengan secret asli.
type Restorer struct {
	vault Detokenizer
	re    *regexp.Regexp
}

// New membangun Restorer. Pola token diturunkan dari TokenPattern vault agar
// restorer dan vault selalu sepakat soal format.
func New(v Detokenizer) *Restorer {
	pre, suf := v.TokenPattern()
	// Tangkap ID di antara prefix dan suffix. ID vault = hex uppercase.
	pat := regexp.QuoteMeta(pre) + `[0-9A-F]+` + regexp.QuoteMeta(suf)
	return &Restorer{vault: v, re: regexp.MustCompile(pat)}
}

// Restore mengganti semua token valid dengan secret-nya. Jika ada token yang
// berbentuk placeholder utuh tetapi tidak dikenal vault, kembalikan error
// (fail-closed). Teks yang hanya "mirip" placeholder tetapi tidak match pola
// penuh tidak dianggap token dan dibiarkan apa adanya.
func (r *Restorer) Restore(content string) (string, error) {
	var firstErr error
	out := r.re.ReplaceAllStringFunc(content, func(tok string) string {
		if firstErr != nil {
			return tok
		}
		secret, ok := r.vault.Detokenize(tok)
		if !ok {
			firstErr = &ErrCorruptedToken{Token: tok}
			return tok
		}
		return secret
	})
	if firstErr != nil {
		return "", firstErr
	}
	return out, nil
}

// HasTruncatedToken mendeteksi fragmen placeholder yang terpotong (mis.
// "__SAFE_SEC") untuk memberi pesan error lebih jelas sebelum eksekusi.
// Dikembalikan true bila ada prefix token tanpa suffix penutup.
func (r *Restorer) HasTruncatedToken(content string) bool {
	pre, suf := r.vault.TokenPattern()
	idx := 0
	for {
		i := strings.Index(content[idx:], pre)
		if i < 0 {
			return false
		}
		abs := idx + i
		rest := content[abs+len(pre):]
		end := strings.Index(rest, suf)
		if end < 0 {
			return true // prefix tanpa suffix => terpotong
		}
		// Jika ada karakter non-hex sebelum suffix, anggap termutasi.
		for _, c := range rest[:end] {
			if !((c >= '0' && c <= '9') || (c >= 'A' && c <= 'F')) {
				return true
			}
		}
		idx = abs + len(pre) + end + len(suf)
	}
}

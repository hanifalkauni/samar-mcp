package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

// resolveAuditDir menentukan direktori penyimpanan log audit:
// 1. Env SAMAR_AUDIT_DIR (fallback: SAFEENV_AUDIT_DIR) jika didefinisikan.
// 2. Default: $HOME/.samar/audit/<project-slug>-<hash8>/
// 3. Fallback: ./.samar/audit jika $HOME tidak dapat diakses.
func resolveAuditDir(cwd string) string {
	if custom := getEnvWithFallback("SAMAR_AUDIT_DIR", "SAFEENV_AUDIT_DIR"); custom != "" {
		return custom
	}

	home, err := os.UserHomeDir()
	if err != nil || strings.TrimSpace(home) == "" {
		return filepath.Join(".samar", "audit")
	}

	slug := projectSlug(cwd)
	return filepath.Join(home, ".samar", "audit", slug)
}

// projectSlug menghasilkan slug folder yang aman dan unik berdasarkan absolute path cwd:
// format: <sanitized-basename>-<hash8>
func projectSlug(cwd string) string {
	if strings.TrimSpace(cwd) == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			cwd = "."
		}
	}

	abs, err := filepath.Abs(cwd)
	if err != nil {
		abs = cwd
	}

	// 8 karakter hash SHA-256 dari absolute path untuk mencegah tabrakan nama folder
	sum := sha256.Sum256([]byte(abs))
	hash8 := hex.EncodeToString(sum[:])[:8]

	base := filepath.Base(abs)
	var clean strings.Builder
	for _, r := range base {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' {
			clean.WriteRune(r)
		} else {
			clean.WriteRune('-')
		}
	}

	sanitized := strings.Trim(clean.String(), "-_")
	if sanitized == "" {
		sanitized = "workspace"
	}

	return fmt.Sprintf("%s-%s", sanitized, hash8)
}

// lazyFileWriter menunda pembuatan direktori dan file audit hingga event pertama
// benar-benar ditulis (lazy creation). Sesi idle tidak akan meninggalkan file kosong.
type lazyFileWriter struct {
	mu       sync.Mutex
	dir      string
	filename string
	file     *os.File
}

func newLazyFileWriter(dir, filename string) *lazyFileWriter {
	return &lazyFileWriter{
		dir:      dir,
		filename: filename,
	}
}

func (l *lazyFileWriter) Write(p []byte) (n int, err error) {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file == nil {
		if err := os.MkdirAll(l.dir, 0o700); err != nil {
			return 0, err
		}

		filePath := filepath.Join(l.dir, l.filename)
		f, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
		if err != nil {
			return 0, err
		}
		l.file = f
	}

	return l.file.Write(p)
}

func (l *lazyFileWriter) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if l.file != nil {
		err := l.file.Close()
		l.file = nil
		return err
	}
	return nil
}

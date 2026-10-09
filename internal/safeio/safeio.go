// Package safeio mengabstraksi akses filesystem dan environment di belakang
// interface, sehingga handler tool tidak terikat langsung ke OS dan bisa
// ditest dengan implementasi palsu (Dependency Inversion).
package safeio

import (
	"fmt"
	"os"
	"strings"
)

// MaxFileBytes membatasi ukuran file yang dibaca (PRD §6.3): di atas ini
// server menolak dengan error terkontrol alih-alih menggantung.
const MaxFileBytes = 10 << 20 // 10 MB

// FileReader membaca isi file sebagai teks.
type FileReader interface {
	ReadFile(path string) (string, error)
}

// EnvReader membaca variabel environment proses.
type EnvReader interface {
	// Lookup mengembalikan nilai satu variabel.
	Lookup(key string) (string, bool)
	// All mengembalikan seluruh environment sebagai map key->value.
	All() map[string]string
}

// FileWriter menulis isi ke sebuah file (jalur outbound, PRD §5.4).
type FileWriter interface {
	WriteFile(path, content string) error
}

// CommandResult membawa keluaran eksekusi perintah.
type CommandResult struct {
	Stdout   string
	Stderr   string
	ExitCode int
}

// CommandRunner mengeksekusi perintah shell di direktori kerja tertentu.
type CommandRunner interface {
	Run(command, cwd string) (CommandResult, error)
}

// OSFileReader membaca dari filesystem nyata dengan batas ukuran.
type OSFileReader struct{}

// ReadFile membaca file, menolak file yang melebihi MaxFileBytes.
func (OSFileReader) ReadFile(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if info.IsDir() {
		return "", fmt.Errorf("safeio: %q adalah direktori, bukan file", path)
	}
	if info.Size() > MaxFileBytes {
		return "", fmt.Errorf("safeio: file %q (%d byte) melebihi batas %d byte", path, info.Size(), MaxFileBytes)
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

// OSEnvReader membaca environment proses nyata.
type OSEnvReader struct{}

// Lookup membungkus os.LookupEnv.
func (OSEnvReader) Lookup(key string) (string, bool) { return os.LookupEnv(key) }

// All memecah os.Environ() menjadi map.
func (OSEnvReader) All() map[string]string {
	m := make(map[string]string)
	for _, kv := range os.Environ() {
		if i := strings.IndexByte(kv, '='); i >= 0 {
			m[kv[:i]] = kv[i+1:]
		}
	}
	return m
}

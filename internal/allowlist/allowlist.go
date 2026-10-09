// Package allowlist menyediakan egress allowlist bertingkat (PRD §13.3): host
// tepercaya global digabung dengan host per-project. Mode default = UNION
// (global ∪ project). Mode STRICT = per-project MEMPERSEMPIT global
// (global ∩ project) bila ada entri project; bila project kosong, fallback ke
// global. Reload tanpa restart (PRD §13.5) memakai lazy check berbasis mtime +
// atomic swap, dengan validate-before-swap sehingga file rusak tidak pernah
// mengosongkan allowlist.
package allowlist

import (
	"bufio"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// source adalah satu file allowlist beserta mtime terakhir yang terbaca.
type source struct {
	path      string
	modTime   time.Time
	hosts     map[string]struct{}
	isProject bool // true untuk source per-project (relevan di strict mode)
}

// Allowlist menggabungkan beberapa source. Aman untuk konkurensi; snapshot host
// aktif disimpan di atomic.Value dan di-swap utuh saat reload.
type Allowlist struct {
	mu       sync.Mutex
	sources  []*source
	ttl      time.Duration
	strict   bool
	lastScan time.Time
	snapshot atomic.Value // map[string]struct{}
	onReload func()       // opsional: dipanggil setelah snapshot di-swap (untuk audit)
}

// SetOnReload mendaftarkan callback yang dipanggil setiap kali reload benar-benar
// menukar snapshot (file allowlist berubah). Dipakai untuk audit config_reload.
// Aman dipanggil sekali saat setup; tidak untuk dipanggil konkuren dengan Allowed.
func (a *Allowlist) SetOnReload(fn func()) {
	a.mu.Lock()
	a.onReload = fn
	a.mu.Unlock()
}

// New membuat allowlist mode UNION dari daftar path (semua diperlakukan global;
// hasilnya global ∪ project). Path yang tidak ada diabaikan (bukan error).
func New(ttl time.Duration, paths ...string) *Allowlist {
	a := &Allowlist{ttl: ttl}
	for _, p := range paths {
		if p != "" {
			a.sources = append(a.sources, &source{path: p, hosts: map[string]struct{}{}})
		}
	}
	a.snapshot.Store(map[string]struct{}{})
	a.reload(true)
	return a
}

// NewLayered membuat allowlist dengan source global dan project yang eksplisit.
// strict=false => union (global ∪ project). strict=true => project mempersempit
// global (global ∩ project) bila project punya entri; project kosong => global.
func NewLayered(ttl time.Duration, strict bool, globalPaths, projectPaths []string) *Allowlist {
	a := &Allowlist{ttl: ttl, strict: strict}
	for _, p := range globalPaths {
		if p != "" {
			a.sources = append(a.sources, &source{path: p, hosts: map[string]struct{}{}, isProject: false})
		}
	}
	for _, p := range projectPaths {
		if p != "" {
			a.sources = append(a.sources, &source{path: p, hosts: map[string]struct{}{}, isProject: true})
		}
	}
	a.snapshot.Store(map[string]struct{}{})
	a.reload(true)
	return a
}

// Allowed mengembalikan true bila host ada di allowlist efektif. Pemanggilan ini
// memicu lazy reload bila TTL terlampaui.
func (a *Allowlist) Allowed(host string) bool {
	a.maybeReload()
	hosts, _ := a.snapshot.Load().(map[string]struct{})
	_, ok := hosts[strings.ToLower(host)]
	return ok
}

// maybeReload memeriksa TTL lalu mtime; murah bila belum waktunya.
func (a *Allowlist) maybeReload() {
	a.mu.Lock()
	due := time.Since(a.lastScan) >= a.ttl
	a.mu.Unlock()
	if due {
		a.reload(false)
	}
}

// reload membaca ulang source yang berubah dan menukar snapshot secara atomik.
// Validate-before-swap: jika sebuah file gagal dibaca, host lama source itu
// dipertahankan (tidak dikosongkan). force=true membaca semua tanpa cek mtime.
func (a *Allowlist) reload(force bool) {
	a.mu.Lock()
	defer a.mu.Unlock()

	changed := false
	for _, s := range a.sources {
		info, err := os.Stat(s.path)
		if err != nil {
			continue // file tidak ada / tak terbaca: pertahankan host lama
		}
		if !force && info.ModTime().Equal(s.modTime) {
			continue
		}
		hosts, perr := parseFile(s.path)
		if perr != nil {
			continue // parse gagal: fail-safe, jangan ganti
		}
		s.hosts = hosts
		s.modTime = info.ModTime()
		changed = true
	}
	a.lastScan = time.Now()

	if changed || force {
		a.snapshot.Store(a.resolve()) // atomic swap pointer
	}
	// Notifikasi reload hanya saat ada perubahan nyata (bukan load awal via force),
	// untuk audit config_reload. Callback dipanggil di luar sorotan lock? Tidak:
	// pemanggil (maybeReload) sudah tak memegang lain; onReload harus ringan.
	if changed && !force && a.onReload != nil {
		a.onReload()
	}
}

// resolve menghitung allowlist efektif dari semua source menurut mode.
func (a *Allowlist) resolve() map[string]struct{} {
	global := make(map[string]struct{})
	project := make(map[string]struct{})
	hasProjectEntries := false
	for _, s := range a.sources {
		dst := global
		if s.isProject {
			dst = project
		}
		for h := range s.hosts {
			dst[h] = struct{}{}
			if s.isProject {
				hasProjectEntries = true
			}
		}
	}

	// Mode STRICT: project mempersempit global (intersection) bila project
	// punya entri. Tanpa entri project, strict jatuh ke global apa adanya.
	if a.strict && hasProjectEntries {
		eff := make(map[string]struct{})
		for h := range project {
			if _, ok := global[h]; ok {
				eff[h] = struct{}{}
			}
		}
		return eff
	}

	// Mode UNION (default): global ∪ project.
	eff := make(map[string]struct{}, len(global)+len(project))
	for h := range global {
		eff[h] = struct{}{}
	}
	for h := range project {
		eff[h] = struct{}{}
	}
	return eff
}

// parseFile membaca host satu-per-baris; '#' = komentar, baris kosong diabaikan.
func parseFile(path string) (map[string]struct{}, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	hosts := make(map[string]struct{})
	sc := bufio.NewScanner(f)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		hosts[strings.ToLower(line)] = struct{}{}
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return hosts, nil
}

package allowlist

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func writeFile(t *testing.T, dir, name, content string) string {
	t.Helper()
	p := filepath.Join(dir, name)
	if err := os.WriteFile(p, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestUnionOfSources(t *testing.T) {
	dir := t.TempDir()
	g := writeFile(t, dir, "global", "global.com\n# komentar\n")
	p := writeFile(t, dir, "project", "project.com\n")
	a := New(time.Hour, g, p)

	if !a.Allowed("global.com") || !a.Allowed("project.com") {
		t.Fatal("union harus memuat host dari kedua source")
	}
	if a.Allowed("unknown.com") {
		t.Fatal("host asing tidak boleh diizinkan")
	}
}

func TestCaseInsensitive(t *testing.T) {
	dir := t.TempDir()
	g := writeFile(t, dir, "g", "Example.COM\n")
	a := New(time.Hour, g)
	if !a.Allowed("example.com") {
		t.Fatal("pencocokan host harus case-insensitive")
	}
}

func TestMissingFileIgnored(t *testing.T) {
	dir := t.TempDir()
	g := writeFile(t, dir, "g", "ok.com\n")
	a := New(time.Hour, g, filepath.Join(dir, "tidak-ada"))
	if !a.Allowed("ok.com") {
		t.Fatal("source yang ada harus tetap bekerja walau source lain hilang")
	}
}

func TestLazyReloadOnChange(t *testing.T) {
	dir := t.TempDir()
	g := writeFile(t, dir, "g", "first.com\n")
	a := New(0, g) // ttl=0 => selalu cek mtime

	if a.Allowed("second.com") {
		t.Fatal("second.com belum ada")
	}
	// Tulis ulang dengan mtime berbeda.
	time.Sleep(10 * time.Millisecond)
	writeFile(t, dir, "g", "first.com\nsecond.com\n")
	// Pastikan mtime maju (beberapa FS kasar granularitasnya).
	future := time.Now().Add(time.Second)
	os.Chtimes(g, future, future)

	if !a.Allowed("second.com") {
		t.Fatal("reload lazy harus memuat host baru setelah file berubah")
	}
}

func TestFailSafeOnInvalidRewrite(t *testing.T) {
	dir := t.TempDir()
	g := writeFile(t, dir, "g", "keep.com\n")
	a := New(0, g)
	if !a.Allowed("keep.com") {
		t.Fatal("setup gagal")
	}
	// Hapus file (simulasi gagal baca): host lama harus dipertahankan.
	os.Remove(g)
	if !a.Allowed("keep.com") {
		t.Fatal("fail-safe: host lama harus bertahan saat file hilang")
	}
}

// --- strict mode (§13.3) ---

func TestLayered_UnionMode(t *testing.T) {
	dir := t.TempDir()
	g := writeFile(t, dir, "g", "global.com\nshared.com\n")
	p := writeFile(t, dir, "p", "project.com\nshared.com\n")
	a := NewLayered(time.Hour, false, []string{g}, []string{p})
	for _, h := range []string{"global.com", "project.com", "shared.com"} {
		if !a.Allowed(h) {
			t.Fatalf("union harus mengizinkan %q", h)
		}
	}
}

func TestLayered_StrictNarrowsGlobal(t *testing.T) {
	dir := t.TempDir()
	g := writeFile(t, dir, "g", "global.com\nshared.com\n")
	p := writeFile(t, dir, "p", "shared.com\nproject-only.com\n")
	a := NewLayered(time.Hour, true, []string{g}, []string{p})

	// Hanya host yang ada di KEDUA (intersection) yang diizinkan.
	if !a.Allowed("shared.com") {
		t.Fatal("strict: host di global ∩ project harus diizinkan")
	}
	if a.Allowed("global.com") {
		t.Fatal("strict: host global yang tidak ada di project harus DITOLAK")
	}
	if a.Allowed("project-only.com") {
		t.Fatal("strict: host project yang tidak ada di global harus DITOLAK")
	}
}

func TestOnReload_FiresOnChange(t *testing.T) {
	dir := t.TempDir()
	g := writeFile(t, dir, "g", "first.com\n")
	a := New(0, g) // ttl=0 => selalu cek mtime
	var fired int
	a.SetOnReload(func() { fired++ })

	// Ubah file + majukan mtime, lalu picu lazy reload lewat Allowed.
	time.Sleep(10 * time.Millisecond)
	writeFile(t, dir, "g", "first.com\nsecond.com\n")
	future := time.Now().Add(time.Second)
	os.Chtimes(g, future, future)
	_ = a.Allowed("second.com")

	if fired == 0 {
		t.Fatal("OnReload harus terpanggil saat file allowlist berubah")
	}
}

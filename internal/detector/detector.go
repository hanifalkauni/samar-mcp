// Package detector menemukan rentang (span) teks sensitif di dalam sebuah
// konten. Setiap strategi deteksi mengimplementasikan interface Detector
// (Interface Segregation): mesin masking tidak perlu tahu detektor mana yang
// dipakai, hanya kontraknya.
package detector

import "sort"

// Finding adalah satu rentang byte di dalam konten yang dianggap rahasia.
// Start inklusif, End eksklusif (konvensi slice Go: content[Start:End]).
type Finding struct {
	Start    int
	End      int
	Detector string // nama detektor penemu, untuk audit (PRD §10)
}

// Value mengembalikan sub-string rahasia dari konten.
func (f Finding) Value(content string) string {
	return content[f.Start:f.End]
}

// Detector memindai konten dan mengembalikan rentang sensitif. Implementasi
// WAJIB tidak memodifikasi konten dan aman dipanggil konkuren.
type Detector interface {
	// Name mengidentifikasi detektor di log audit.
	Name() string
	// Detect mengembalikan daftar temuan. filename membantu detektor yang
	// bergantung ekstensi (mis. dotenv untuk file ".env*"); boleh kosong.
	Detect(filename, content string) []Finding
}

// Registry menggabungkan beberapa Detector menjadi satu (Composite). Menambah
// detektor baru = daftarkan implementasi, tanpa mengubah konsumen (Open/Closed).
type Registry struct {
	detectors []Detector
}

// NewRegistry membuat registry dari detektor-detektor yang diberikan.
func NewRegistry(ds ...Detector) *Registry {
	return &Registry{detectors: ds}
}

// Name memenuhi Detector sehingga Registry sendiri bisa dikomposisi lagi.
func (r *Registry) Name() string { return "registry" }

// Detect menjalankan semua detektor, menggabungkan temuan, lalu me-normalisasi:
// temuan diurutkan dan rentang yang tumpang-tindih digabung agar satu secret
// tidak di-tokenisasi dua kali (mis. DB URI yang juga cocok pola generik).
func (r *Registry) Detect(filename, content string) []Finding {
	var all []Finding
	for _, d := range r.detectors {
		all = append(all, d.Detect(filename, content)...)
	}
	return mergeOverlapping(all)
}

// mergeOverlapping mengurutkan temuan berdasar Start lalu menggabungkan rentang
// yang bersinggungan/berdampingan. Detektor pemenang (Detector pada hasil gabung)
// adalah temuan pertama yang membuka rentang tersebut.
func mergeOverlapping(fs []Finding) []Finding {
	if len(fs) <= 1 {
		return fs
	}
	sort.Slice(fs, func(i, j int) bool {
		if fs[i].Start != fs[j].Start {
			return fs[i].Start < fs[j].Start
		}
		return fs[i].End > fs[j].End // yang lebih panjang dulu pada Start sama
	})
	merged := make([]Finding, 0, len(fs))
	cur := fs[0]
	for _, f := range fs[1:] {
		if f.Start <= cur.End { // tumpang tindih atau bersentuhan
			if f.End > cur.End {
				cur.End = f.End
			}
			continue
		}
		merged = append(merged, cur)
		cur = f
	}
	merged = append(merged, cur)
	return merged
}

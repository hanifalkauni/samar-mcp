// Package corpus menyediakan fixture adversarial berlabel untuk mengukur
// recall deteksi (PRD §11) dan menguji ketahanan jalur masking/outbound (§12).
//
// Semua "secret" di sini adalah NILAI PALSU untuk pengujian — bukan kredensial
// nyata. Jangan pernah menaruh secret sungguhan di repo.
package corpus

// Case adalah satu baris corpus: konten mentah yang memuat Secret, dengan
// Filename untuk mengarahkan detektor berbasis ekstensi (mis. .env).
type Case struct {
	Name     string
	Filename string
	Content  string
	Secret   string // nilai palsu yang HARUS termasking
	Family   string // keluarga detektor yang diharapkan menangkap
}

// Secrets mengembalikan hanya nilai-nilai secret, untuk leak-scan.
func Secrets(cases []Case) []string {
	out := make([]string, 0, len(cases))
	for _, c := range cases {
		out = append(out, c.Secret)
	}
	return out
}

// Cases mengembalikan corpus. Daftar sengaja mencakup pola yang mudah (provider
// keys) sampai yang sulit (secret acak di .env yang tak cocok regex apa pun).
func Cases() []Case {
	return []Case{
		{"aws_key", "creds.txt", "aws_access_key_id = AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE", "regex"},
		{"github_pat", "notes.md", "token: ghp_1234567890abcdefABCDEF1234567890abcd", "ghp_1234567890abcdefABCDEF1234567890abcd", "regex"},
		{"openai", "cfg.yaml", "OPENAI=sk-abcdefghijklmnopqrstuvwx", "sk-abcdefghijklmnopqrstuvwx", "regex"},
		{"slack", "a.txt", "xoxb-EXAMPLE-dummytoken12345", "xoxb-EXAMPLE-dummytoken12345", "regex"},
		{"stripe", "b.txt", "key=sk_live_abcdefghij1234567890", "sk_live_abcdefghij1234567890", "regex"},
		{"jwt", "c.txt", "auth eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVabc123", "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjMifQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJVabc123", "regex"},
		{"postgres_uri", "d.txt", "DATABASE_URL=postgres://u:p@db.local:5432/app", "postgres://u:p@db.local:5432/app", "regex"},
		{"mongodb_uri", "e.txt", "mongodb://user:pass@mongo:27017/x", "mongodb://user:pass@mongo:27017/x", "regex"},
		{"generic_password", "app.conf", "DB_PASSWORD=plainpw123", "plainpw123", "regex"},
		{"generic_apikey", "app.conf", "MY_API_KEY=zzzyyyxxx000", "zzzyyyxxx000", "regex"},
		// Sulit: nilai acak di .env yang TIDAK cocok pola apa pun. Harus tetap
		// termasking karena file .env mask-semua (PRD §7).
		{"env_random_value", ".env", "WEIRD_SETTING=q8Zx2Lp0vT", "q8Zx2Lp0vT", "dotenv"},
		{"env_plain_host", ".env", "HOST=internal.db.corp", "internal.db.corp", "dotenv"},
	}
}

package detector

import "testing"

func found(content string, fs []Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Value(content))
	}
	return out
}

func TestDotEnv_MasksAllValues(t *testing.T) {
	d := NewDotEnv()
	content := "# komentar\nAPP_NAME=demo\nRANDOM_THING=xyz123\n\nexport PORT=8080\n"
	fs := d.Detect(".env", content)
	vals := found(content, fs)
	// Semua value harus terdeteksi walau tidak cocok pola regex apa pun.
	want := map[string]bool{"demo": true, "xyz123": true, "8080": true}
	if len(vals) != 3 {
		t.Fatalf("harap 3 value, dapat %d: %v", len(vals), vals)
	}
	for _, v := range vals {
		if !want[v] {
			t.Fatalf("value tak terduga: %q (semua: %v)", v, vals)
		}
	}
}

func TestDotEnv_IgnoresNonEnvFiles(t *testing.T) {
	d := NewDotEnv()
	if fs := d.Detect("config.yaml", "KEY=value"); fs != nil {
		t.Fatalf("dotenv tidak boleh aktif untuk non-.env, dapat %v", fs)
	}
	if fs := d.Detect(".env.production", "A=1"); len(fs) != 1 {
		t.Fatalf(".env.production harus diproses, dapat %v", fs)
	}
}

func TestDotEnv_CRLFOffsets(t *testing.T) {
	d := NewDotEnv()
	content := "A=one\r\nB=two\r\n"
	fs := d.Detect(".env", content)
	vals := found(content, fs)
	if len(vals) != 2 || vals[0] != "one" || vals[1] != "two" {
		t.Fatalf("offset CRLF salah: %v", vals)
	}
}

func TestRegex_KnownPatterns(t *testing.T) {
	r := NewRegex()
	cases := map[string]string{
		"aws":   "AKIAIOSFODNN7EXAMPLE",
		"jwt":   "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
		"dburi": "postgres://user:pass@localhost:5432/db",
		"ghp":   "ghp_1234567890abcdefABCDEF1234567890abcd",
	}
	for name, secret := range cases {
		content := "value = " + secret
		fs := r.Detect("x.txt", content)
		if len(fs) == 0 {
			t.Fatalf("%s: tidak terdeteksi dalam %q", name, content)
		}
	}
}

func TestRegex_GenericAssignmentMasksOnlyValue(t *testing.T) {
	r := NewRegex()
	content := `DB_PASSWORD=supersecret`
	fs := r.Detect("app.conf", content)
	if len(fs) == 0 {
		t.Fatal("generic assignment tidak terdeteksi")
	}
	// Hanya value yang di-span, bukan seluruh baris.
	if got := fs[0].Value(content); got != "supersecret" {
		t.Fatalf("harus mask value saja, dapat %q", got)
	}
}

func TestRegex_GenericAssignmentMasksWholeQuotedValue(t *testing.T) {
	r := NewRegex()
	cases := []struct {
		content string
		want    string
	}{
		{`{"PASSWORD": "correct horse battery staple #1"}`, `correct horse battery staple #1`},
		{`DB_PASSWORD='correct horse battery staple #1'`, `correct horse battery staple #1`},
		{`API_TOKEN="first \"quoted\" value"`, `first \"quoted\" value`},
	}
	for _, tc := range cases {
		fs := r.Detect("app.conf", tc.content)
		if len(fs) != 1 {
			t.Fatalf("expected one secret span in %q, got %d", tc.content, len(fs))
		}
		if got := fs[0].Value(tc.content); got != tc.want {
			t.Errorf("masked span for %q = %q, want %q", tc.content, got, tc.want)
		}
	}
}

func TestRegex_ExpandedPatterns(t *testing.T) {
	r := NewRegex()
	cases := map[string]string{
		"gitlab":          "glpat-ABCDEFGHIJ1234567890",
		"anthropic":       "sk-ant-api03-ABCDEFGHIJ1234567890",
		"npm":             "npm_abcdefghijklmnopqrstuvwxyz0123456789",
		"sendgrid":        "SG.ABCDEFGHIJKLMNOPQRSTUV.ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghij",
		"huggingface":     "hf_ABCDEFGHIJKLMNOPQRSTUVWXYZ01234567",
		"basic_auth":      "https://user:p4ssw0rd@internal.example.com/path",
		"access_key":      "access_key: zzzyyyxxx000",
		"client_secret":   "client_secret = abcdef123456",
		"authorization":   `Authorization: Bearer abcDEF123456tokenvalue`,
		"json_conf_token": `"CONF_TOKEN": "ODg0Njk2NTI2NTIzOmConfluencePatSecret"`,
		"json_pat":        `"CONFLUENCE_PAT": "my-secret-pat-value-999"`,
		"atlassian_token": `ATATT3xFfGF0abcdef1234567890ABCDEF123456`,
		"custom_header":   `X-API-Key: my_custom_header_secret_key_123`,
		"cli_flag_pat":    `samar --pat cli_secret_pat_value`,
		"curl_basic_u":    `curl -u admin:curlBasicSecretPass123 https://confluence.corp/rest/api`,
	}
	for name, content := range cases {
		if len(r.Detect("f.txt", content)) == 0 {
			t.Errorf("%s: tidak terdeteksi dalam %q", name, content)
		}
	}
}

func TestRegex_JSONConfigMasksOnlySecretValue(t *testing.T) {
	r := NewRegex()
	content := `{"env": {"CONF_TOKEN": "secretConfluenceToken123", "CONFLUENCE_PAT": "secretPat456"}}`
	fs := r.Detect("mcp_config.json", content)
	vals := found(content, fs)
	if len(vals) != 2 || vals[0] != "secretConfluenceToken123" || vals[1] != "secretPat456" {
		t.Fatalf("JSON config secret value tidak tepat terdeteksi: %v", vals)
	}
}

func TestRegex_NoFalsePositiveOnNeutralValues(t *testing.T) {
	r := NewRegex()
	// Nilai non-secret dengan NAMA FIELD netral tidak boleh dimasking
	// (hindari merusak tool dengan over-masking).
	neutral := []string{
		"endpoint: https://api.example.com/v1",
		"region: us-east-1",
		"timeout: 30000",
		"id: 550e8400-e29b-41d4-a716-446655440000", // UUID polos
		"name: my-service",
		"PATH: /usr/local/bin:/usr/bin",
		"pattern: *.go",
	}
	for _, c := range neutral {
		if fs := r.Detect("config.yaml", c); len(fs) != 0 {
			t.Errorf("false-positive: %q seharusnya tidak dimasking, dapat %d temuan", c, len(fs))
		}
	}
}

func TestRegistry_MergesOverlap(t *testing.T) {
	// DB URI dengan "PASSWORD" bisa cocok dua rule; registry harus menggabung.
	reg := NewRegistry(NewRegex())
	content := "DATABASE_PASSWORD=postgres://u:p@h:5432/d"
	fs := reg.Detect("x.conf", content)
	// Setelah merge tidak boleh ada rentang tumpang tindih.
	for i := 1; i < len(fs); i++ {
		if fs[i].Start < fs[i-1].End {
			t.Fatalf("rentang tumpang tindih setelah merge: %+v", fs)
		}
	}
}

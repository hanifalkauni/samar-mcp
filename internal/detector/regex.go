package detector

import "regexp"

// rule memasangkan nama (untuk audit) dengan pola. Jika pola punya grup tangkap
// bernama "secret", hanya grup itu yang dimasking; jika tidak, seluruh match.
type rule struct {
	name string
	re   *regexp.Regexp
}

// Regex adalah detektor berbasis aturan untuk pola kredensial yang dikenal.
// Rule-set awal diilhami gitleaks/detect-secrets (PRD §5.2, §8). Menambah pola
// baru = tambah entri di defaultRules, tanpa mengubah konsumen (Open/Closed).
type Regex struct {
	rules []rule
}

// NewRegex membuat detektor dengan rule-set default.
func NewRegex() *Regex {
	return &Regex{rules: defaultRules()}
}

// Name memenuhi Detector; format "regex:<rule>" ditetapkan per-temuan di Detect.
func (r *Regex) Name() string { return "regex" }

// Detect menjalankan semua aturan dan mengembalikan rentang byte yang cocok.
func (r *Regex) Detect(_ , content string) []Finding {
	var findings []Finding
	for _, ru := range r.rules {
		idx := ru.re.SubexpIndex("secret")
		for _, m := range ru.re.FindAllStringSubmatchIndex(content, -1) {
			start, end := m[0], m[1]
			if idx > 0 && m[2*idx] >= 0 { // ada grup "secret"
				start, end = m[2*idx], m[2*idx+1]
			}
			if end > start {
				findings = append(findings, Finding{
					Start:    start,
					End:      end,
					Detector: "regex:" + ru.name,
				})
			}
		}
	}
	return findings
}

// defaultRules mengembalikan rule-set. Pola konservatif — menghindari
// false-positive (tidak mask-semua / tidak entropy-based yang menangkap
// UUID/hash/base64 non-secret). Diperluas dari gitleaks/detect-secrets.
func defaultRules() []rule {
	must := regexp.MustCompile
	return []rule{
		// --- Provider API keys / tokens (prefix spesifik, pasti secret) ---
		{"aws_access_key_id", must(`A(?:KIA|SIA|GPA|IDA|ROA|IPA|NPA|NVA)[0-9A-Z]{16}`)},
		{"github_pat", must(`ghp_[0-9A-Za-z]{36}`)},
		{"github_fine_grained", must(`github_pat_[0-9A-Za-z_]{22,}`)},
		{"github_oauth", must(`gho_[0-9A-Za-z]{36}`)},
		{"gitlab_pat", must(`glpat-[0-9A-Za-z\-_]{20,}`)},
		{"openai", must(`sk-[A-Za-z0-9]{20,}`)},
		{"anthropic", must(`sk-ant-[A-Za-z0-9\-_]{20,}`)},
		{"slack_token", must(`xox[baprs]-[0-9A-Za-z-]{10,}`)},
		{"slack_webhook", must(`https://hooks\.slack\.com/services/[A-Za-z0-9/]+`)},
		{"stripe_secret", must(`sk_live_[0-9A-Za-z]{16,}`)},
		{"stripe_restricted", must(`rk_live_[0-9A-Za-z]{16,}`)},
		{"google_api", must(`AIza[0-9A-Za-z\-_]{35}`)},
		{"gcp_sa_key", must(`"private_key_id"\s*:\s*"[0-9a-f]{40}"`)},
		{"sendgrid", must(`SG\.[A-Za-z0-9\-_]{22}\.[A-Za-z0-9\-_]{43}`)},
		{"twilio_sid", must(`AC[0-9a-fA-F]{32}`)},
		{"twilio_key", must(`SK[0-9a-fA-F]{32}`)},
		{"npm_token", must(`npm_[0-9A-Za-z]{36}`)},
		{"heroku_api", must(`(?i)heroku[0-9A-Za-z\-]*\s*[:=]\s*["']?[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`)},
		{"huggingface", must(`hf_[A-Za-z0-9]{30,}`)},
		{"azure_storage_key", must(`(?i)AccountKey\s*=\s*[A-Za-z0-9+/]{40,}={0,2}`)},
		{"jwt", must(`eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}`)},

		// --- Kredensial dalam URL / connection string ---
		{"db_uri", must(`(?:postgres|postgresql|mysql|redis|mongodb|amqp|amqps)(?:\+srv)?://[^\s"'<>]+`)},
		{"basic_auth_url", must(`https?://[^\s:/@"']+:[^\s:/@"']+@[^\s"'<>]+`)},

		// --- Private keys / certs ---
		{"private_key_block", must(`(?s)-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA |PGP |ENCRYPTED )?PRIVATE KEY-----`)},

		// --- Assignment generik: nama field mengandung kata-kunci secret ---
		// Hanya VALUE (grup "secret") yang dimasking. Kata-kunci diperluas.
		{"generic_assignment", must(`(?i)(?:[A-Z0-9_]*(?:SECRET|PASSWORD|PASSWD|PWD|TOKEN|API[_-]?KEY|ACCESS[_-]?KEY|PRIVATE[_-]?KEY|CLIENT[_-]?SECRET|CREDENTIAL|AUTH|BEARER|SIGNING[_-]?KEY|ENCRYPTION[_-]?KEY|SALT|DSN|CONNECTION[_-]?STRING)[A-Z0-9_]*)\s*[:=]\s*["']?(?P<secret>[^\s"'#]+)["']?`)},

		// --- Header Authorization: Bearer/Basic <token> ---
		{"authorization_header", must(`(?i)authorization["']?\s*[:=]\s*["']?(?:bearer|basic)\s+(?P<secret>[A-Za-z0-9\-._~+/]+=*)`)},
	}
}

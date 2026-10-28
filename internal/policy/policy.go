// Package policy menegakkan kontrol exfiltration / confused-deputy pada jalur
// outbound (PRD §5.6). Policy berjalan SEBELUM token di-unmask: jika sebuah
// token hendak dikirim ke destinasi jaringan eksternal yang tidak ada di
// allowlist, operasi diblokir (fail-closed) sehingga secret asli tidak pernah
// dipulihkan untuk perintah berbahaya.
package policy

import (
	"fmt"
	"regexp"
	"strings"
)

// HostAllower memutuskan apakah sebuah host eksternal boleh menerima secret.
// Dipenuhi oleh *allowlist.Allowlist (Dependency Inversion).
type HostAllower interface {
	Allowed(host string) bool
}

// Decision adalah hasil evaluasi policy.
type Decision struct {
	Allow             bool
	Reason            string   // alasan deny, untuk audit (PRD §10) dan pesan error
	Host              string   // host sink pertama yang menyebabkan deny (bila ada)
	NeedsConfirmation bool     // true: command membawa secret dan harus disetujui manusia sebelum dieksekusi
	Hosts             []string // host tujuan yang terdeteksi (untuk pesan konfirmasi/audit)
}

// Policy mengevaluasi string command terhadap aturan egress.
type Policy struct {
	allow        HostAllower
	urlRe        *regexp.Regexp
	netTools     map[string]struct{}
	rawHostTools map[string]struct{}
}

// New membuat policy dengan HostAllower yang diberikan.
func New(a HostAllower) *Policy {
	return &Policy{
		allow: a,
		// Menangani skema http(s), ftp, sftp, ssh, scp, ws(s) serta mengabaikan userinfo (user:pass@) sebelum host.
		urlRe: regexp.MustCompile(`(?i)\b(?:https?|s?ftp|ssh|scp|wss?)://(?:[^\s/'"@]+@)?([^\s/:"'?#]+)`),
		netTools: map[string]struct{}{
			"curl": {}, "wget": {}, "nc": {}, "ncat": {}, "socat": {},
			"ssh": {}, "scp": {}, "sftp": {}, "rsync": {}, "telnet": {}, "ftp": {},
			"invoke-webrequest": {}, "iwr": {}, "invoke-restmethod": {}, "irm": {},
			"certutil": {}, "bitsadmin": {},
			"nslookup": {}, "dig": {}, "resolve-dnsname": {}, "ping": {},
		},
		// Alat jaringan/DNS yang menerima argumen host mentah tanpa skema URL (rentan bypass jika digabung URL allowlist).
		rawHostTools: map[string]struct{}{
			"nc": {}, "ncat": {}, "socat": {}, "telnet": {},
			"nslookup": {}, "dig": {}, "resolve-dnsname": {}, "ping": {},
		},
	}
}

// tokenAware adalah kontrak minimal untuk mengenali apakah string mengandung
// token Samar. Dipenuhi oleh restorer/vault via TokenPattern.
type tokenAware interface {
	TokenPattern() (prefix, suffix string)
}

// EvaluateCommand memeriksa command yang (masih) mengandung token. containsToken
// menandai apakah command membawa token Samar sama sekali; bila tidak, tidak
// ada secret yang berisiko dan policy mengizinkan.
//
// Aturan (fail-closed):
//  1. Tidak ada token         -> ALLOW (tak ada secret untuk dibocorkan).
//  2. Ada token + ada URL ke host di luar allowlist                 -> DENY.
//  3. Ada token + memakai network tool tanpa host URL yang bisa diverifikasi -> DENY.
//  4. Semua command lain yang membawa token perlu konfirmasi manusia sebelum
//     dijalankan. Command string tidak cukup untuk membuktikan proses lokal.
func (p *Policy) EvaluateCommand(command string, containsToken bool) Decision {
	if !containsToken {
		return Decision{Allow: true, Reason: "no_token"}
	}

	hosts := p.extractHosts(command)
	usesNetTool, usesRawHostTool := p.detectNetworkTools(command)

	// Jika ada host eksternal terdeteksi, semuanya wajib ada di allowlist.
	for _, h := range hosts {
		if !p.allow.Allowed(h) {
			return Decision{Allow: false, Host: h, Reason: "egress_host_not_in_allowlist"}
		}
	}

	// Raw socket / DNS exfiltration tool (nc, ncat, dig, nslookup, dll.) dengan token
	// atau network tool tanpa host URL yang bisa diverifikasi -> fail-closed.
	if usesRawHostTool || (usesNetTool && len(hosts) == 0) {
		return Decision{Allow: false, Reason: "network_tool_with_unresolved_host"}
	}

	// String perintah shell tidak bisa membuktikan command lokal: skrip dan
	// interpreter dapat membuka koneksi tanpa URL literal atau nama tool umum.
	// Karena itu setiap command yang membawa token harus disetujui sebelum
	// restorasi, bukan hanya command yang dikenali sebagai jaringan.
	return Decision{Allow: true, Reason: "secret_command_requires_confirmation", NeedsConfirmation: true, Hosts: hosts}
}

// extractHosts menarik host dari URL eksplisit. Host tujuan tanpa URL tidak
// dianggap tepercaya oleh parser command.
func (p *Policy) extractHosts(cmd string) []string {
	seen := map[string]struct{}{}
	var hosts []string
	add := func(h string) {
		h = strings.ToLower(strings.Trim(h, "/"))
		if h == "" {
			return
		}
		if _, ok := seen[h]; !ok {
			seen[h] = struct{}{}
			hosts = append(hosts, h)
		}
	}
	for _, m := range p.urlRe.FindAllStringSubmatch(cmd, -1) {
		add(m[1])
	}
	return hosts
}

// detectNetworkTools memeriksa apakah perintah memanggil network tool atau raw-host/DNS tool.
func (p *Policy) detectNetworkTools(cmd string) (usesNet, usesRaw bool) {
	tokens := strings.FieldsFunc(cmd, func(r rune) bool {
		switch r {
		case ' ', '\t', '\n', '\r', ';', '|', '&', '(', ')', '`', '$', '<', '>', '"', '\'':
			return true
		}
		return false
	})
	for _, field := range tokens {
		name := strings.ToLower(field)
		// buang path: /usr/bin/curl -> curl
		if i := strings.LastIndexAny(name, `/\`); i >= 0 {
			name = name[i+1:]
		}
		name = strings.TrimSuffix(name, ".exe")
		if _, ok := p.netTools[name]; ok {
			usesNet = true
		}
		if _, ok := p.rawHostTools[name]; ok {
			usesRaw = true
		}
	}
	return usesNet, usesRaw
}

// DenyError memformat Decision menjadi error yang aman ditampilkan ke LLM.
func DenyError(d Decision) error {
	if d.Host != "" {
		return fmt.Errorf("exfiltration policy: host %q tidak ada di egress allowlist; eksekusi dibatalkan (%s)", d.Host, d.Reason)
	}
	return fmt.Errorf("exfiltration policy: eksekusi dibatalkan (%s)", d.Reason)
}

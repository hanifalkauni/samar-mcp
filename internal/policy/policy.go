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
	NeedsConfirmation bool     // true: diizinkan oleh allowlist TAPI mengirim secret ke jaringan -> minta konfirmasi manusia (§5.6/§13.2)
	Hosts             []string // host tujuan yang terdeteksi (untuk pesan konfirmasi/audit)
}

// Policy mengevaluasi string command terhadap aturan egress.
type Policy struct {
	allow     HostAllower
	urlRe     *regexp.Regexp
	netTools  map[string]struct{}
}

// New membuat policy dengan HostAllower yang diberikan.
func New(a HostAllower) *Policy {
	return &Policy{
		allow:    a,
		urlRe:    regexp.MustCompile(`(?i)\b(?:https?|ftp)://([^\s/:"']+)`),
		netTools: map[string]struct{}{"curl": {}, "wget": {}, "nc": {}, "ncat": {}, "ssh": {}, "scp": {}, "telnet": {}, "ftp": {}},
	}
}

// tokenAware adalah kontrak minimal untuk mengenali apakah string mengandung
// token SafeEnv. Dipenuhi oleh restorer/vault via TokenPattern.
type tokenAware interface {
	TokenPattern() (prefix, suffix string)
}

// EvaluateCommand memeriksa command yang (masih) mengandung token. containsToken
// menandai apakah command membawa token SafeEnv sama sekali; bila tidak, tidak
// ada secret yang berisiko dan policy mengizinkan.
//
// Aturan (fail-closed):
//  1. Tidak ada token         -> ALLOW (tak ada secret untuk dibocorkan).
//  2. Ada token + ada URL ke host di luar allowlist                 -> DENY.
//  3. Ada token + memakai network tool (curl/wget/nc/ssh/...)       -> DENY,
//     kecuali seluruh host tujuan yang terdeteksi ada di allowlist.
//  4. Selain itu (token dipakai perintah lokal murni)               -> ALLOW.
func (p *Policy) EvaluateCommand(command string, containsToken bool) Decision {
	if !containsToken {
		return Decision{Allow: true, Reason: "no_token"}
	}

	hosts := p.extractHosts(command)
	usesNetTool := p.usesNetworkTool(command)

	// Jika ada host eksternal terdeteksi, semuanya wajib ada di allowlist.
	for _, h := range hosts {
		if !p.allow.Allowed(h) {
			return Decision{Allow: false, Host: h, Reason: "egress_host_not_in_allowlist"}
		}
	}

	// Network tool dengan token tapi tanpa host yang bisa diurai (mis. host dari
	// variabel) tidak dapat diverifikasi aman -> fail-closed.
	if usesNetTool && len(hosts) == 0 {
		return Decision{Allow: false, Reason: "network_tool_with_unresolved_host"}
	}

	// Token mengalir ke host jaringan yang SUDAH di allowlist: diizinkan, tetapi
	// karena secret akan keluar ke jaringan, minta konfirmasi manusia default-on
	// (§5.6/§13.2). Perintah lokal murni (tanpa host/net-tool) tidak perlu konfirmasi.
	if len(hosts) > 0 || usesNetTool {
		return Decision{Allow: true, Reason: "ok_needs_confirmation", NeedsConfirmation: true, Hosts: hosts}
	}

	return Decision{Allow: true, Reason: "ok"}
}

// extractHosts menarik host dari URL eksplisit maupun argumen host:port setelah
// network tool sederhana (mis. "nc host 1234").
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

// usesNetworkTool true bila token pertama (nama program) atau token mana pun
// adalah alat jaringan dikenal.
func (p *Policy) usesNetworkTool(cmd string) bool {
	for _, field := range strings.Fields(cmd) {
		name := strings.ToLower(field)
		// buang path: /usr/bin/curl -> curl
		if i := strings.LastIndexAny(name, `/\`); i >= 0 {
			name = name[i+1:]
		}
		if _, ok := p.netTools[name]; ok {
			return true
		}
	}
	return false
}

// DenyError memformat Decision menjadi error yang aman ditampilkan ke LLM.
func DenyError(d Decision) error {
	if d.Host != "" {
		return fmt.Errorf("exfiltration policy: host %q tidak ada di egress allowlist; eksekusi dibatalkan (%s)", d.Host, d.Reason)
	}
	return fmt.Errorf("exfiltration policy: eksekusi dibatalkan (%s)", d.Reason)
}

package masking

import (
	"strings"
	"testing"

	"github.com/hanifalkauni/samar-mcp/internal/detector"
	"github.com/hanifalkauni/samar-mcp/internal/idgen"
	"github.com/hanifalkauni/samar-mcp/internal/vault"
)

func newEngine() (*Engine, *vault.Vault) {
	v := vault.New(idgen.NewCryptoGen())
	det := detector.NewRegistry(detector.NewDotEnv(), detector.NewRegex())
	return New(det, v), v
}

func TestMask_DotEnvReplacesValues(t *testing.T) {
	e, v := newEngine()
	content := "API_KEY=abcdef123456\nHOST=localhost\n"
	res := e.Mask(".env", content)

	if strings.Contains(res.Masked, "abcdef123456") {
		t.Fatalf("secret masih muncul di output: %q", res.Masked)
	}
	// .env memasking SEMUA value (PRD §7), termasuk 'localhost' yang tampak non-rahasia.
	if strings.Contains(res.Masked, "localhost") {
		t.Fatalf("di file .env, semua value harus dimasking termasuk 'localhost': %q", res.Masked)
	}
	if res.SecretCount != 2 {
		t.Fatalf("harap 2 secret (.env mask semua value), dapat %d", res.SecretCount)
	}
	// Setiap token harus bisa dipulihkan ke nilai asli.
	for _, tok := range extractTokens(res.Masked) {
		if _, ok := v.Detokenize(tok); !ok {
			t.Fatalf("token %q tidak ada di vault", tok)
		}
	}
}

func TestMask_NoFindingsPassthrough(t *testing.T) {
	e, _ := newEngine()
	content := "halo dunia, tidak ada rahasia di sini"
	res := e.Mask("notes.txt", content)
	if res.Masked != content || res.SecretCount != 0 {
		t.Fatalf("konten tanpa secret harus apa adanya, dapat %q (n=%d)", res.Masked, res.SecretCount)
	}
}

func TestMask_SameSecretSameToken(t *testing.T) {
	e, _ := newEngine()
	// Secret identik muncul dua kali -> token identik (determinisme, PRD §6.5).
	content := "A=dupervalue\nB=dupervalue\n"
	res := e.Mask(".env", content)
	toks := extractTokens(res.Masked)
	if len(toks) != 2 {
		t.Fatalf("harap 2 token, dapat %v", toks)
	}
	if toks[0] != toks[1] {
		t.Fatalf("secret sama harus token sama: %q vs %q", toks[0], toks[1])
	}
}

func TestMask_OffsetIntegrityMultiline(t *testing.T) {
	e, v := newEngine()
	content := "line1\nTOKEN=aaa\nline3\nPASSWORD=bbb\nend"
	res := e.Mask(".env", content)
	// Baris non-secret harus utuh.
	if !strings.Contains(res.Masked, "line1\n") || !strings.Contains(res.Masked, "\nline3\n") || !strings.HasSuffix(res.Masked, "\nend") {
		t.Fatalf("struktur baris rusak: %q", res.Masked)
	}
	for _, tok := range extractTokens(res.Masked) {
		if _, ok := v.Detokenize(tok); !ok {
			t.Fatalf("token %q tidak valid", tok)
		}
	}
}

// extractTokens menarik semua "__SAMAR_SECRET_...__" dari teks.
func extractTokens(s string) []string {
	const pre, suf = "__SAMAR_SECRET_", "__"
	var out []string
	for {
		i := strings.Index(s, pre)
		if i < 0 {
			break
		}
		rest := s[i+len(pre):]
		j := strings.Index(rest, suf)
		if j < 0 {
			break
		}
		out = append(out, pre+rest[:j]+suf)
		s = rest[j+len(suf):]
	}
	return out
}

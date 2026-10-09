package restore

import (
	"strings"
	"testing"

	"github.com/hanifalkauni/samar-mcp/internal/idgen"
	"github.com/hanifalkauni/samar-mcp/internal/vault"
)

func newRestorer() (*Restorer, *vault.Vault) {
	v := vault.New(idgen.NewCryptoGen())
	return New(v), v
}

func TestRestore_RoundTrip(t *testing.T) {
	r, v := newRestorer()
	tok := v.Tokenize("s3cr3t-value")
	out, err := r.Restore("auth=" + tok + ";end")
	if err != nil {
		t.Fatalf("tak terduga error: %v", err)
	}
	if out != "auth=s3cr3t-value;end" {
		t.Fatalf("restorasi salah: %q", out)
	}
}

func TestRestore_MultipleSameToken(t *testing.T) {
	r, v := newRestorer()
	tok := v.Tokenize("dup")
	out, err := r.Restore(tok + " " + tok)
	if err != nil || out != "dup dup" {
		t.Fatalf("restorasi ganda salah: %q err=%v", out, err)
	}
}

func TestRestore_CorruptedTokenFailsClosed(t *testing.T) {
	r, _ := newRestorer()
	// Bentuk placeholder utuh tapi ID tak dikenal.
	_, err := r.Restore("x=__SAMAR_SECRET_DEADBEEF__")
	if err == nil {
		t.Fatal("token tak dikenal harus error (fail-closed)")
	}
	if _, ok := err.(*ErrCorruptedToken); !ok {
		t.Fatalf("tipe error harus ErrCorruptedToken, dapat %T", err)
	}
}

func TestRestore_NoTokenPassthrough(t *testing.T) {
	r, _ := newRestorer()
	out, err := r.Restore("tidak ada token di sini")
	if err != nil || out != "tidak ada token di sini" {
		t.Fatalf("konten tanpa token harus apa adanya: %q err=%v", out, err)
	}
}

func TestHasTruncatedToken(t *testing.T) {
	r, _ := newRestorer()
	cases := map[string]bool{
		"v=__SAMAR_SECRET_12AB":   true,  // prefix tanpa suffix
		"v=__SAMAR_SECRET_12":     true,  // terpotong
		"v=__SAMAR_SECRET_XYZ__":  true,  // non-hex (termutasi)
		"v=__SAMAR_SECRET_1A2B__": false, // utuh & hex
		"tidak ada token":        false,
	}
	for in, want := range cases {
		if got := r.HasTruncatedToken(in); got != want {
			t.Errorf("HasTruncatedToken(%q)=%v, mau %v", in, got, want)
		}
	}
}

func TestRestore_DoesNotLeakOnError(t *testing.T) {
	r, v := newRestorer()
	good := v.Tokenize("goodsecret")
	// Satu token valid + satu korup: harus error, TIDAK mengembalikan parsial.
	out, err := r.Restore(good + " __SAMAR_SECRET_BADBAD01__")
	if err == nil {
		t.Fatal("harus error karena ada token korup")
	}
	if strings.Contains(out, "goodsecret") {
		t.Fatalf("tidak boleh mengembalikan secret parsial saat abort: %q", out)
	}
}

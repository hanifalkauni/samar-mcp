package vault

import (
	"strconv"
	"sync"
	"testing"
)

// seqGen adalah TokenGenerator deterministik untuk test (counter berurutan).
type seqGen struct {
	mu sync.Mutex
	n  int
}

func (g *seqGen) NewID() string {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.n++
	return strconv.Itoa(g.n)
}

func TestTokenize_DeterministicPerSecret(t *testing.T) {
	v := New(&seqGen{})
	a := v.Tokenize("hunter2")
	b := v.Tokenize("hunter2")
	if a != b {
		t.Fatalf("secret sama harus menghasilkan token sama: %q != %q", a, b)
	}
	c := v.Tokenize("different")
	if c == a {
		t.Fatalf("secret berbeda harus token berbeda, keduanya %q", c)
	}
	if v.Len() != 2 {
		t.Fatalf("harap 2 entri unik, dapat %d", v.Len())
	}
}

func TestTokenize_FormatAndEmpty(t *testing.T) {
	v := New(&seqGen{})
	if got := v.Tokenize(""); got != "" {
		t.Fatalf("secret kosong tidak di-tokenisasi, dapat %q", got)
	}
	tok := v.Tokenize("x")
	if tok != "__SAMAR_SECRET_1__" {
		t.Fatalf("format token tak sesuai: %q", tok)
	}
	pre, suf := v.TokenPattern()
	if pre != "__SAMAR_SECRET_" || suf != "__" {
		t.Fatalf("TokenPattern salah: %q %q", pre, suf)
	}
}

func TestDetokenize_RoundTripAndFailClosed(t *testing.T) {
	v := New(&seqGen{})
	tok := v.Tokenize("s3cr3t")
	got, ok := v.Detokenize(tok)
	if !ok || got != "s3cr3t" {
		t.Fatalf("round-trip gagal: got=%q ok=%v", got, ok)
	}
	// Token termutasi/terpotong harus gagal (fail-closed, PRD §7).
	if _, ok := v.Detokenize("__SAMAR_SECRET_999__"); ok {
		t.Fatal("token tak dikenal seharusnya ok=false")
	}
	if _, ok := v.Detokenize(tok[:len(tok)-2]); ok {
		t.Fatal("token terpotong seharusnya ok=false")
	}
}

func TestTokenize_TokenNotDerivedFromSecret(t *testing.T) {
	// Token tidak boleh mengandung nilai asli (anti kebocoran, PRD §5.2).
	v := New(&seqGen{})
	secret := "admin123"
	tok := v.Tokenize(secret)
	if contains(tok, secret) {
		t.Fatalf("token %q mengandung secret %q", tok, secret)
	}
}

func TestTokenize_ConcurrentSameSecret(t *testing.T) {
	v := New(&seqGen{})
	var wg sync.WaitGroup
	tokens := make([]string, 50)
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			tokens[idx] = v.Tokenize("shared")
		}(i)
	}
	wg.Wait()
	for _, tk := range tokens {
		if tk != tokens[0] {
			t.Fatalf("race: token tak konsisten %q vs %q", tk, tokens[0])
		}
	}
	if v.Len() != 1 {
		t.Fatalf("harap 1 entri untuk secret bersama, dapat %d", v.Len())
	}
	_ = v.debugString()
}

func contains(s, sub string) bool {
	return len(sub) > 0 && len(s) >= len(sub) && indexOf(s, sub) >= 0
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

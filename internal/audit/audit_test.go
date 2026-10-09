package audit

import (
	"bytes"
	"encoding/json"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/hanifalkauni/samar-mcp/internal/leakscan"
)

type seqGen struct {
	mu sync.Mutex
	n  int
}

func (g *seqGen) NewID() string { g.mu.Lock(); defer g.mu.Unlock(); g.n++; return "e" + strconv.Itoa(g.n) }

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Unix(1700000000, 0).UTC() }

func newLogger(chain bool) (*Logger, *bytes.Buffer) {
	var buf bytes.Buffer
	l := New(&buf, Options{SessionID: "sess-1", Gen: &seqGen{}, Clock: fixedClock{}, HashChain: chain})
	return l, &buf
}

func TestLog_JSONLShape(t *testing.T) {
	l, buf := newLogger(false)
	if err := l.Log(Event{EventType: EventRead, Tool: "samar_read_file"}); err != nil {
		t.Fatal(err)
	}
	line := strings.TrimSpace(buf.String())
	var e Event
	if err := json.Unmarshal([]byte(line), &e); err != nil {
		t.Fatalf("baris bukan JSON valid: %v", err)
	}
	if e.SessionID != "sess-1" || e.EventID != "e1" || e.EventType != EventRead {
		t.Fatalf("field standar tidak terisi: %+v", e)
	}
	if e.TS == "" {
		t.Fatal("ts kosong")
	}
}

func TestLog_ZeroPlaintext(t *testing.T) {
	l, buf := newLogger(false)
	secret := "SuperSecretValue"
	ref := Fingerprint(secret)
	l.Log(Event{EventType: EventMask, Secret: &ref, Decision: "allow"})

	if !leakscan.Clean(buf.String(), []string{secret}) {
		t.Fatalf("AUDIT BOCOR plaintext: %s", buf.String())
	}
	// Fingerprint harus ada dan ter-truncate, panjang value tercatat.
	if !strings.Contains(buf.String(), "sha256:") {
		t.Fatal("fingerprint tidak tercatat")
	}
	if ref.ValueLen != len(secret) {
		t.Fatalf("value_len salah: %d", ref.ValueLen)
	}
}

func TestLog_SeverityRouting(t *testing.T) {
	l, buf := newLogger(false)
	l.Log(Event{EventType: EventPolicyBlock, Reason: "egress_host_not_in_allowlist"})
	if !strings.Contains(buf.String(), `"severity":"warning"`) {
		t.Fatalf("policy_block harus warning: %s", buf.String())
	}
}

func TestLog_HashChainLinks(t *testing.T) {
	l, buf := newLogger(true)
	l.Log(Event{EventType: EventRead})
	l.Log(Event{EventType: EventWrite})

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("harap 2 baris, dapat %d", len(lines))
	}
	var e1, e2 Event
	json.Unmarshal([]byte(lines[0]), &e1)
	json.Unmarshal([]byte(lines[1]), &e2)
	if e1.PrevHash != "" {
		t.Fatal("entri pertama tidak boleh punya prev_hash")
	}
	if e2.PrevHash == "" || !strings.HasPrefix(e2.PrevHash, "sha256:") {
		t.Fatalf("entri kedua harus menautkan hash entri pertama: %q", e2.PrevHash)
	}
}

func TestFingerprint_SameValueSameFP(t *testing.T) {
	a := Fingerprint("x")
	b := Fingerprint("x")
	if a.ValueFingerprint != b.ValueFingerprint {
		t.Fatal("fingerprint harus deterministik")
	}
	if Fingerprint("y").ValueFingerprint == a.ValueFingerprint {
		t.Fatal("nilai beda harus fingerprint beda")
	}
}

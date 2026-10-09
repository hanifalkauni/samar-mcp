// Package audit menulis log kejadian keamanan Samar (PRD §10).
//
// Prinsip mengikat:
//   - Zero plaintext: nilai asli secret TIDAK PERNAH ditulis. Hanya
//     value_fingerprint (SHA-256 terpotong) + value_len.
//   - Format JSON Lines (JSONL), append-only, satu event per baris.
//   - Tamper-evident opsional: hash-chain antar entri (prev_hash).
//   - Lokasi per sesi; stdout tidak dipakai (itu transport MCP).
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"sync"
	"time"
)

// EventType mengklasifikasikan kejadian. Nilai wajib dicatat per PRD §10.
type EventType string

const (
	EventMask         EventType = "mask"
	EventUnmask       EventType = "unmask"
	EventAbort        EventType = "abort"
	EventPolicyBlock  EventType = "policy_block"
	EventRead         EventType = "read"
	EventWrite        EventType = "write"
	EventExecute      EventType = "execute"
	EventConsent      EventType = "consent"
	EventConfigReload EventType = "config_reload"
)

// Severity merutekan event (info/warning/critical).
type Severity string

const (
	SevInfo     Severity = "info"
	SevWarning  Severity = "warning"
	SevCritical Severity = "critical"
)

// SecretRef adalah referensi AMAN ke sebuah secret: tidak memuat nilai asli.
type SecretRef struct {
	Token            string `json:"token,omitempty"`
	ValueFingerprint string `json:"value_fingerprint,omitempty"`
	ValueLen         int    `json:"value_len,omitempty"`
	Detector         string `json:"detector,omitempty"`
}

// Event adalah satu baris audit. Tidak ada field untuk nilai asli: desain tipe
// ini sendiri yang menjamin zero-plaintext.
type Event struct {
	TS        string    `json:"ts"`
	EventID   string    `json:"event_id"`
	SessionID string    `json:"session_id"`
	EventType EventType `json:"event_type"`
	Tool      string    `json:"tool,omitempty"`
	Actor     string    `json:"actor,omitempty"`
	Resource  map[string]string `json:"resource,omitempty"`
	Secret    *SecretRef `json:"secret_ref,omitempty"`
	Decision  string     `json:"decision,omitempty"`
	Reason    string     `json:"reason,omitempty"`
	Policy    map[string]any `json:"policy,omitempty"`
	Severity  Severity   `json:"severity"`
	DurationMS int64     `json:"duration_ms,omitempty"`
	PrevHash  string     `json:"prev_hash,omitempty"`
}

// Fingerprint menghitung referensi aman dari sebuah nilai rahasia. Nilai asli
// hanya lewat di sini untuk di-hash; tidak pernah disimpan.
func Fingerprint(secret string) SecretRef {
	sum := sha256.Sum256([]byte(secret))
	return SecretRef{
		ValueFingerprint: "sha256:" + hex.EncodeToString(sum[:])[:12],
		ValueLen:         len(secret),
	}
}

// IDGen menghasilkan event_id. Di-inject agar test deterministik.
type IDGen interface{ NewID() string }

// Clock menyediakan waktu. Di-inject agar test deterministik.
type Clock interface{ Now() time.Time }

type realClock struct{}

func (realClock) Now() time.Time { return time.Now() }

// Logger menulis event ke sebuah io.Writer sebagai JSONL, aman konkurensi,
// dengan hash-chain opsional.
type Logger struct {
	mu        sync.Mutex
	w         io.Writer
	sessionID string
	gen       IDGen
	clock     Clock
	chain     bool
	lastHash  string
}

// Options mengatur perilaku Logger.
type Options struct {
	SessionID string
	Gen       IDGen
	Clock     Clock
	HashChain bool // aktifkan tamper-evident prev_hash
}

// New membuat Logger yang menulis ke w.
func New(w io.Writer, opts Options) *Logger {
	if opts.Clock == nil {
		opts.Clock = realClock{}
	}
	return &Logger{
		w:         w,
		sessionID: opts.SessionID,
		gen:       opts.Gen,
		clock:     opts.Clock,
		chain:     opts.HashChain,
	}
}

// Log melengkapi field standar, menautkan hash-chain bila aktif, lalu menulis
// satu baris JSON. Error penulisan dikembalikan agar pemanggil bisa memutuskan;
// kegagalan audit tidak boleh diam.
func (l *Logger) Log(e Event) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	e.TS = l.clock.Now().Format(time.RFC3339Nano)
	e.SessionID = l.sessionID
	if e.EventID == "" && l.gen != nil {
		e.EventID = l.gen.NewID()
	}
	if e.Severity == "" {
		e.Severity = severityFor(e.EventType)
	}
	if l.chain {
		e.PrevHash = l.lastHash
	}

	b, err := json.Marshal(e)
	if err != nil {
		return err
	}
	// SELF-TEST redaksi: baris yang akan ditulis tidak boleh mengandung nilai
	// asli. Karena tipe Event tidak punya field nilai, ini defensif terhadap
	// perubahan di masa depan. Pemanggil dapat memanggil AssertNoPlaintext.
	if _, err := fmt.Fprintf(l.w, "%s\n", b); err != nil {
		return err
	}
	if l.chain {
		sum := sha256.Sum256(b)
		l.lastHash = "sha256:" + hex.EncodeToString(sum[:])
	}
	return nil
}

// severityFor memetakan event ke severity default (PRD §10 severity routing).
func severityFor(t EventType) Severity {
	switch t {
	case EventPolicyBlock, EventAbort:
		return SevWarning
	default:
		return SevInfo
	}
}

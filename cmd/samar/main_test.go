package main

import (
	"context"
	"errors"
	"io"
	"os"
	"strings"
	"testing"

	"github.com/hanifalkauni/samar-mcp/internal/audit"
)

func TestConfirmer_Modes(t *testing.T) {
	ctx := context.Background()

	// Empty and unknown modes fail closed; only explicit "off" auto-approves.
	if (&confirmer{mode: ""}).Confirm(ctx, "curl https://x", []string{"x"}) {
		t.Fatal("mode kosong harus fail-closed")
	}
	if !(&confirmer{mode: "off"}).Confirm(ctx, "cmd", nil) {
		t.Fatal("mode off harus auto-approve secara eksplisit")
	}

	// deny -> selalu tolak.
	if (&confirmer{mode: "deny"}).Confirm(ctx, "curl https://x", []string{"x"}) {
		t.Fatal("mode deny harus menolak")
	}

	// elicit tanpa server ref -> fail-closed (tolak), tidak panic.
	if (&confirmer{mode: "elicit", srv: nil}).Confirm(ctx, "cmd", nil) {
		t.Fatal("mode elicit tanpa srv harus fail-closed (tolak)")
	}

	// confirmationOff hanya benar untuk mode off yang eksplisit.
	if (&confirmer{mode: ""}).confirmationOff() || !(&confirmer{mode: "off"}).confirmationOff() {
		t.Fatal("confirmationOff harus true hanya untuk off")
	}
	if (&confirmer{mode: "elicit"}).confirmationOff() || (&confirmer{mode: "deny"}).confirmationOff() {
		t.Fatal("confirmationOff harus false untuk elicit/deny")
	}
}

func TestNewConfirmerDefaultsToElicit(t *testing.T) {
	t.Setenv("SAMAR_REQUIRE_CONFIRM", "")
	t.Setenv("SAFEENV_REQUIRE_CONFIRM", "")
	if got := newConfirmer().mode; got != "elicit" {
		t.Fatalf("default mode harus elicit, dapat %q", got)
	}
}

type failedAuditWriter struct{}

func (failedAuditWriter) Write([]byte) (int, error) { return 0, errors.New("disk full") }

func TestAuditAdapterReportsDroppedEvents(t *testing.T) {
	reader, writer, err := os.Pipe()
	if err != nil {
		t.Fatalf("create stderr pipe: %v", err)
	}
	defer reader.Close()
	originalStderr := os.Stderr
	os.Stderr = writer
	defer func() { os.Stderr = originalStderr }()

	adapter := &auditAdapter{log: audit.New(failedAuditWriter{}, audit.Options{})}
	adapter.Event("read", "samar_read_file", "allow", "ok")
	adapter.Event("write", "samar_write_file", "allow", "ok")
	_ = writer.Close()
	os.Stderr = originalStderr

	warning, err := io.ReadAll(reader)
	if err != nil {
		t.Fatalf("read stderr pipe: %v", err)
	}
	if got := strings.Count(string(warning), "audit logging failed"); got != 1 {
		t.Fatalf("expected one dropped-event warning, got %d: %s", got, warning)
	}
}

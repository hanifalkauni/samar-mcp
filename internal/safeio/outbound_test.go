package safeio

import (
	"context"
	"strings"
	"testing"
)

func TestBoundedBufferCapsOutput(t *testing.T) {
	buf := &boundedBuffer{}
	payload := strings.Repeat("x", MaxCommandOutputBytes+16)

	n, err := buf.Write([]byte(payload))
	if err != nil {
		t.Fatalf("write failed: %v", err)
	}
	if n != len(payload) {
		t.Fatalf("write reported %d bytes, want %d", n, len(payload))
	}
	if buf.Len() != MaxCommandOutputBytes || !buf.truncated {
		t.Fatalf("buffer length/truncation = %d/%v", buf.Len(), buf.truncated)
	}
}

func TestOSCommandRunnerHonorsCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	if _, err := (OSCommandRunner{}).Run(ctx, "echo ignored", ""); err == nil {
		t.Fatal("canceled context should stop command execution")
	}
}

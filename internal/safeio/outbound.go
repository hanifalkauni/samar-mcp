package safeio

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"time"
)

// OSFileWriter menulis ke filesystem nyata.
type OSFileWriter struct{}

// WriteFile menulis content ke path dengan permission 0600 (file bisa berisi
// secret asli setelah unmask, jadi batasi akses).
func (OSFileWriter) WriteFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

const commandWaitDelay = 2 * time.Second

// OSCommandRunner menjalankan perintah via shell OS. Pada Windows memakai
// cmd.exe, selainnya /bin/sh. Runner membatasi waktu dan ukuran output, tetapi
// tidak mengisolasi akses filesystem atau jaringan.
type OSCommandRunner struct{}

// Run mengeksekusi command di cwd (opsional) dan menangkap stdout/stderr.
func (OSCommandRunner) Run(ctx context.Context, command, cwd string) (CommandResult, error) {
	runCtx, cancel := context.WithTimeout(ctx, CommandTimeout)
	defer cancel()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(runCtx, "cmd", "/C", command)
	} else {
		cmd = exec.CommandContext(runCtx, "/bin/sh", "-c", command)
	}
	cmd.WaitDelay = commandWaitDelay
	if cwd != "" {
		cmd.Dir = cwd
	}
	stdout, stderr := &boundedBuffer{}, &boundedBuffer{}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	err := cmd.Run()

	res := CommandResult{
		Stdout:          stdout.String(),
		Stderr:          stderr.String(),
		StdoutTruncated: stdout.truncated,
		StderrTruncated: stderr.truncated,
	}
	if ctx.Err() != nil {
		return res, ctx.Err()
	}
	if errors.Is(runCtx.Err(), context.DeadlineExceeded) {
		return res, fmt.Errorf("command timed out after %s", CommandTimeout)
	}
	if runCtx.Err() != nil {
		return res, runCtx.Err()
	}
	if ee, ok := err.(*exec.ExitError); ok {
		res.ExitCode = ee.ExitCode()
		return res, nil // exit non-zero bukan error tool; laporkan ke pemanggil
	}
	if err != nil {
		return res, err
	}
	return res, nil
}

type boundedBuffer struct {
	bytes.Buffer
	truncated bool
}

func (b *boundedBuffer) Write(p []byte) (int, error) {
	remaining := MaxCommandOutputBytes - b.Len()
	if remaining > 0 {
		if len(p) > remaining {
			_, _ = b.Buffer.Write(p[:remaining])
			b.truncated = true
		} else {
			_, _ = b.Buffer.Write(p)
		}
	} else if len(p) > 0 {
		b.truncated = true
	}
	return len(p), nil
}

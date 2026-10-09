package safeio

import (
	"bytes"
	"os"
	"os/exec"
	"runtime"
)

// OSFileWriter menulis ke filesystem nyata.
type OSFileWriter struct{}

// WriteFile menulis content ke path dengan permission 0600 (file bisa berisi
// secret asli setelah unmask, jadi batasi akses).
func (OSFileWriter) WriteFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0o600)
}

// OSCommandRunner menjalankan perintah via shell OS. Pada Windows memakai
// cmd.exe, selainnya /bin/sh. Perintah yang diterima SUDAH di-unmask dan SUDAH
// lolos policy exfiltration — runner tidak mengambil keputusan keamanan.
type OSCommandRunner struct{}

// Run mengeksekusi command di cwd (opsional) dan menangkap stdout/stderr.
func (OSCommandRunner) Run(command, cwd string) (CommandResult, error) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/C", command)
	} else {
		cmd = exec.Command("/bin/sh", "-c", command)
	}
	if cwd != "" {
		cmd.Dir = cwd
	}
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()

	res := CommandResult{Stdout: stdout.String(), Stderr: stderr.String()}
	if ee, ok := err.(*exec.ExitError); ok {
		res.ExitCode = ee.ExitCode()
		return res, nil // exit non-zero bukan error tool; laporkan ke pemanggil
	}
	if err != nil {
		return res, err
	}
	return res, nil
}

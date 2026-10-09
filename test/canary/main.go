// Command canary adalah test harness otomatis untuk membuktikan batas proteksi
// Samar secara KONKRET: ia menanam penanda unik ("canary") di berbagai jenis
// file, memanggil tool Samar lewat protokol MCP (stdio), lalu memastikan TIDAK
// ADA canary yang bocor ke output tool.
//
// Yang DIBUKTIKAN: masking Samar pada jalur yang melewati tool-nya.
// Yang TIDAK dibuktikan: bahwa AI tak bisa membaca file lewat tool BAWAAN client
// (bypass) — itu perilaku client, hanya bisa diuji di client nyata.
//
// Pemakaian:
//   go build -o bin/samar ./cmd/samar
//   go run ./test/canary            # exit 0 = tak ada kebocoran tak terduga
//
// Harness MELAPORKAN per-fixture: PROTECTED (canary termasking) atau LEAK
// (canary muncul mentah). Beberapa fixture memang DIHARAPKAN tak terlindungi
// (secret acak di file non-.env yang tak cocok regex) — ini ditandai sebagai
// "expected-leak" dan tidak menggagalkan harness, tetapi dilaporkan jelas agar
// pengguna tahu batas proteksi.
package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// fixture adalah satu file uji dengan canary di dalamnya.
type fixture struct {
	name         string
	filename     string // relatif ke tempdir
	content      string
	canary       string
	expectLeak   bool   // true: fixture ini DIHARAPKAN tak terlindungi (batas desain)
	note         string
}

func canary(tag string) string { return "CANARY_" + tag + "_7f3a9c21e4b8" }

func fixtures(dir string) []fixture {
	return []fixture{
		{
			name: "dotenv_regex_match", filename: ".env",
			content: "AWS_SECRET_ACCESS_KEY=" + canary("awsenv") + "\n",
			canary:  canary("awsenv"),
		},
		{
			name: "dotenv_random_value", filename: ".env",
			content: "WEIRD=" + canary("rndenv") + "\n",
			canary:  canary("rndenv"),
			note:    "dilindungi oleh dotenv mask-semua walau bukan pola regex",
		},
		{
			name: "env_local", filename: ".env.local",
			content: "DB_PASSWORD=" + canary("envlocal") + "\n",
			canary:  canary("envlocal"),
		},
		{
			name: "config_yaml_generic_key", filename: "config.yaml",
			content: "api_key: " + canary("yamlkey") + "\n",
			canary:  canary("yamlkey"),
			note:    "dilindungi oleh pola generic_assignment (ada 'api_key')",
		},
		{
			name: "config_yaml_random_nonsecret_name", filename: "config.yaml",
			content: "endpoint: " + canary("yamlrnd") + "\n",
			canary:  canary("yamlrnd"),
			expectLeak: true,
			note:       "BATAS DESAIN: file non-.env + nama field tak mengandung kata-kunci secret + nilai tak cocok pola -> TIDAK terdeteksi",
		},
		{
			name: "yaml_access_key_field", filename: "config.yaml",
			content: "access_key: " + canary("accesskey") + "\n",
			canary:  canary("accesskey"),
			note:    "kata-kunci diperluas: 'access_key' kini terdeteksi",
		},
		{
			name: "yaml_client_secret_field", filename: "config.yaml",
			content: "client_secret: " + canary("clientsecret") + "\n",
			canary:  canary("clientsecret"),
			note:    "kata-kunci diperluas: 'client_secret' kini terdeteksi",
		},
		{
			name: "plain_txt_random", filename: "notes.txt",
			content: "catatan: " + canary("txtrnd") + "\n",
			canary:  canary("txtrnd"),
			expectLeak: true,
			note:       "BATAS DESAIN: teks biasa tanpa pola secret -> tidak terdeteksi",
		},
	}
}

type rpcResp struct {
	ID     int `json:"id"`
	Result *struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	} `json:"result"`
}

func findOrBuildBinary() (string, func(), error) {
	if custom := os.Getenv("SAMAR_BIN"); custom != "" {
		if _, err := os.Stat(custom); err == nil {
			return custom, func() {}, nil
		}
	}

	defaultBin := filepath.Join("bin", "samar")
	if runtime.GOOS == "windows" {
		defaultBin = filepath.Join("bin", "samar.exe")
	}
	if _, err := os.Stat(defaultBin); err == nil {
		return defaultBin, func() {}, nil
	}

	// Otomatis build binary sementara bila belum ada
	tmpDir, err := os.MkdirTemp("", "samar-canary-bin-")
	if err != nil {
		return "", nil, fmt.Errorf("gagal buat tempdir: %w", err)
	}
	targetBin := filepath.Join(tmpDir, "samar")
	if runtime.GOOS == "windows" {
		targetBin = filepath.Join(tmpDir, "samar.exe")
	}

	buildCmd := exec.Command("go", "build", "-o", targetBin, "./cmd/samar")
	if out, err := buildCmd.CombinedOutput(); err != nil {
		os.RemoveAll(tmpDir)
		return "", nil, fmt.Errorf("gagal build binary otomatis (%v): %s", err, string(out))
	}

	cleanup := func() {
		os.RemoveAll(tmpDir)
	}
	return targetBin, cleanup, nil
}

func main() {
	bin, cleanupBin, err := findOrBuildBinary()
	if err != nil {
		fmt.Fprintf(os.Stderr, "canary: %v\n", err)
		os.Exit(2)
	}
	defer cleanupBin()

	dir, err := os.MkdirTemp("", "samar-canary-")
	if err != nil {
		fmt.Fprintln(os.Stderr, "canary: gagal buat tempdir:", err)
		os.Exit(2)
	}
	defer os.RemoveAll(dir)

	fxs := fixtures(dir)

	// Tulis fixture. Dua fixture memakai nama .env yang sama -> gabungkan.
	byFile := map[string][]fixture{}
	for _, f := range fxs {
		byFile[f.filename] = append(byFile[f.filename], f)
	}
	for fname, group := range byFile {
		var b strings.Builder
		for _, f := range group {
			b.WriteString(f.content)
		}
		if err := os.WriteFile(filepath.Join(dir, fname), []byte(b.String()), 0o600); err != nil {
			fmt.Fprintln(os.Stderr, "canary: gagal tulis fixture:", err)
			os.Exit(2)
		}
	}

	// Jalankan satu sesi Samar; baca tiap file via samar_read_file.
	cmd := exec.Command(bin)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	cmd.Stderr = nil
	if err := cmd.Start(); err != nil {
		fmt.Fprintln(os.Stderr, "canary: gagal start server:", err)
		os.Exit(2)
	}

	send := func(v any) { b, _ := json.Marshal(v); fmt.Fprintf(stdin, "%s\n", b) }
	send(map[string]any{"jsonrpc": "2.0", "id": 1, "method": "initialize", "params": map[string]any{"protocolVersion": "2024-11-05", "capabilities": map[string]any{}, "clientInfo": map[string]any{"name": "canary", "version": "1"}}})
	send(map[string]any{"jsonrpc": "2.0", "method": "notifications/initialized"})

	// id per file (urut byFile keys stabil via slice).
	fileList := make([]string, 0, len(byFile))
	for fname := range byFile {
		fileList = append(fileList, fname)
	}
	idToFile := map[int]string{}
	nextID := 10
	for _, fname := range fileList {
		idToFile[nextID] = fname
		send(map[string]any{"jsonrpc": "2.0", "id": nextID, "method": "tools/call", "params": map[string]any{"name": "samar_read_file", "arguments": map[string]any{"path": filepath.Join(dir, fname)}}})
		nextID++
	}

	// Kumpulkan respons.
	responses := map[int]string{}
	go func() {
		sc := bufio.NewScanner(stdout)
		sc.Buffer(make([]byte, 1<<20), 1<<20)
		for sc.Scan() {
			var r rpcResp
			if json.Unmarshal(sc.Bytes(), &r) == nil && r.Result != nil {
				var txt strings.Builder
				for _, c := range r.Result.Content {
					txt.WriteString(c.Text)
				}
				responses[r.ID] = txt.String()
			}
		}
	}()
	time.Sleep(1500 * time.Millisecond)
	stdin.(io.Closer).Close()
	cmd.Wait()

	// Evaluasi: untuk tiap fixture, cek apakah canary-nya ada di output file-nya.
	fmt.Println("=== Samar Canary Harness ===")
	tokenRe := regexp.MustCompile(`__SAMAR_SECRET_[0-9A-F]+__`)
	unexpectedLeaks := 0
	expectedLeaks := 0
	protected := 0

	for id, fname := range idToFile {
		out := responses[id]
		for _, f := range byFile[fname] {
			leaked := strings.Contains(out, f.canary)
			status := ""
			switch {
			case !leaked:
				status = "PROTECTED"
				protected++
			case leaked && f.expectLeak:
				status = "EXPECTED-LEAK (batas desain)"
				expectedLeaks++
			default:
				status = "!!! UNEXPECTED LEAK !!!"
				unexpectedLeaks++
			}
			line := fmt.Sprintf("[%s] %-32s (%s)", status, f.name, f.filename)
			if f.note != "" {
				line += "\n    catatan: " + f.note
			}
			fmt.Println(line)
		}
	}

	// Sanity: output file .env harus mengandung token (bukti masking jalan).
	hasToken := false
	for _, out := range responses {
		if tokenRe.MatchString(out) {
			hasToken = true
			break
		}
	}

	fmt.Println("---")
	fmt.Printf("protected=%d  expected-leak=%d  UNEXPECTED-LEAK=%d  masking-token-terlihat=%v\n",
		protected, expectedLeaks, unexpectedLeaks, hasToken)

	if unexpectedLeaks > 0 {
		fmt.Println("HASIL: GAGAL — ada canary bocor yang TIDAK diharapkan.")
		os.Exit(1)
	}
	if !hasToken {
		fmt.Println("HASIL: GAGAL — tidak ada token masking terlihat (apakah masking jalan?).")
		os.Exit(1)
	}
	fmt.Println("HASIL: LULUS — tak ada kebocoran tak terduga; batas proteksi sesuai harapan.")
}

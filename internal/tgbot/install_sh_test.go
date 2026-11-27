package tgbot

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const fakeOneClickToken = "FAKE-oneclick-token-0123456789"

func runInstallSh(t *testing.T, script string, env []string, args ...string) (string, int) {
	t.Helper()
	cmd := exec.Command("bash", append([]string{script}, args...)...)
	cmd.Env = append(os.Environ(), env...)
	cmd.Stdin = nil
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatal(err)
	}
	return string(out), code
}

func TestInstallShGoVersion(t *testing.T) {
	sh := filepath.Join(findRepoRoot(t), "install.sh")
	script := `source "$1"
for v in go1.24 go1.24.3 go1.25rc1 go1.27.4 go2.0; do go_version_ok "$v" || { echo "want ok $v"; exit 1; }; done
for v in go1.23.9 go1.9 go1 "" devel; do go_version_ok "$v" && { echo "want bad $v"; exit 1; }; done
exit 0`
	if out, err := exec.Command("bash", "-c", script, "x", sh).CombinedOutput(); err != nil {
		t.Fatalf("%v %s", err, out)
	}
}

// 令牌不接受命令行参数；错误信息不回显参数内容。
func TestInstallShRejectsTokenArgAndBadRole(t *testing.T) {
	sh := filepath.Join(findRepoRoot(t), "install.sh")
	for _, args := range [][]string{
		{"--token", fakeOneClickToken},
		{"--token=" + fakeOneClickToken},
		{"--role", "control", fakeOneClickToken},
		{"--role", "nope"},
	} {
		out, code := runInstallSh(t, sh, nil, args...)
		if code != 2 {
			t.Fatalf("%v: code %d out=%s", args, code, out)
		}
		if strings.Contains(out, fakeOneClickToken) {
			t.Fatalf("%v: token echoed: %s", args, out)
		}
	}
}

// agent 非交互：令牌只走环境变量，dry-run 不回显令牌，参数原样交给 install-agent.sh。
func TestInstallShDryRunAgent(t *testing.T) {
	sh := filepath.Join(findRepoRoot(t), "install.sh")
	pin := strings.Repeat("ab", 32)
	out, code := runInstallSh(t, sh, []string{"SBRELAY_TOKEN=" + fakeOneClickToken},
		"--role", "landing", "--url", "https://ctl.example:8443/", "--pin", pin, "--pubkey", "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=", "--dry-run")
	if code != 0 {
		t.Fatalf("code %d: %s", code, out)
	}
	if strings.Contains(out, fakeOneClickToken) {
		t.Fatalf("token leaked: %s", out)
	}
	for _, want := range []string{"deploy/install-agent.sh", "--url https://ctl.example:8443 ", "--pin " + pin, "--role landing", "--pubkey sha256//", "令牌：已提供"} {
		if !strings.Contains(out, want) {
			t.Fatalf("missing %q in %s", want, out)
		}
	}
	// 缺 --pin
	out, code = runInstallSh(t, sh, nil, "--role", "relay", "--url", "https://ctl.example:8443", "--dry-run")
	if code != 2 || !strings.Contains(out, "--pin") {
		t.Fatalf("missing pin: %d %s", code, out)
	}
	// 只给角色：交给 pm 的粘贴面板命令流程
	out, code = runInstallSh(t, sh, nil, "--role", "relay", "--dry-run")
	if code != 0 || !strings.Contains(out, "deploy/pm.sh 2") {
		t.Fatalf("interactive agent path: %d %s", code, out)
	}
}

func TestInstallShDryRunControlAndUninstall(t *testing.T) {
	sh := filepath.Join(findRepoRoot(t), "install.sh")
	out, code := runInstallSh(t, sh, []string{"SBRELAY_TG_TOKEN=" + fakeOneClickToken}, "--role", "control", "--dry-run")
	if code != 0 || !strings.Contains(out, "deploy/install-control.sh") || !strings.Contains(out, "环境变量已提供") || strings.Contains(out, fakeOneClickToken) {
		t.Fatalf("control dry-run: %d %s", code, out)
	}
	cases := map[string][]string{
		"install-control.sh --purge":   {"--role", "control", "--purge", "--dry-run"},
		"install-agent.sh --uninstall": {"--role", "relay", "--uninstall", "--dry-run"},
		"pm.sh 6":                      {"--uninstall", "--dry-run"},
		"pm.sh status":                 {"--status", "--dry-run"},
	}
	for want, args := range cases {
		out, code := runInstallSh(t, sh, nil, args...)
		if code != 0 || !strings.Contains(out, want) {
			t.Fatalf("%v: want %q got %d %s", args, want, code, out)
		}
	}
	// 非交互且没指定角色：直接报错退出，不卡在菜单
	out, code = runInstallSh(t, sh, nil, "--dry-run")
	if code != 2 {
		t.Fatalf("no role non-tty: %d %s", code, out)
	}
}

// 单独拷出 install.sh（不在仓库里）时给出明确提示。
func TestInstallShNeedsRepo(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(findRepoRoot(t), "install.sh"))
	if err != nil {
		t.Fatal(err)
	}
	p := filepath.Join(t.TempDir(), "install.sh")
	if err := os.WriteFile(p, b, 0755); err != nil {
		t.Fatal(err)
	}
	out, code := runInstallSh(t, p, nil, "--role", "control", "--dry-run")
	if code == 0 || !strings.Contains(out, "仓库根目录") {
		t.Fatalf("standalone: %d %s", code, out)
	}
}

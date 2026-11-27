package tgbot

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// 面板生成的命令粘贴进 pm 后要能解析出 地址/指纹/令牌，且解析过程不输出令牌。
func TestPmParsesPanelCommand(t *testing.T) {
	b := &Bot{
		cfg:     Config{PublicURL: "https://control.example:8443"},
		pin:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		spkiPin: "sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
	}
	var line string
	for _, l := range strings.Split(b.InstallScript(fakeInstallToken), "\n") {
		if strings.HasPrefix(l, " curl ") {
			line = l
		}
	}
	if line == "" {
		t.Fatal("no curl line")
	}
	pm := filepath.Join(findRepoRoot(t), "deploy", "pm.sh")
	cases := []string{
		line,
		"curl -LfsS https://control.example:8443/install-agent.sh | bash -s -- --url 'https://control.example:8443' --pin 0123456789ABCDEF0123456789abcdef0123456789abcdef0123456789abcdef --pubkey sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA= --token " + fakeInstallToken,
	}
	for _, c := range cases {
		script := `source "$1"; parse_panel_cmd "$2"; echo "url=$P_URL"; echo "pin=$P_PIN"; echo "pub=$P_PUB"; [ "$P_TOK" = "$3" ] && echo tok=ok`
		out, err := exec.Command("bash", "-c", script, "x", pm, c, fakeInstallToken).CombinedOutput()
		if err != nil {
			t.Fatalf("%v %s", err, out)
		}
		s := string(out)
		for _, want := range []string{
			"url=https://control.example:8443\n",
			"pin=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef\n",
			"pub=sha256//AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=\n",
			"tok=ok\n",
		} {
			if !strings.Contains(s, want) {
				t.Fatalf("missing %q in %q", want, s)
			}
		}
		if strings.Count(s, fakeInstallToken) != 0 {
			t.Fatal("pm parse echoed token")
		}
	}
}

// pm 不能自己实现安装：只能调用 install-control.sh / install-agent.sh。
func TestPmReusesInstallScripts(t *testing.T) {
	root := findRepoRoot(t)
	out, err := exec.Command("bash", "-c", `source "$1"; declare -f control_install agent_install change_token uninstall_menu`, "x", filepath.Join(root, "deploy", "pm.sh")).CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	s := string(out)
	for _, bad := range []string{"useradd", "sudoers.d/sbrelay-helper <", "/v1/register", "systemctl enable", "visudo"} {
		if strings.Contains(s, bad) {
			t.Fatalf("pm duplicates install logic: %s", bad)
		}
	}
	for _, want := range []string{"install-control.sh", "install-agent.sh", "--set-token", "SBRELAY_TOKEN=\"$P_TOK\" bash"} {
		if !strings.Contains(s, want) {
			t.Fatalf("pm should call %s", want)
		}
	}
}

func TestPmReuseAfterKeepDataUninstall(t *testing.T) {
	root := findRepoRoot(t)
	out, err := exec.Command("bash", "-c", `source "$1"; declare -f agent_install`, "x", filepath.Join(root, "deploy", "pm.sh")).CombinedOutput()
	if err != nil {
		t.Fatalf("%v %s", err, out)
	}
	s := string(out)
	if !strings.Contains(s, `agent.json`) || !strings.Contains(s, `AGENT_ENV`) {
		t.Fatal("agent_install should key off retained registration files, not only the unit")
	}
	if !strings.Contains(s, "本机有保留的 agent 注册数据") {
		t.Fatal("missing keep-data uninstall prompt")
	}
	if strings.Contains(s, "has_agent && [ -s /var/lib/sbrelay-agent/agent.json ]") {
		t.Fatal("still requires has_agent before offering token-free update")
	}
}

// 保留数据卸载 agent 时不能删掉 pm，否则「pm → 2 → 1 免令牌恢复」无从进入；只有确认彻底清除才删。
func TestAgentKeepDataUninstallKeepsPm(t *testing.T) {
	b, err := os.ReadFile(filepath.Join(findRepoRoot(t), "deploy", "install-agent.sh"))
	if err != nil {
		t.Fatal(err)
	}
	s := string(b)
	i := strings.Index(s, "uninstall_agent() {")
	j := strings.Index(s, `echo "AGENT_UNINSTALLED"`)
	if i < 0 || j < i {
		t.Fatal("uninstall_agent not found")
	}
	body := s[i:j]
	rmPm := strings.Index(body, "/usr/local/bin/pm")
	guard := strings.Index(body, `if [ "$purged" = 1 ]; then`)
	if rmPm < 0 || guard < 0 || rmPm < guard {
		t.Fatalf("pm removal must be guarded by purged=1")
	}
	if strings.Count(body, "/usr/local/bin/pm") != 2 { // 一处删除（彻底清除），一处存在性判断
		t.Fatalf("unexpected pm references in uninstall_agent")
	}
}

// pm.sh 的临时目录必须在主 shell 里创建，正常退出和异常退出（exit 非 0、INT、TERM、HUP、
// set -e 下的 ERR、set -u 未定义变量）后都不能在 TMPDIR 里留下 pm-* 目录。
func TestPmTmpDirCleanedOnExit(t *testing.T) {
	pm := filepath.Join(findRepoRoot(t), "deploy", "pm.sh")
	cases := []struct {
		name string
		body string
		code int
	}{
		{"normal", `exit 0`, 0},
		{"error-exit", `exit 3`, 3},
		{"sigterm", `kill -TERM $$; sleep 5`, 143},
		{"sigint", `kill -INT $$; sleep 5`, 130},
		{"sighup", `kill -HUP $$; sleep 5`, 129},
		{"errexit-err", `set -e; false; echo unreachable`, 1},
		{"unbound-var", `echo "$PM_TEST_UNSET_VAR"`, 127},
		{"fall-off-end", `true`, 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			base := t.TempDir()
			script := `source "$1"
ensure_tmpdir || exit 90
[ -d "$TMP_DIR" ] || exit 91
case "$TMP_DIR" in "$TMPDIR"/pm-*) ;; *) exit 92 ;; esac
touch "$TMP_DIR/install-agent.sh"
# 二次调用复用同一目录，不再新建
first=$TMP_DIR; ensure_tmpdir; [ "$TMP_DIR" = "$first" ] || exit 93
` + tc.body + "\n"
			cmd := exec.Command("bash", "-c", script, "pm-test", pm)
			cmd.Env = append(os.Environ(), "TMPDIR="+base)
			out, err := cmd.CombinedOutput()
			code := 0
			if ee, ok := err.(*exec.ExitError); ok {
				code = ee.ExitCode()
			} else if err != nil {
				t.Fatalf("run: %v", err)
			}
			if code != tc.code {
				t.Fatalf("exit code = %d, want %d; out=%s", code, tc.code, out)
			}
			if strings.Contains(string(out), "unreachable") {
				t.Fatal("set -e did not stop the script")
			}
			left, _ := filepath.Glob(filepath.Join(base, "pm-*"))
			if len(left) != 0 {
				t.Fatalf("leftover tmp dirs after %s: %v", tc.name, left)
			}
		})
	}
}

// 回归：get_agent_script 在 $(...) 里调用时不得自己建临时目录（子 shell 建的目录 trap 清不到）；
// 不开 errexit 时普通命令失败不能提前删掉还要用的临时目录。
func TestPmTmpDirNotCreatedInSubshell(t *testing.T) {
	root := findRepoRoot(t)
	pm := filepath.Join(root, "deploy", "pm.sh")
	b, err := os.ReadFile(pm)
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"$(tmpdir", "$(ensure_tmpdir", "`tmpdir", "`ensure_tmpdir"} {
		if strings.Contains(string(b), bad) {
			t.Fatalf("pm.sh creates tmp dir inside command substitution: %s", bad)
		}
	}
	base := t.TempDir()
	script := `source "$1"
# 没有 TMP_DIR 时在子 shell 里取脚本：不能新建 pm-* 目录
s=$(get_agent_script "https://127.0.0.1:1" "sha256//AAAA" 2>/dev/null || true)
n=$(find "$TMPDIR" -maxdepth 1 -name 'pm-*' | wc -l)
[ "$n" = 0 ] || { echo "subshell created dir"; exit 80; }
ensure_tmpdir
false
grep -q nomatch /dev/null
[ -d "$TMP_DIR" ] || { echo "tmp dir removed by non-fatal failure"; exit 81; }
exit 0
`
	cmd := exec.Command("bash", "-c", script, "pm-test", pm)
	cmd.Env = append(os.Environ(), "TMPDIR="+base)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("%v: %s", err, out)
	}
	left, _ := filepath.Glob(filepath.Join(base, "pm-*"))
	if len(left) != 0 {
		t.Fatalf("leftover tmp dirs: %v", left)
	}
}

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

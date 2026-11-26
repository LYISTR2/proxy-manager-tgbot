package tgbot

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"sbrelay/internal/tlspin"
)

// LoadTLSFiles 保持兼容：只返回证书 DER 的 SHA-256 hex。
func LoadTLSFiles(cert, key string) (pin string, err error) {
	hex, _, err := tlspin.FromKeyPair(cert, key)
	return hex, err
}

func (b *Bot) pkgDir() string {
	if b != nil && b.cfg.PkgDir != "" {
		return b.cfg.PkgDir
	}
	if v := os.Getenv("SBRELAY_PKG_DIR"); v != "" {
		return v
	}
	return "/usr/local/lib/sbrelay"
}

func (b *Bot) handleInstallAgentSh(w http.ResponseWriter, r *http.Request) {
	b.serveScript(w, r, "install-agent.sh")
}

// handleScript 下发公开脚本（pm.sh、install-control.sh）。脚本不含任何秘密。
func (b *Bot) handleScript(w http.ResponseWriter, r *http.Request) {
	name := filepath.Base(r.URL.Path)
	switch name {
	case "pm.sh", "install-control.sh", "install-agent.sh":
	default:
		http.NotFound(w, r)
		return
	}
	b.serveScript(w, r, name)
}

func (b *Bot) serveScript(w http.ResponseWriter, r *http.Request, name string) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method", 405)
		return
	}
	// 脚本本身不含令牌或私钥；令牌只通过环境变量交给 bash。
	p := filepath.Join(b.pkgDir(), name)
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		http.Error(w, "install script unavailable", 404)
		return
	}
	w.Header().Set("Content-Type", "text/x-shellscript; charset=utf-8")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	http.ServeFile(w, r, p)
}

func (b *Bot) handlePkg(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method", 405)
		return
	}
	name := filepath.Base(r.URL.Path)
	switch name {
	case "sbrelay", "sbrelay-helper":
	default:
		http.NotFound(w, r)
		return
	}
	p := filepath.Join(b.pkgDir(), name)
	st, err := os.Stat(p)
	if err != nil || st.IsDir() {
		http.NotFound(w, r)
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/octet-stream")
	http.ServeFile(w, r, p)
}

// InstallScript 生成面板里的一行安装命令。令牌只作为 bash 的环境变量传入，
// 不出现在进程参数（ps）里，也不进脚本文件。行首空格配合 HISTCONTROL=ignorespace，尽量不写入 shell 历史。
func (b *Bot) InstallScript(token string) string {
	url := strings.TrimRight(b.cfg.PublicURL, "/")
	pin := b.pin
	spki := b.spkiPin
	var sb strings.Builder
	sb.WriteString("export HISTCONTROL=ignorespace\n")
	sb.WriteString("# 下一行行首有空格，尽量不写入 shell 历史。令牌不要转发到群聊。\n")
	sb.WriteString("# -k 只跳过系统 CA（自签证书）；真正校验的是 --pinnedpubkey。\n")
	fmt.Fprintf(&sb, " curl -LfsS --tlsv1.2 -k --pinnedpubkey %s %s/install-agent.sh | SBRELAY_TOKEN=%s bash -s -- --url %s --pin %s --pubkey %s\n",
		spki, url, token, url, pin, spki)
	sb.WriteString("# 也可运行交互菜单 pm，选 2 后粘贴上面这一行：\n")
	fmt.Fprintf(&sb, "# curl -LfsS --tlsv1.2 -k --pinnedpubkey %s %s/pm.sh -o /tmp/pm.sh && bash /tmp/pm.sh\n", spki, url)
	sb.WriteString("# 卸载（不改 sing-box）：pm 选 6，或下载 install-agent.sh 后加 --uninstall\n")
	return sb.String()
}

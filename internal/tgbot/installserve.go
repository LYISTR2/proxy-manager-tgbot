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
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		http.Error(w, "method", 405)
		return
	}
	// 脚本本身不含令牌或私钥；令牌只通过命令行/环境变量交给 bash。
	p := filepath.Join(b.pkgDir(), "install-agent.sh")
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

// InstallScript 生成面板里的一行安装命令。令牌只出现在命令参数里，不进脚本文件。
// 行首空格配合 HISTCONTROL=ignorespace，尽量不写入 shell 历史。
func (b *Bot) InstallScript(token string) string {
	url := strings.TrimRight(b.cfg.PublicURL, "/")
	pin := b.pin
	spki := b.spkiPin
	var sb strings.Builder
	sb.WriteString("export HISTCONTROL=ignorespace\n")
	sb.WriteString("# 下一行行首有空格，尽量不写入 shell 历史。令牌不要转发到群聊。\n")
	sb.WriteString("# -k 只跳过系统 CA（自签证书）；真正校验的是 --pinnedpubkey。\n")
	fmt.Fprintf(&sb, " curl -LfsS --tlsv1.2 -k --pinnedpubkey %s %s/install-agent.sh | bash -s -- --url %s --pin %s --pubkey %s --token %s\n",
		spki, url, url, pin, spki, token)
	sb.WriteString("# 卸载（不改 sing-box）：同样下载脚本后追加 --uninstall\n")
	return sb.String()
}

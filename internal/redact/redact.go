// Package redact 把日志和错误串里的敏感凭据打码，避免进 journal。
package redact

import (
	"io"
	"regexp"
	"strings"
)

// 假想的 Telegram Bot token 形态：数字 id + 冒号 + 较长的字母数字密钥。
var reBotToken = regexp.MustCompile(`\b\d{6,16}:[A-Za-z0-9_-]{20,}\b`)

// 含 token 的 Bot API URL（含无 scheme、http/https）。
var reBotAPI = regexp.MustCompile(`(?i)(?:https?://)?(?:api\.)?telegram\.org/bot[^\s"'\\]+`)

// URL 里的 user:password@host（含 ssh://）。
var reURLUserinfo = regexp.MustCompile(`(?i)([a-z][a-z0-9+.-]*://[^:/@\s]+):([^@/\s]+)@`)

// password= / Password: / ssh_password= 等赋值。
var rePasswordAssign = regexp.MustCompile(`(?i)((?:ssh[_-])?pass(?:word|wd|phrase)?\s*[=:]\s*)[^\s]+`)

// PEM / OpenSSH 私钥整段。
var rePEMKey = regexp.MustCompile(`(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----`)

// String 将 s 中的 Bot token、完整 Bot API URL、SSH/URL 密码、私钥打码。
func String(s string) string {
	if s == "" {
		return s
	}
	s = rePEMKey.ReplaceAllString(s, "[redacted private key]")
	s = reBotAPI.ReplaceAllStringFunc(s, maskBotAPIURL)
	s = reBotToken.ReplaceAllString(s, "***")
	s = reURLUserinfo.ReplaceAllString(s, "${1}:***@")
	s = rePasswordAssign.ReplaceAllString(s, "${1}***")
	return s
}

func maskBotAPIURL(u string) string {
	lower := strings.ToLower(u)
	i := strings.Index(lower, "/bot")
	if i < 0 {
		return u
	}
	start := i + 4
	end := start
	for end < len(u) && u[end] != '/' && u[end] != '?' && u[end] != '#' && u[end] != ' ' && u[end] != '"' && u[end] != '\'' {
		end++
	}
	return u[:start] + "***" + u[end:]
}

// Error 对 err.Error() 打码；err 为 nil 时返回空串。
func Error(err error) string {
	if err == nil {
		return ""
	}
	return String(err.Error())
}

// Writer 包装底层 Writer，写出前打码。返回的写入长度按原始 p 计，避免 log 包当成短写。
func Writer(w io.Writer) io.Writer {
	return writer{w: w}
}

type writer struct{ w io.Writer }

func (w writer) Write(p []byte) (int, error) {
	out := []byte(String(string(p)))
	if _, err := w.w.Write(out); err != nil {
		return 0, err
	}
	return len(p), nil
}

// sbrelay-helper：root 拥有、经 sudoers 精确白名单调用的小助手。
// 只接受三个固定子命令；路径全部写死，切换参数只从 stdin 的 JSON 读，避免 sudoers 通配符放行任意参数。
package main

import (
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"time"

	"sbrelay/internal/helper"
	"sbrelay/internal/relaycfg"
)

func main() {
	env := &helper.Env{
		Dir:        "/usr/local/etc/sing-box",
		SingBox:    "/usr/local/bin/sing-box",
		StateDir:   "/var/lib/sbrelay-helper",
		Service:    "sing-box",
		LockWait:   30 * time.Second,
		SettleWait: 3 * time.Second,
		Systemctl:  func(a ...string) error { return exec.Command("/usr/bin/systemctl", a...).Run() },
	}
	os.MkdirAll(env.StateDir, 0700)
	var res helper.Result
	if len(os.Args) != 2 {
		res = helper.Result{Error: "用法: sbrelay-helper status|switch|rollback"}
	} else {
		switch os.Args[1] {
		case "status":
			res = env.Status()
		case "switch":
			var req helper.SwitchReq
			b, _ := io.ReadAll(io.LimitReader(os.Stdin, 4096))
			if err := json.Unmarshal(b, &req); err != nil || !relaycfg.TagRe.MatchString(req.Inbound) || !relaycfg.TagRe.MatchString(req.Outbound) {
				res = helper.Result{Op: "switch", Error: "参数不合法"}
			} else {
				res = env.Switch(req, "switch")
			}
		case "rollback":
			res = env.Rollback()
		default:
			res = helper.Result{Error: "未知子命令"}
		}
	}
	json.NewEncoder(os.Stdout).Encode(res)
	if !res.OK {
		os.Exit(1)
	}
}

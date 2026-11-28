# proxy-manager-tgbot (`sbrelay`)

用 Telegram Bot 管理「线路机 + 落地机」：自动搭好 SS2022 节点，随时在 Bot 里一键换落地或切换「本机直出」，**客户端连接信息（地址 / 端口 / 密码）始终不变**。

使用纯 **Rust 单一静态二进制**重写：无需在目标机安装 Go / Python / OpenSSL，无 `sudoers` / helper 拆分，采用 HTTP 长轮询实现毫秒级指令下发。

## 一键安装

以 root 执行（先 `sudo -i`）：

```bash
# 打开交互菜单
bash <(curl -fsSL https://raw.githubusercontent.com/LYISTR2/proxy-manager-tgbot/main/install.sh)

# 直接安装控制端（按提示不回显输入 Bot token，或预先 export SBRELAY_TG_TOKEN）
bash <(curl -fsSL https://raw.githubusercontent.com/LYISTR2/proxy-manager-tgbot/main/install.sh) control
```

> 如服务器访问 GitHub 较慢，可加环境变量 `SBRELAY_MIRROR="https://你的镜像前缀/"`。

## 快速开始

1. 在 [@BotFather](https://t.me/BotFather) 创建 Bot，获取 token。
2. 在控制端机器运行上方安装命令：
   - **高位随机端口 + 域名直连（默认推荐）**：交互提示可直接输入高位端口（默认随机 `20000–59999`，避开常规 8443）和域名（如 `pm.example.com`，Cloudflare 建议设为「仅 DNS 灰云」），无需安装 Nginx/Caddy，自签证书指纹固定，迁移时证书与状态一起带走。
   - **可选反代 / CF 橙云模式**：如已有本机 Caddy/Nginx 或希望走 Cloudflare 橙云回源，可在安装提示中选择或传入 `--tls-mode webpki`。
3. 完成后在 Telegram 给 Bot 发 `/start`（首位发送者成为管理员）。
4. 在 Bot 面板点「添加线路机 / 添加落地机」，把生成的一行命令复制到目标机器以 root 执行：
   - 没装 `sing-box` 会自动下载官方稳定版（校验 SHA-256）。
   - 自动生成 SS2022 入站（`2022-blake3-aes-128-gcm`）并上报；线路机会自动把节点链接推送到 Telegram。
5. 在线路机面板点「换落地 / 本机直出」→ 选择目标落地机或「本机直出」→ 确认即可。

## 控制端迁移（无需重新对接 Agent）

只要控制端绑定了**域名**（无论高位端口直连还是反代模式），换新服务器时 Agent 一台都不用碰：

1. 在旧控制端（或直接在 Telegram Bot 发 `/backup` / 点「备份控制端」）导出加密备份 `.sbr` 文件并记下口令（备份内含 `control.toml`、`state.json` 及自签 `tls.crt`/`tls.key`）。
2. 在新服务器安装 `sbrelay` 后放行对应端口并执行：
   ```bash
   sbrelay restore sbrelay-backup-xxxx.sbr
   ```
3. 把域名解析（DNS）切到新服务器 IP。
4. 所有已安装 Agent 的线路机 / 落地机每 5 秒自动重连域名，**TLS 证书指纹与原有 HMAC 凭据完全一致，会自动无感上线并重新上报节点信息与当前出口**。

> 如果当初用 IP 直连（无域名）且旧机已失联，在新机 `restore` 后，只需在目标机跑一行 `sbrelay rebind --url https://新地址:8443`（无需重新生成令牌，不动已有 SS2022 节点）。

## 常用命令

安装后可随时运行 `sbrelay` 或 `pm`：

```bash
pm                      # 打开交互管理菜单（等同 sbrelay menu）
sbrelay status          # 查看控制端 / Agent / sing-box 状态与证书指纹
sbrelay backup          # 导出控制端加密备份（.sbr，含配置/证书/状态库）
sbrelay restore <file>  # 在新控制机从加密备份恢复并启动服务
sbrelay rebind --url …  # 灾备：将本机 Agent 重新指向新的控制端地址
sbrelay set-token       # 更换 Telegram Bot token 并重启控制端
sbrelay restart         # 重启本机 sbrelay 服务
sbrelay uninstall       # 卸载服务（保留配置、证书、注册状态，不动 sing-box）
sbrelay uninstall --purge  # 彻底清除配置与状态数据（需输入 yes 确认）
```

## 本地源码编译

```bash
cargo build --release
# 产物位于 target/release/sbrelay
```

发版只需推送 `v*` 标签（如 `git tag v0.5.0 && git push origin v0.5.0`），GitHub Actions 会自动编译 `x86_64` 与 `aarch64` 静态 musl 二进制并生成 `SHA256SUMS` 附到 Release。

## 安全与可靠性

- **TLS 证书指纹固定（DER SHA-256）**：Agent 在 TLS 握手阶段强校验控制端自签证书指纹，不匹配即拒绝连接。
- **防重放鉴权**：所有 Agent 请求均带 `HMAC-SHA256` 签名、±120 秒时间窗与 Nonce 防重放；注册接口带单 IP 失败限流，安装令牌一次性且 2 小时过期。
- **独立 `sing-box` 实例隔离**：sbrelay 使用专用配置 `/etc/sbrelay/sing-box.json` 与独立服务 `sbrelay-sing-box.service`，完全不修改或覆盖宿主机原有的 `sing-box.service` 及任何单/多文件配置。
- **配置零损坏保障**：切换只改出站与 `route.final`，绝不修改入站；每次切换前自动备份并执行 `sing-box check`，失败不落盘，重启异常自动恢复并支持一键回滚。
- **最小权限与脱敏**：配置文件与密钥权限 `0600`；systemd 启用 `ProtectSystem=strict` 与路径白名单；日志自动脱敏 Bot token 与密码。

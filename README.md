# proxy-manager-tgbot（sbrelay）

用 Telegram Bot 管理「线路机 + 落地机」：线路机自动搭好 SS2022 客户端节点，之后在 Bot 里一键换落地或改成本机直出，**客户端节点（地址 / 端口 / 密码）始终不变**。

## 一键安装

控制端（首次部署，在仓库目录运行；仓库为私有，需已登录 GitHub 的 git / SSH 密钥）：

```bash
git clone git@github.com:LYISTR2/proxy-manager-tgbot.git && cd proxy-manager-tgbot && sudo bash install.sh --role control
```

线路机 / 落地机：在 Bot 里点「添加线路机 / 添加落地机」，把面板给的一行命令以 root 执行即可（令牌走环境变量，不进进程参数）。

已有控制端时，任意机器打开管理菜单（`-k` 只跳过系统 CA，真正校验的是公钥指纹）：

```bash
curl -LfsS --tlsv1.2 -k --pinnedpubkey sha256//<公钥指纹> https://<控制端>:8443/pm.sh -o /tmp/pm.sh && sudo bash /tmp/pm.sh
```

## 组成

| 角色 | 作用 |
|---|---|
| 控制端 | Telegram Bot + HTTPS 接口（默认 :8443，自签证书 + 指纹校验），保存机器与状态 |
| 线路机 | agent + sing-box；没装 sing-box 会自动安装，并生成 SS2022 入站，节点链接推送到 Bot |
| 落地机 | agent + sing-box；自动生成 SS2022 落地入站并上报，已有 Shadowsocks 入站则沿用 |

Bot 功能：添加 / 重命名 / 删除机器，查看节点链接，**换落地**（多条中转时为「给第 N 条中转换落地」），**本机直出**（流量从线路机自己的 IP 出去，不需要落地机），一键回滚。每次切换都会先备份、`sing-box check`，失败不落盘，服务异常自动恢复。

## 快速开始

1. 在 [@BotFather](https://t.me/BotFather) 创建 Bot，拿到 token。
2. 控制端：`sudo bash install.sh --role control`，按提示输入 token（不回显）。没有 Go ≥ 1.24 时会临时下载官方 Go（校验 SHA-256）编译，结束即删。
3. 在 Telegram 给 Bot 发 `/start`，第一个发的人成为管理员。
4. 点「添加线路机」「添加落地机」，到对应机器以 root 执行面板命令。
5. 线路机面板 → 「换落地」→ 选落地机或「本机直出」→ 确认。

`install.sh` 其他用法：

```bash
sudo bash install.sh                       # 交互菜单
sudo bash install.sh --role relay          # 粘贴面板命令安装 agent（不回显）
sudo bash install.sh --role landing --url https://<控制端>:8443 --pin <证书指纹>   # 令牌按提示输入
sudo bash install.sh --status | --uninstall | --purge
sudo bash install.sh --help
```

## 管理菜单 pm

装过任一角色后直接运行 `pm`：

```
1 安装/更新控制端   2 安装/更新 agent   3 状态
4 改 Bot token      5 重启服务          6 卸载
```

也可 `pm status`、`pm 3`。agent 已注册（包括保留数据卸载过）时，选 2 → 1 原地更新，不需要新令牌。

## 卸载

- **保留数据**：`pm` 选 6 → 1，或 `install.sh --uninstall`。控制端保留 state、证书和 token；agent 保留注册数据，之后可免令牌恢复。
- **彻底清除**：`pm` 选 6 → 2，或 `install.sh --purge`，需输入 `yes` 确认。
- 卸载不会改动 sing-box 的配置和服务。

## 安全说明

- agent 以非 root 用户运行，只能通过 sudoers 白名单调用固定的 helper（落地机只放行只读 `status`）。
- agent 与控制端之间：TLS 证书指纹固定 + HMAC 签名 + nonce 防重放；安装令牌一次性、2 小时过期。
- 令牌和 Bot token 只经环境变量或不回显输入传递，不进命令行参数和日志；含密码的配置文件权限为 600。
- 切换只改线路机出站与路由，不动入站；sing-box 校验失败时不落盘。

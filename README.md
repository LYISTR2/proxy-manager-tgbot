# proxy-manager-tgbot（sbrelay）

用 Telegram Bot 管理线路机与落地机：**绑定线路机自动搭建 SS2022 客户端节点，绑定落地机自动搭建 SS2022 落地服务，后续在不动客户端节点（地址/端口/密码完全不变）的情况下用 Telegram 一键切换落地机。**

## 核心流程

1. **部署控制端**：在控制端机器运行 `sudo bash deploy/pm.sh` 选 `1`（或 `sudo ./deploy/install-control.sh`）。
2. **绑定管理员**：在 Telegram 向 Bot 发送 `/start` 绑定首位管理员（未绑定前不响应任何其他指令）。
3. **添加线路机**：点「添加线路机」起名，拿到一行安装命令在线路机以 root 执行：
   - 若机器未装 `sing-box`，脚本会自动安装官方稳定版并生成 **SS2022 (`2022-blake3-aes-128-gcm`)** 客户端入站；
   - 线路机上线后，Bot 会自动把 `ss://` 节点链接推送给你（也可随时在「线路机 → 查看 SS2022 节点链接」查看）；
   - 若本机已有 `singbox-lite` 配置，会保留原配置兼容使用。
4. **添加落地机**：点「添加落地机」起名，拿到安装命令在落地机以 root 执行：
   - 自动安装 `sing-box` 并搭建 **SS2022** 落地服务，自动向控制端上报节点信息与在线状态；
   - 落地机 agent 的 sudoers 仅放行只读 `status`。
5. **一键切换落地**：进入线路机面板 → 点「换落地」→ 选择任意已绑定落地机并确认。控制端会自动把该落地机的出站配置下发给线路机，仅更新出站与路由规则，**客户端 SS2022 节点完全无需改动**；支持一键回滚、重命名与删除机器。

## 管理菜单 pm（推荐）

`deploy/pm.sh` 是中文数字菜单：1 安装/更新控制端、2 安装/更新 agent、3 状态、4 改 Bot token、5 重启、6 卸载。装过一次后直接运行 `pm`（也可 `pm status`、`pm 3`）。

**已有控制端时，任何机器一条命令下载运行**（用公钥指纹校验；`-k` 只跳过系统 CA）：

```bash
curl -LfsS --tlsv1.2 -k --pinnedpubkey sha256//<公钥指纹> https://<控制端地址>:8443/pm.sh -o /tmp/pm.sh && sudo bash /tmp/pm.sh
```

## 控制端命令行

```bash
sudo ./deploy/install-control.sh              # 安装 / 更新 / 修复（保留 state、证书、token）
sudo ./deploy/install-control.sh --set-token  # 只改 Bot token（不回显），并重启
sudo ./deploy/install-control.sh --uninstall  # 卸载，保留数据
sudo ./deploy/install-control.sh --purge      # 卸载并删除数据（需输入 yes）
```

## Agent 命令行

在面板点「添加线路机」或「添加落地机」，把给出的命令以 root 执行（令牌走环境变量，不进进程参数；行首空格配合 `HISTCONTROL=ignorespace` 不进历史）：

```bash
export HISTCONTROL=ignorespace
 curl -LfsS --tlsv1.2 -k --pinnedpubkey <公钥指纹> https://<控制端地址>:8443/install-agent.sh | SBRELAY_TOKEN=<token> bash -s -- --url https://<控制端地址>:8443 --pin <证书指纹> --pubkey <公钥指纹>
```

卸载：`pm` 选 6，或 `bash /usr/local/lib/sbrelay/install-agent.sh --uninstall`（保留注册数据）/ `--purge`（彻底清除）。

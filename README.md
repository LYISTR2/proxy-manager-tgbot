# proxy-manager-tgbot（sbrelay）

用 Telegram Bot 给 singbox-lite 线路机切换落地出站。显示名只存在控制端，不改节点地址、端口或密码，也不改 sing-box 启动参数。

## 管理菜单 pm（推荐）

`deploy/pm.sh` 是中文数字菜单：1 安装/更新控制端、2 安装/更新 agent、3 状态、4 改 Bot token、5 重启、6 卸载。装过一次后直接运行 `pm`（也可 `pm status`、`pm 3`）。

**已有控制端时，任何机器一条命令下载运行**（从你自己的控制端下发，用公钥指纹校验；`-k` 只跳过系统 CA）：

```
curl -LfsS --tlsv1.2 -k --pinnedpubkey sha256//<公钥指纹> https://<控制端地址>:8443/pm.sh -o /tmp/pm.sh && sudo bash /tmp/pm.sh
```

公钥指纹在控制端运行 `pm status` 可见，面板的安装命令里也带着。

**第一台控制端**：仓库是私有的，先用有权限的账号克隆（例如 `gh repo clone LYISTR2/proxy-manager-tgbot`），再在仓库目录运行 `sudo bash deploy/pm.sh` 选 1（本机有 Go 会自动编译）。

为什么这样下发：私有仓库的 raw/release 下载都要在目标机器放 GitHub token；控制端本来就在 :8443 下发 agent 安装脚本和二进制，并有固定证书指纹，复用它不需要额外凭据，且下载内容被指纹校验。

## 控制端（不用菜单时）

```
sudo ./deploy/install-control.sh              # 安装 / 更新 / 修复（保留 state、证书、token）
sudo ./deploy/install-control.sh --set-token  # 只改 Bot token（不回显），并重启
sudo ./deploy/install-control.sh --uninstall  # 卸载，保留数据
sudo ./deploy/install-control.sh --purge      # 卸载并删除数据（需输入 yes）
```

装完向 Bot 发送 `/start` 绑定管理员，再用面板添加机器。

## Agent（不用菜单时）

在面板点「添加线路机」或「添加落地机」，把给出的命令以 root 执行（令牌走环境变量，不进进程参数；行首空格配合 `HISTCONTROL=ignorespace` 不进历史）：

```
export HISTCONTROL=ignorespace
 curl -LfsS --tlsv1.2 -k --pinnedpubkey <公钥指纹> https://<控制端地址>:8443/install-agent.sh | SBRELAY_TOKEN=<token> bash -s -- --url https://<控制端地址>:8443 --pin <证书指纹> --pubkey <公钥指纹>
```

用 pm 时选 2，把这一行粘贴进去即可（不回显）。已注册机器更新：`pm` 选 2 → 1，不需要新令牌。线路机可切换中转出站；落地机只读。

卸载：`pm` 选 6，或 `bash /usr/local/lib/sbrelay/install-agent.sh --uninstall`（保留注册数据）/ `--purge`（彻底清除）。

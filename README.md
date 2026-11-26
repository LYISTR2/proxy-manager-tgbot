# proxy-manager-tgbot（sbrelay）

用 Telegram Bot 给 singbox-lite 线路机切换落地出站。显示名只存在控制端，不改节点地址、端口或密码。

## 控制端

在仓库目录以 root 运行（无预编译二进制时，若本机有 Go 会自动编译）：

```
sudo ./deploy/install-control.sh
```

按提示填写 Bot token 和监听地址（默认 `0.0.0.0:8443`）。也可预先设置 `SBRELAY_TG_TOKEN`、`SBRELAY_LISTEN`、`SBRELAY_PUBLIC_URL`。更新时默认保留 state、证书和已有 token。

装完向 Bot 发送 `/start` 绑定管理员，再用面板添加机器。

卸载（默认保留证书和数据）：

```
sudo ./deploy/install-control.sh --uninstall
```

彻底删除数据：`sudo ./deploy/install-control.sh --purge`

## Agent

在 Telegram 面板点「添加线路机」或「添加落地机」，把给出的命令（建议先 `export HISTCONTROL=ignorespace`，命令行首有空格）复制到目标机器以 root 执行，例如：

```
export HISTCONTROL=ignorespace
 curl -LfsS --tlsv1.2 -k --pinnedpubkey <SPKI指纹> https://<控制端地址>/install-agent.sh | bash -s -- --url https://<控制端地址> --pin <证书指纹> --pubkey <SPKI指纹> --token <token>
```

`-k` 只跳过系统 CA（自签证书），真正校验的是 `--pinnedpubkey`。线路机可切换中转出站；落地机只读。不要改 sing-box 启动参数。

卸载（不改 sing-box）：

```
 curl -LfsS --tlsv1.2 -k --pinnedpubkey <SPKI指纹> https://<控制端地址>/install-agent.sh | bash -s -- --uninstall
```

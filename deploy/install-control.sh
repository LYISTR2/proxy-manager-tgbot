#!/bin/bash
# sbrelay 控制端一键安装 / 更新 / 修复 / 卸载。
# 不修改本机 sing-box 入站、出站或服务启动参数。
#
# 用法（root）：
#   ./deploy/install-control.sh
#   SBRELAY_TG_TOKEN=... SBRELAY_LISTEN=0.0.0.0:8443 ./deploy/install-control.sh
#   ./deploy/install-control.sh --uninstall
#   ./deploy/install-control.sh --purge   # 同时删除 state、证书和 Bot token（会确认）
#
# 二进制路径与现网一致：/usr/local/lib/sbrelay/sbrelay，并提供 /usr/local/bin/sbrelay 符号链接。
# 更新时默认保留 state、证书和已有 Bot token。

set -euo pipefail
set +x

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行。" >&2
  exit 1
fi

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=$(cd "$SCRIPT_DIR/.." 2>/dev/null && pwd || true)
BIN_DST=/usr/local/lib/sbrelay/sbrelay
HELPER_DST=/usr/local/lib/sbrelay/sbrelay-helper
BIN_LINK=/usr/local/bin/sbrelay
ENV_FILE=/etc/sbrelay/control.env
STATE_DIR=/var/lib/sbrelay
UNIT=/etc/systemd/system/sbrelay-control.service

UNINSTALL=0
PURGE=0
for a in "$@"; do
  case "$a" in
    --uninstall) UNINSTALL=1 ;;
    --purge) PURGE=1; UNINSTALL=1 ;;
    -h|--help)
      sed -n '2,16p' "$0"
      exit 0
      ;;
    *) echo "未知参数 $a" >&2; exit 2 ;;
  esac
done

uninstall_control() {
  systemctl disable --now sbrelay-control.service 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload || true
  rm -f "$BIN_DST" "$HELPER_DST" "$BIN_LINK" /usr/local/lib/sbrelay/install-agent.sh
  if [ "$PURGE" = 1 ]; then
    echo "即将删除 $STATE_DIR 与 /etc/sbrelay（含证书和 Bot token）。"
    read -r -p "确认彻底删除？输入 yes 继续：" ans
    if [ "$ans" = yes ]; then
      rm -rf "$STATE_DIR" /etc/sbrelay
      echo "已删除数据目录。"
    else
      echo "已取消删除数据；服务已卸载。"
    fi
  else
    echo "CONTROL_UNINSTALLED"
    echo "说明：$STATE_DIR 与 /etc/sbrelay（含证书和 Bot token）默认保留。彻底删除请用 --purge。"
  fi
  if getent passwd sbrelayctl >/dev/null; then
    userdel sbrelayctl || true
  fi
}

if [ "$UNINSTALL" = 1 ]; then
  uninstall_control
  exit 0
fi

echo "======== sbrelay 控制端安装 / 更新 / 修复 ========"

# 定位二进制：BIN_SRC / 脚本同目录 / 仓库编译 / 已安装文件
BIN_SRC=${BIN_SRC:-}
HELPER_SRC=${HELPER_SRC:-}
find_or_build() {
  if [ -n "$BIN_SRC" ] && [ -x "$BIN_SRC" ]; then
    return 0
  fi
  for c in "$SCRIPT_DIR/sbrelay" /tmp/sbrelay-pkg/sbrelay "$BIN_DST"; do
    if [ -x "$c" ]; then BIN_SRC=$c; break; fi
  done
  if [ -z "$HELPER_SRC" ]; then
    for c in "$SCRIPT_DIR/sbrelay-helper" /tmp/sbrelay-pkg/sbrelay-helper "$HELPER_DST"; do
      if [ -x "$c" ]; then HELPER_SRC=$c; break; fi
    done
  fi
  if [ -x "$BIN_SRC" ] && [ -x "${HELPER_SRC:-}" ]; then
    return 0
  fi
  if [ -n "$REPO_ROOT" ] && [ -f "$REPO_ROOT/go.mod" ] && [ -d "$REPO_ROOT/cmd/sbrelay" ] && command -v go >/dev/null; then
    echo "未找到预编译二进制，正在本仓库编译（CGO_ENABLED=0）..."
    mkdir -p /tmp/sbrelay-pkg
    ( cd "$REPO_ROOT" && CGO_ENABLED=0 go build -o /tmp/sbrelay-pkg/sbrelay ./cmd/sbrelay && CGO_ENABLED=0 go build -o /tmp/sbrelay-pkg/sbrelay-helper ./cmd/sbrelay-helper )
    BIN_SRC=/tmp/sbrelay-pkg/sbrelay
    HELPER_SRC=/tmp/sbrelay-pkg/sbrelay-helper
    return 0
  fi
  echo "找不到 sbrelay 二进制，也无法编译。请先 go build，或设置 BIN_SRC / HELPER_SRC。" >&2
  exit 1
}
find_or_build
[ -x "$HELPER_SRC" ] || { echo "找不到 sbrelay-helper（控制端需要它以便下发给 agent）。" >&2; exit 1; }

id -u sbrelayctl >/dev/null 2>&1 || useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin --create-home sbrelayctl
mkdir -p /usr/local/lib/sbrelay /etc/sbrelay "$STATE_DIR"
chown sbrelayctl:sbrelayctl "$STATE_DIR"
chmod 750 "$STATE_DIR"
chown root:sbrelayctl /etc/sbrelay
chmod 750 /etc/sbrelay

# 监听地址
LISTEN=${SBRELAY_LISTEN:-}
if [ -z "$LISTEN" ] && [ -f "$ENV_FILE" ]; then
  LISTEN=$(awk -F= '$1=="SBRELAY_LISTEN"{print substr($0,index($0,"=")+1)}' "$ENV_FILE" || true)
fi
if [ -z "$LISTEN" ]; then
  if [ -t 0 ]; then
    read -r -p "监听地址 [默认 0.0.0.0:8443]：" LISTEN || true
  fi
  LISTEN=${LISTEN:-0.0.0.0:8443}
fi
# 允许只写端口
if printf '%s' "$LISTEN" | grep -Eq '^[0-9]+$'; then
  LISTEN="0.0.0.0:$LISTEN"
fi
if printf '%s' "$LISTEN" | grep -Eq '^:[0-9]+$'; then
  LISTEN="0.0.0.0$LISTEN"
fi

HOST=${SBRELAY_CERT_HOST:-}
if [ -z "$HOST" ]; then
  HOST=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
[ -n "$HOST" ] || HOST=127.0.0.1
PUB=${SBRELAY_PUBLIC_URL:-}
if [ -z "$PUB" ] && [ -f "$ENV_FILE" ]; then
  PUB=$(awk -F= '$1=="SBRELAY_PUBLIC_URL"{print substr($0,index($0,"=")+1)}' "$ENV_FILE" || true)
fi
if [ -z "$PUB" ]; then
  port=${LISTEN##*:}
  PUB="https://${HOST}:${port}"
fi

# Bot token：已有则默认保留
HAVE_TOKEN=0
if [ -f "$ENV_FILE" ] && grep -q '^SBRELAY_TG_TOKEN=.\+' "$ENV_FILE"; then
  HAVE_TOKEN=1
fi
NEW_TOKEN=${SBRELAY_TG_TOKEN:-}
if [ -n "$NEW_TOKEN" ] && [ "$HAVE_TOKEN" = 1 ] && [ "${SBRELAY_OVERWRITE_TOKEN:-}" != 1 ]; then
  echo "检测到已有 Bot token，已保留（如需覆盖请设 SBRELAY_OVERWRITE_TOKEN=1）。"
  NEW_TOKEN=""
fi
if [ -z "$NEW_TOKEN" ] && [ "$HAVE_TOKEN" != 1 ]; then
  if [ -t 0 ]; then
    echo "请输入 Telegram Bot token（输入不会回显）："
    read -rs NEW_TOKEN || true
    echo
  fi
fi
if [ -z "$NEW_TOKEN" ] && [ "$HAVE_TOKEN" != 1 ]; then
  echo "缺少 Bot token。请设置 SBRELAY_TG_TOKEN 或在交互时输入。" >&2
  exit 2
fi

OWNER=${SBRELAY_OWNER_ID:-}
if [ -z "$OWNER" ] && [ -f "$ENV_FILE" ]; then
  OWNER=$(awk -F= '$1=="SBRELAY_OWNER_ID"{print substr($0,index($0,"=")+1)}' "$ENV_FILE" || true)
fi

echo "正在安装二进制到 $BIN_DST （并链接 $BIN_LINK）..."
# 短暂停服务再替换，避免正在运行的文件无法覆盖
systemctl stop sbrelay-control.service 2>/dev/null || true
install -o root -g sbrelayctl -m 0750 "$BIN_SRC" "$BIN_DST"
install -o root -g sbrelayctl -m 0750 "$HELPER_SRC" "$HELPER_DST"
if [ -f "$SCRIPT_DIR/install-agent.sh" ]; then
  install -o root -g sbrelayctl -m 0640 "$SCRIPT_DIR/install-agent.sh" /usr/local/lib/sbrelay/install-agent.sh
fi
ln -sfn "$BIN_DST" "$BIN_LINK"

# 证书：已有则保留
if [ ! -s /etc/sbrelay/tls.crt ] || [ ! -s /etc/sbrelay/tls.key ]; then
  echo "未找到 TLS 证书，正在生成自签证书（主机名/IP：$HOST）..."
  SBRELAY_CERT=/etc/sbrelay/tls.crt SBRELAY_KEY=/etc/sbrelay/tls.key SBRELAY_CERT_HOST="$HOST" \
    "$BIN_DST" gen-cert
  chown root:sbrelayctl /etc/sbrelay/tls.crt /etc/sbrelay/tls.key
  chmod 644 /etc/sbrelay/tls.crt
  chmod 640 /etc/sbrelay/tls.key
  echo "已生成自签证书。"
else
  echo "使用已有 TLS 证书，未覆盖。"
fi

umask 077
TMPENV=$(mktemp /tmp/sbrelay-control-env-XXXXXX)
chmod 600 "$TMPENV"
if [ "$HAVE_TOKEN" = 1 ] && [ -z "$NEW_TOKEN" ]; then
  # 从旧文件取出 token，不打印
  awk -F= '$1=="SBRELAY_TG_TOKEN"{print substr($0,index($0,"=")+1); exit}' "$ENV_FILE" > "$TMPENV.tok"
  chmod 600 "$TMPENV.tok"
  NEW_TOKEN=$(cat "$TMPENV.tok")
  rm -f "$TMPENV.tok"
fi
# 写 env，不 echo token
python3 - "$TMPENV" "$NEW_TOKEN" "$OWNER" "$LISTEN" "$PUB" <<'PY'
import os,sys
path,token,owner,listen,pub=sys.argv[1:6]
data={
  "SBRELAY_TG_TOKEN": token,
  "SBRELAY_OWNER_ID": owner,
  "SBRELAY_DATA_DIR": "/var/lib/sbrelay",
  "SBRELAY_LISTEN": listen,
  "SBRELAY_CERT": "/etc/sbrelay/tls.crt",
  "SBRELAY_KEY": "/etc/sbrelay/tls.key",
  "SBRELAY_PUBLIC_URL": pub,
  "SBRELAY_PKG_DIR": "/usr/local/lib/sbrelay",
}
with open(path,"w") as f:
    for k,v in data.items():
        f.write("%s=%s\n"%(k,v))
PY
unset NEW_TOKEN
install -o root -g sbrelayctl -m 0640 "$TMPENV" "$ENV_FILE"
rm -f "$TMPENV"

# systemd unit
UNIT_SRC=${UNIT_SRC:-$SCRIPT_DIR/sbrelay-control.service}
if [ ! -f "$UNIT_SRC" ]; then
  cat > /tmp/sbrelay-control.service <<'UNIT'
[Unit]
Description=sbrelay Telegram control plane
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sbrelayctl
Group=sbrelayctl
EnvironmentFile=/etc/sbrelay/control.env
ExecStart=/usr/local/lib/sbrelay/sbrelay control
WorkingDirectory=/var/lib/sbrelay
Restart=on-failure
RestartSec=3s
LimitNOFILE=4096

[Install]
WantedBy=multi-user.target
UNIT
  UNIT_SRC=/tmp/sbrelay-control.service
fi
install -o root -g root -m 0644 "$UNIT_SRC" "$UNIT"
systemctl daemon-reload
systemctl enable sbrelay-control.service
systemctl start sbrelay-control.service
sleep 1

echo
if systemctl is-active --quiet sbrelay-control.service; then
  echo "控制端服务：active"
else
  echo "控制端服务未能保持运行。请查看：journalctl -u sbrelay-control -n 50" >&2
  systemctl --no-pager --full status sbrelay-control.service | head -20
  exit 1
fi
systemctl --no-pager --full status sbrelay-control.service | head -12

CERT_HEX=$(openssl x509 -in /etc/sbrelay/tls.crt -outform DER | sha256sum | awk '{print $1}')
SPKI=$(openssl x509 -in /etc/sbrelay/tls.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64)
echo
echo "TLS 证书指纹（agent --pin）：$CERT_HEX"
echo "curl --pinnedpubkey：sha256//$SPKI"
echo "对外地址：${PUB}"
echo "监听：${LISTEN}"
echo "数据目录：${STATE_DIR}（更新未覆盖已有 state）"
echo
echo "下一步："
echo "  1. 在 Telegram 向 Bot 发送 /start（首位管理员会被绑定）。"
echo "  2. 用面板「添加线路机」或「添加落地机」生成一键安装命令，到目标机器以 root 执行。"
echo "  3. 卸载控制端： $0 --uninstall （默认保留证书和数据）。"
echo "CONTROL_INSTALLED"

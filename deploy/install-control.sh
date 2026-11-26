#!/bin/bash
# sbrelay 控制端安装 / 更新 / 修复 / 改 token / 卸载。可重复执行。
# 不修改本机 sing-box 入站、出站或服务启动参数。
#
#   sudo ./deploy/install-control.sh              安装 / 更新 / 修复
#   sudo ./deploy/install-control.sh --set-token  只改 Bot token（从标准输入或不回显提示读取），并重启
#   sudo ./deploy/install-control.sh --uninstall  卸载，保留 state、证书和 token
#   sudo ./deploy/install-control.sh --purge      卸载并删除数据（需输入 yes 确认）
#
# 环境变量（可选）：SBRELAY_TG_TOKEN SBRELAY_LISTEN SBRELAY_PUBLIC_URL SBRELAY_CERT_HOST SBRELAY_OWNER_ID
#   证书：SBRELAY_CERT_SRC + SBRELAY_KEY_SRC 导入自有证书；SBRELAY_REGEN_CERT=1 重新生成自签证书。
# 二进制：/usr/local/lib/sbrelay/sbrelay（另链 /usr/local/bin/sbrelay）。更新默认保留 state、证书、token。

set -euo pipefail
set +x

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行。" >&2
  exit 1
fi

for cmd in systemctl openssl python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "缺少依赖命令 $cmd，请先安装。" >&2
    exit 1
  fi
done

SCRIPT_DIR=$(cd "$(dirname "$0")" && pwd)
REPO_ROOT=""
if [ -f "$SCRIPT_DIR/../go.mod" ]; then
  REPO_ROOT=$(cd "$SCRIPT_DIR/.." && pwd)
fi
LIB_DIR=/usr/local/lib/sbrelay
BIN_DST=$LIB_DIR/sbrelay
HELPER_DST=$LIB_DIR/sbrelay-helper
BIN_LINK=/usr/local/bin/sbrelay
PM_LINK=/usr/local/bin/pm
ENV_FILE=/etc/sbrelay/control.env
STATE_DIR=/var/lib/sbrelay
UNIT=/etc/systemd/system/sbrelay-control.service

BUILD_TMP=""
TMPENV=""
cleanup() {
  [ -n "$BUILD_TMP" ] && rm -rf "$BUILD_TMP"
  [ -n "$TMPENV" ] && rm -f "$TMPENV"
}
trap cleanup EXIT

MODE=install
PURGE=0
for a in "$@"; do
  case "$a" in
    --uninstall) MODE=uninstall ;;
    --purge) MODE=uninstall; PURGE=1 ;;
    --set-token) MODE=set-token ;;
    -h|--help) sed -n '2,13p' "$0"; exit 0 ;;
    *) echo "未知参数 $a" >&2; exit 2 ;;
  esac
done

# 只把文件装到目标位置；源和目标是同一个文件时跳过（从已安装位置重跑修复）。
# 二进制和公开脚本对控制端(sbrelayctl)和同机 agent(sbrelay)共用，设为 root:root 0755 避免同机权限冲突。
install_file() {
  local mode=$1 src=$2 dst=$3
  if [ -e "$dst" ] && [ "$src" -ef "$dst" ]; then
    chown root:root "$dst" 2>/dev/null || true
    chmod "$mode" "$dst"
    return 0
  fi
  install -o root -g root -m "$mode" "$src" "$dst"
}

# 从标准输入读一行 Bot token，写进 control.env。不回显、不进命令行参数。
write_token_from_stdin() {
  python3 -c '
import os, sys, tempfile
path = sys.argv[1]
tok = sys.stdin.readline().strip()
if not tok or len(tok) > 256 or any(c.isspace() for c in tok):
    sys.exit("Bot token 为空或格式不对（不能含空白，长度不超过 256）")
lines = []
if os.path.exists(path):
    with open(path) as f:
        lines = [l.rstrip("\n") for l in f if not l.startswith("SBRELAY_TG_TOKEN=")]
lines.insert(0, "SBRELAY_TG_TOKEN=" + tok)
d = os.path.dirname(path)
fd, tmp = tempfile.mkstemp(prefix=".control.env.", dir=d)
with os.fdopen(fd, "w") as f:
    f.write("\n".join(lines) + "\n")
os.chmod(tmp, 0o640)
os.replace(tmp, path)
' "$ENV_FILE"
  chown root:sbrelayctl "$ENV_FILE"
  chmod 640 "$ENV_FILE"
}

read_token_interactive() {
  local tok=""
  if [ -t 0 ]; then
    echo "请输入 Telegram Bot token（输入不会显示，回车结束）："
    IFS= read -rs tok || true
    echo
  else
    IFS= read -r tok || true
  fi
  printf '%s\n' "$tok"
}

uninstall_control() {
  systemctl disable --now sbrelay-control.service 2>/dev/null || true
  rm -f "$UNIT"
  systemctl daemon-reload || true
  rm -f "$BIN_LINK"
  # 本机若也装了 agent，保留共用的二进制和 pm
  if [ ! -f /etc/systemd/system/sbrelay-agent.service ]; then
    rm -f "$BIN_DST" "$HELPER_DST" "$LIB_DIR/install-agent.sh" "$LIB_DIR/install-control.sh" "$LIB_DIR/pm.sh" "$PM_LINK"
    rmdir "$LIB_DIR" 2>/dev/null || true
  fi
  if [ "$PURGE" = 1 ]; then
    echo "即将删除 $STATE_DIR 与 /etc/sbrelay/control.env、证书（含 Bot token，删后无法恢复）。"
    local ans=""
    read -r -p "确认彻底删除？输入 yes 继续：" ans || true
    if [ "$ans" = yes ]; then
      rm -rf "$STATE_DIR"
      rm -f "$ENV_FILE" /etc/sbrelay/tls.crt /etc/sbrelay/tls.key
      rmdir /etc/sbrelay 2>/dev/null || true
      echo "已删除控制端数据。"
    else
      echo "已取消删除数据；服务已卸载，数据保留。"
    fi
  else
    echo "说明：$STATE_DIR 与 /etc/sbrelay（含证书和 Bot token）已保留。"
  fi
  if getent passwd sbrelayctl >/dev/null && [ ! -d "$STATE_DIR" ]; then
    userdel sbrelayctl 2>/dev/null || true
  fi
  echo "CONTROL_UNINSTALLED"
}

if [ "$MODE" = uninstall ]; then
  uninstall_control
  exit 0
fi

if [ "$MODE" = set-token ]; then
  if [ ! -f "$ENV_FILE" ]; then
    echo "还没有安装控制端（找不到 $ENV_FILE）。" >&2
    exit 1
  fi
  read_token_interactive | write_token_from_stdin
  systemctl restart sbrelay-control.service
  sleep 1
  if systemctl is-active --quiet sbrelay-control.service; then
    echo "Bot token 已更新，控制端已重启。"
  else
    echo "控制端重启后未运行，请检查 token：journalctl -u sbrelay-control -n 30" >&2
    exit 1
  fi
  exit 0
fi

echo "======== sbrelay 控制端安装 / 更新 / 修复 ========"

# 定位二进制：BIN_SRC / 脚本同目录 / 仓库编译 / 已安装文件
BIN_SRC=${BIN_SRC:-}
HELPER_SRC=${HELPER_SRC:-}
if [ -z "$BIN_SRC" ] || [ -z "$HELPER_SRC" ]; then
  if [ -n "$REPO_ROOT" ] && command -v go >/dev/null; then
    echo "在仓库里编译（CGO_ENABLED=0）..."
    BUILD_TMP=$(mktemp -d /tmp/sbrelay-build-XXXXXX)
    (cd "$REPO_ROOT" && CGO_ENABLED=0 go build -o "$BUILD_TMP/sbrelay" ./cmd/sbrelay && CGO_ENABLED=0 go build -o "$BUILD_TMP/sbrelay-helper" ./cmd/sbrelay-helper)
    BIN_SRC=$BUILD_TMP/sbrelay
    HELPER_SRC=$BUILD_TMP/sbrelay-helper
  else
    for d in "$SCRIPT_DIR" /tmp/sbrelay-pkg "$LIB_DIR"; do
      if [ -x "$d/sbrelay" ] && [ -x "$d/sbrelay-helper" ]; then
        BIN_SRC=$d/sbrelay
        HELPER_SRC=$d/sbrelay-helper
        break
      fi
    done
  fi
fi
if [ ! -x "${BIN_SRC:-}" ] || [ ! -x "${HELPER_SRC:-}" ]; then
  echo "找不到 sbrelay / sbrelay-helper 二进制，也无法编译。请在仓库目录运行，或设置 BIN_SRC、HELPER_SRC。" >&2
  exit 1
fi

id -u sbrelayctl >/dev/null 2>&1 || useradd --system --home-dir "$STATE_DIR" --shell /usr/sbin/nologin --create-home sbrelayctl
mkdir -p "$LIB_DIR" /etc/sbrelay "$STATE_DIR"
chown sbrelayctl:sbrelayctl "$STATE_DIR"
chmod 750 "$STATE_DIR"
chown root:root /etc/sbrelay
chmod 755 /etc/sbrelay

env_get() {
  [ -f "$ENV_FILE" ] || return 0
  awk -F= -v k="$1" '$1==k{print substr($0,index($0,"=")+1); exit}' "$ENV_FILE"
}

# 监听地址
LISTEN=${SBRELAY_LISTEN:-$(env_get SBRELAY_LISTEN)}
if [ -z "$LISTEN" ]; then
  if [ -t 0 ]; then
    read -r -p "监听地址 [默认 0.0.0.0:8443]：" LISTEN || true
  fi
  LISTEN=${LISTEN:-0.0.0.0:8443}
fi
case "$LISTEN" in
  :*) LISTEN="0.0.0.0$LISTEN" ;;
  *[!0-9]*) ;;
  *) LISTEN="0.0.0.0:$LISTEN" ;;
esac

HOST=${SBRELAY_CERT_HOST:-}
if [ -z "$HOST" ]; then
  HOST=$(hostname -I 2>/dev/null | awk '{print $1}')
fi
HOST=${HOST:-127.0.0.1}
URL_HOST="$HOST"
case "$HOST" in
  *:*) URL_HOST="[$HOST]" ;;
esac
PUB=${SBRELAY_PUBLIC_URL:-$(env_get SBRELAY_PUBLIC_URL)}
PUB=${PUB:-https://${URL_HOST}:${LISTEN##*:}}
OWNER=${SBRELAY_OWNER_ID:-$(env_get SBRELAY_OWNER_ID)}

HAVE_TOKEN=0
if [ -n "$(env_get SBRELAY_TG_TOKEN)" ]; then
  HAVE_TOKEN=1
fi
if [ -n "${SBRELAY_TG_TOKEN:-}" ] && [ "$HAVE_TOKEN" = 1 ] && [ "${SBRELAY_OVERWRITE_TOKEN:-}" != 1 ]; then
  echo "检测到已有 Bot token，已保留（如需覆盖请用 --set-token 或设 SBRELAY_OVERWRITE_TOKEN=1）。"
fi

echo "正在安装二进制到 $BIN_DST（并链接 $BIN_LINK）..."
systemctl stop sbrelay-control.service 2>/dev/null || true
install_file 0755 "$BIN_SRC" "$BIN_DST"
install_file 0755 "$HELPER_SRC" "$HELPER_DST"
# 安装脚本与 pm 一起放进下发目录：控制端会通过 :8443 下发给 agent 机器
for f in install-agent.sh install-control.sh pm.sh; do
  if [ -f "$SCRIPT_DIR/$f" ]; then
    install_file 0755 "$SCRIPT_DIR/$f" "$LIB_DIR/$f"
  fi
done
ln -sfn "$BIN_DST" "$BIN_LINK"
if [ -f "$LIB_DIR/pm.sh" ]; then
  ln -sfn "$LIB_DIR/pm.sh" "$PM_LINK"
fi

# 证书
if [ -n "${SBRELAY_CERT_SRC:-}" ] || [ -n "${SBRELAY_KEY_SRC:-}" ]; then
  if [ ! -s "${SBRELAY_CERT_SRC:-}" ] || [ ! -s "${SBRELAY_KEY_SRC:-}" ]; then
    echo "证书或私钥文件不存在。" >&2
    exit 2
  fi
  if ! openssl x509 -in "$SBRELAY_CERT_SRC" -noout 2>/dev/null; then
    echo "证书文件无法解析。" >&2
    exit 2
  fi
  install -o root -g sbrelayctl -m 0644 "$SBRELAY_CERT_SRC" /etc/sbrelay/tls.crt
  install -o root -g sbrelayctl -m 0640 "$SBRELAY_KEY_SRC" /etc/sbrelay/tls.key
  echo "已导入自有证书。已注册的 agent 需要用新指纹重新安装。"
elif [ "${SBRELAY_REGEN_CERT:-}" = 1 ] || [ ! -s /etc/sbrelay/tls.crt ] || [ ! -s /etc/sbrelay/tls.key ]; then
  echo "正在生成自签证书（主机名/IP：$HOST）..."
  rm -f /etc/sbrelay/tls.crt /etc/sbrelay/tls.key
  SBRELAY_CERT=/etc/sbrelay/tls.crt SBRELAY_KEY=/etc/sbrelay/tls.key SBRELAY_CERT_HOST="$HOST" "$BIN_DST" gen-cert >/dev/null
  chown root:sbrelayctl /etc/sbrelay/tls.crt /etc/sbrelay/tls.key
  chmod 644 /etc/sbrelay/tls.crt
  chmod 640 /etc/sbrelay/tls.key
  echo "已生成自签证书。"
else
  echo "使用已有 TLS 证书，未覆盖。"
fi

# 写 env：token 只经标准输入传递，不进命令行参数
umask 077
TMPENV=$(mktemp /tmp/sbrelay-control-env-XXXXXX)
{
  echo "SBRELAY_OWNER_ID=${OWNER}"
  echo "SBRELAY_DATA_DIR=$STATE_DIR"
  echo "SBRELAY_LISTEN=${LISTEN}"
  echo "SBRELAY_CERT=/etc/sbrelay/tls.crt"
  echo "SBRELAY_KEY=/etc/sbrelay/tls.key"
  echo "SBRELAY_PUBLIC_URL=${PUB}"
  echo "SBRELAY_PKG_DIR=$LIB_DIR"
} > "$TMPENV"
OLD_TOKEN_LINE=0
if [ "$HAVE_TOKEN" = 1 ] && [ "${SBRELAY_OVERWRITE_TOKEN:-}" != 1 ]; then
  grep '^SBRELAY_TG_TOKEN=' "$ENV_FILE" | head -n1 >> "$TMPENV"
  OLD_TOKEN_LINE=1
fi
install -o root -g sbrelayctl -m 0640 "$TMPENV" "$ENV_FILE"
rm -f "$TMPENV"
TMPENV=""
if [ "$OLD_TOKEN_LINE" != 1 ]; then
  if [ -n "${SBRELAY_TG_TOKEN:-}" ]; then
    printf '%s\n' "$SBRELAY_TG_TOKEN" | write_token_from_stdin
  else
    read_token_interactive | write_token_from_stdin
  fi
fi
unset SBRELAY_TG_TOKEN

UNIT_SRC=${UNIT_SRC:-$SCRIPT_DIR/sbrelay-control.service}
if [ -f "$UNIT_SRC" ]; then
  install -o root -g root -m 0644 "$UNIT_SRC" "$UNIT"
elif [ ! -f "$UNIT" ]; then
  cat > "$UNIT" <<'UNITEOF'
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
UNITEOF
fi
systemctl daemon-reload
systemctl enable sbrelay-control.service >/dev/null 2>&1
systemctl start sbrelay-control.service
sleep 1

echo
if ! systemctl is-active --quiet sbrelay-control.service; then
  echo "控制端服务未能保持运行。请查看：journalctl -u sbrelay-control -n 50" >&2
  exit 1
fi
echo "控制端服务：active"
CERT_HEX=$(openssl x509 -in /etc/sbrelay/tls.crt -outform DER | sha256sum | awk '{print $1}')
SPKI=$(openssl x509 -in /etc/sbrelay/tls.crt -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64)
echo "版本：$("$BIN_DST" version 2>/dev/null || echo 未知)"
echo "证书指纹（--pin）：$CERT_HEX"
echo "公钥指纹（--pinnedpubkey）：sha256//$SPKI"
echo "对外地址：$PUB    监听：$LISTEN"
echo "数据目录：$STATE_DIR（更新未覆盖已有 state）"
echo
echo "下一步："
echo "  1. 在 Telegram 向 Bot 发送 /start（首位管理员会被绑定）。"
echo "  2. 面板点「添加线路机 / 添加落地机」，把命令拿到目标机器以 root 执行（自动搭建 SS2022 节点）。"
echo "  3. 以后随时运行 pm 打开管理菜单。"
echo "CONTROL_INSTALLED"

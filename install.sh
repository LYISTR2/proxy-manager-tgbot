#!/bin/bash
# sbrelay 极简引导脚本：下载对应架构的静态 Rust 二进制（SHA-256 校验），然后交给 sbrelay 自身完成安装/管理。
# 用法（root）：
#   bash <(curl -fsSL https://raw.githubusercontent.com/LYISTR2/proxy-manager-tgbot/main/install.sh)
#   bash <(curl -fsSL https://raw.githubusercontent.com/LYISTR2/proxy-manager-tgbot/main/install.sh) control
#   SBRELAY_TOKEN=... bash <(curl -fsSL https://raw.githubusercontent.com/LYISTR2/proxy-manager-tgbot/main/install.sh) agent --url https://控制端:8443 --pin <指纹>
set -euo pipefail
set +x

REPO="${SBRELAY_REPO:-LYISTR2/proxy-manager-tgbot}"
MIRROR="${SBRELAY_MIRROR:-}"
VERSION="${SBRELAY_VERSION:-latest}"
BIN="/usr/local/bin/sbrelay"

die() { printf '%s\n' "$1" >&2; exit "${2:-1}"; }

[ "$(id -u)" -eq 0 ] || die "请以 root 运行（例如先 sudo -i）。"
for cmd in curl sha256sum; do
  command -v "$cmd" >/dev/null 2>&1 || die "缺少命令：$cmd"
done

case "$(uname -m)" in
  x86_64|amd64) ARCH="x86_64" ;;
  aarch64|arm64) ARCH="aarch64" ;;
  *) die "不支持的 CPU 架构：$(uname -m)" ;;
esac

ASSET="sbrelay-linux-${ARCH}"
if [ "$VERSION" = "latest" ]; then
  BASE="${MIRROR}https://github.com/${REPO}/releases/latest/download"
else
  BASE="${MIRROR}https://github.com/${REPO}/releases/download/${VERSION}"
fi

TMP="$(mktemp -d "${TMPDIR:-/tmp}/sbrelay-dl-XXXXXX")"
trap 'rm -rf -- "$TMP"' EXIT

echo "正在下载 ${ASSET}（${REPO}@${VERSION}）..."
curl -fL --proto '=https' --connect-timeout 15 --max-time 180 "${BASE}/${ASSET}" -o "${TMP}/${ASSET}"
curl -fsSL --proto '=https' --connect-timeout 15 --max-time 60 "${BASE}/SHA256SUMS" -o "${TMP}/SHA256SUMS"

(cd "$TMP" && grep "  ${ASSET}\$" SHA256SUMS | sha256sum -c --status -) \
  || die "SHA-256 校验失败，已中止安装。"

install -o root -g root -m 0755 "${TMP}/${ASSET}" "$BIN"
ln -sfn "$BIN" /usr/local/bin/pm

case "${1:-}" in
  control) shift; exec "$BIN" setup control "$@" ;;
  agent)   shift; exec "$BIN" setup agent "$@" ;;
  "")      exec "$BIN" menu ;;
  *)       exec "$BIN" "$@" ;;
esac

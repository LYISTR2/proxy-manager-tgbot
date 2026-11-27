#!/bin/bash
# sbrelay 一键安装入口（在克隆下来的仓库根目录运行）。
#   sudo bash install.sh                         交互选择：控制端 / 线路机 / 落地机 / 状态 / 卸载
#   sudo bash install.sh --role control          安装 / 更新控制端（Bot token 不回显输入，或用环境变量 SBRELAY_TG_TOKEN）
#   sudo bash install.sh --role relay|landing    安装 agent：粘贴面板给的安装命令（不回显）
#   sudo bash install.sh --role relay --url https://控制端:8443 --pin <证书指纹> [--pubkey sha256//...]
#                                                令牌按提示不回显输入；或在 root shell 里先 export SBRELAY_TOKEN
#   sudo bash install.sh --status | --uninstall | --purge
# 只是入口：真正干活的是 deploy/install-control.sh、deploy/install-agent.sh、deploy/pm.sh，这里不重复它们的逻辑。
# 令牌一律走环境变量或不回显输入，不接受命令行参数，不写日志。
set -uo pipefail
set +x

ROOT_DIR=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
DEPLOY_DIR=$ROOT_DIR/deploy
GO_MIN=1.24
WORK=""

ROLE=""; URL=""; PIN=""; PUBKEY=""; ACTION=install
DRY_RUN=0; NO_DEPS=0; NO_GO_DOWNLOAD=0
LISTEN=""; PUBLIC_URL=""

usage() { sed -n '2,9p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; cat <<'U'

参数：
  --role control|relay|landing   要装的角色
  --url URL --pin HEX --pubkey sha256//...   agent 连接控制端的参数（公钥指纹可省，会按证书指纹校验后得出）
  --listen ADDR --public-url URL 控制端监听地址 / 对外地址（默认 0.0.0.0:8443 / 本机 IP）
  --status | --uninstall | --purge
  --no-deps            不自动安装缺少的系统依赖
  --no-go-download     本机没有合适的 Go 时不自动下载（控制端需要 Go ≥ 1.24 编译）
  --dry-run            只打印将要执行的步骤，不改动系统
U
}

cleanup() {
  if [ -n "$WORK" ] && [ -d "$WORK" ]; then
    rm -rf -- "$WORK"
  fi
  WORK=""
  return 0
}
trap cleanup EXIT
trap 'trap - INT; cleanup; exit 130' INT
trap 'trap - TERM; cleanup; exit 143' TERM

say() { printf '%s\n' "$*"; }
die() { printf '%s\n' "$1" >&2; exit "${2:-1}"; }

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --role) ROLE="${2:-}"; shift 2 ;;
      --role=*) ROLE="${1#*=}"; shift ;;
      --url) URL="${2:-}"; shift 2 ;;
      --pin) PIN="${2:-}"; shift 2 ;;
      --pubkey|--pinnedpubkey) PUBKEY="${2:-}"; shift 2 ;;
      --listen) LISTEN="${2:-}"; shift 2 ;;
      --public-url) PUBLIC_URL="${2:-}"; shift 2 ;;
      --status) ACTION=status; shift ;;
      --uninstall) ACTION=uninstall; shift ;;
      --purge) ACTION=purge; shift ;;
      --no-deps) NO_DEPS=1; shift ;;
      --no-go-download) NO_GO_DOWNLOAD=1; shift ;;
      --dry-run) DRY_RUN=1; shift ;;
      -h|--help) usage; exit 0 ;;
      --token|--token=*) die "不接受 --token：令牌请用环境变量 SBRELAY_TOKEN 或按提示不回显输入。" 2 ;;
      *) die "未知参数（为免误回显令牌，不显示内容）。用 --help 查看用法。" 2 ;;
    esac
  done
  case "$ROLE" in
    ""|control|relay|landing) ;;
    agent) ROLE=relay ;;
    *) die "--role 只能是 control、relay 或 landing。" 2 ;;
  esac
}

detect_arch() {
  case "$(uname -m)" in
    x86_64|amd64) echo amd64 ;;
    aarch64|arm64) echo arm64 ;;
    *) return 1 ;;
  esac
}

# go_version_ok "go1.24.3" → 0；低于 GO_MIN 或无法解析 → 1
go_version_ok() {
  local v=${1#go} maj min wmaj wmin
  maj=${v%%.*}; v=${v#*.}; min=${v%%[.a-z]*}
  wmaj=${GO_MIN%%.*}; wmin=${GO_MIN#*.}
  case "$maj$min" in ''|*[!0-9]*) return 1 ;; esac
  [ "$maj" -gt "$wmaj" ] || { [ "$maj" -eq "$wmaj" ] && [ "$min" -ge "$wmin" ]; }
}

have_go() {
  local v
  command -v go >/dev/null 2>&1 || return 1
  v=$(go env GOVERSION 2>/dev/null) || return 1
  go_version_ok "$v"
}

missing_deps() {
  local c miss=()
  for c in systemctl curl openssl python3 tar sha256sum; do
    command -v "$c" >/dev/null 2>&1 || miss+=("$c")
  done
  printf '%s\n' "${miss[@]}"
}

ensure_deps() {
  local miss
  miss=$(missing_deps | paste -sd' ' -)
  [ -z "$miss" ] && return 0
  if [ "$NO_DEPS" = 1 ]; then
    die "缺少依赖：$miss（已指定 --no-deps，请自行安装）。"
  fi
  case " $miss " in *" systemctl "*) die "本机没有 systemd（缺 systemctl），不支持。" ;; esac
  say "缺少依赖：$miss，正在自动安装..."
  if command -v apt-get >/dev/null 2>&1; then
    DEBIAN_FRONTEND=noninteractive apt-get update -qq && DEBIAN_FRONTEND=noninteractive apt-get install -y -qq curl openssl python3 tar coreutils ca-certificates >/dev/null
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q curl openssl python3 tar coreutils ca-certificates
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q curl openssl python3 tar coreutils ca-certificates
  else
    die "无法自动安装依赖，请手动安装：$miss"
  fi
  miss=$(missing_deps | paste -sd' ' -)
  [ -z "$miss" ] || die "依赖仍缺少：$miss"
}

# 控制端需要编译：没有合适的 Go 时，下载官方 Go（校验 SHA-256）到临时目录，只用于这次编译，结束即删。
ensure_go() {
  local arch meta file sum url
  if have_go; then
    say "使用本机 Go：$(go env GOVERSION)"
    return 0
  fi
  [ "$NO_GO_DOWNLOAD" = 1 ] && die "本机没有 Go ≥ $GO_MIN（已指定 --no-go-download）。请先安装 Go。"
  arch=$(detect_arch) || die "不支持的 CPU 架构：$(uname -m)"
  WORK=$(mktemp -d "${TMPDIR:-/tmp}/sbrelay-install-XXXXXX") || die "无法创建临时目录。"
  chmod 700 "$WORK"
  say "本机没有 Go ≥ $GO_MIN，正在下载官方 Go（linux-$arch，仅用于本次编译）..."
  meta=$(curl -fsSL --max-time 30 'https://go.dev/dl/?mode=json' | python3 -c '
import json, sys
arch = sys.argv[1]
for rel in json.load(sys.stdin):
    if not rel.get("stable"):
        continue
    for f in rel.get("files", []):
        if f.get("os") == "linux" and f.get("arch") == arch and f.get("kind") == "archive":
            print(f["filename"], f["sha256"]); sys.exit(0)
sys.exit(1)' "$arch") || die "获取 Go 下载信息失败。"
  file=${meta% *}; sum=${meta#* }
  case "$file" in go*.linux-"$arch".tar.gz) ;; *) die "Go 下载信息异常。" ;; esac
  url="https://go.dev/dl/$file"
  curl -fL# --connect-timeout 20 --max-time 600 "$url" -o "$WORK/$file" || die "下载 Go 失败。"
  printf '%s  %s\n' "$sum" "$WORK/$file" | sha256sum -c --status - || die "Go 安装包 SHA-256 校验失败，已中止。"
  tar -xzf "$WORK/$file" -C "$WORK" || die "解压 Go 失败。"
  export PATH="$WORK/go/bin:$PATH" GOTOOLCHAIN=local GOCACHE="$WORK/gocache" GOPATH="$WORK/gopath" GOMODCACHE="$WORK/gopath/pkg/mod"
  have_go || die "下载的 Go 不可用。"
  say "已准备临时 Go：$(go env GOVERSION)"
}

need_repo() {
  local f
  for f in "$ROOT_DIR/go.mod" "$DEPLOY_DIR/install-control.sh" "$DEPLOY_DIR/install-agent.sh" "$DEPLOY_DIR/pm.sh"; do
    if [ ! -f "$f" ]; then
      die "找不到 deploy/ 下的安装脚本。请在克隆下来的仓库根目录运行：sudo bash install.sh"
    fi
  done
}

choose_role() {
  local c=""
  if [ ! -t 0 ]; then
    die "没有指定 --role，且不是交互终端。用法见 --help。" 2
  fi
  say "======== sbrelay 一键安装 ========"
  say "  1. 控制端（Telegram Bot，管理所有机器）"
  say "  2. 线路机（自动搭 SS2022 客户端节点，可换落地 / 本机直出）"
  say "  3. 落地机（自动搭 SS2022 落地并上报）"
  say "  4. 查看状态"
  say "  5. 卸载"
  say "  0. 退出"
  read -r -p "请输入数字：" c || exit 0
  case "$c" in
    1) ROLE=control ;;
    2) ROLE=relay ;;
    3) ROLE=landing ;;
    4) ACTION=status ;;
    5) ACTION=uninstall ;;
    *) exit 0 ;;
  esac
}

run() {
  if [ "$DRY_RUN" = 1 ]; then
    say "[dry-run] $*"
    return 0
  fi
  "$@"
}

install_control() {
  local -a envs=()
  [ -n "$LISTEN" ] && envs+=("SBRELAY_LISTEN=$LISTEN")
  [ -n "$PUBLIC_URL" ] && envs+=("SBRELAY_PUBLIC_URL=${PUBLIC_URL%/}")
  if [ "$DRY_RUN" = 1 ]; then
    if have_go; then say "[dry-run] 使用本机 Go 编译"; else say "[dry-run] 下载官方 Go 到临时目录编译"; fi
    say "[dry-run] bash deploy/install-control.sh（Bot token：$([ -n "${SBRELAY_TG_TOKEN:-}" ] && echo 环境变量已提供 || echo 不回显输入)）"
    return 0
  fi
  ensure_go
  if [ "${#envs[@]}" -gt 0 ]; then
    env "${envs[@]}" bash "$DEPLOY_DIR/install-control.sh"
  else
    bash "$DEPLOY_DIR/install-control.sh"
  fi
}

install_agent() {
  local tok="${SBRELAY_TOKEN:-}"
  if [ -z "$URL" ]; then
    # 没给参数：交给 pm 的「粘贴面板命令」流程（令牌不回显）
    run bash "$DEPLOY_DIR/pm.sh" 2
    return
  fi
  [ -n "$PIN" ] || die "缺少 --pin（证书指纹，面板命令里 --pin 后面那串）。" 2
  if [ -z "$tok" ] && [ "$DRY_RUN" != 1 ]; then
    [ -t 0 ] || die "缺少安装令牌：请用环境变量 SBRELAY_TOKEN 提供。" 2
    printf '请输入面板给的安装令牌（不回显）：'
    IFS= read -rs tok || true
    echo
    [ -n "$tok" ] || die "没有输入令牌，已取消。" 2
  fi
  local -a args=(--url "${URL%/}" --pin "$PIN" --role "$ROLE")
  [ -n "$PUBKEY" ] && args+=(--pubkey "$PUBKEY")
  if [ "$DRY_RUN" = 1 ]; then
    say "[dry-run] bash deploy/install-agent.sh ${args[*]}（令牌：$([ -n "$tok" ] && echo 已提供 || echo 未提供)，经环境变量传递）"
    return 0
  fi
  SBRELAY_TOKEN="$tok" bash "$DEPLOY_DIR/install-agent.sh" "${args[@]}"
  local rc=$?
  tok=""
  return $rc
}

do_uninstall() {
  local flag=--uninstall
  [ "$ACTION" = purge ] && flag=--purge
  case "$ROLE" in
    control) run bash "$DEPLOY_DIR/install-control.sh" "$flag" ;;
    relay|landing) run bash "$DEPLOY_DIR/install-agent.sh" "$flag" ;;
    *) run bash "$DEPLOY_DIR/pm.sh" 6 ;;
  esac
}

main() {
  parse_args "$@"
  need_repo
  if [ "$DRY_RUN" != 1 ] && [ "$(id -u)" -ne 0 ]; then
    die "请用 root 运行：sudo bash install.sh"
  fi
  if [ "$DRY_RUN" != 1 ]; then
    ensure_deps
  fi
  if [ "$ACTION" = install ] && [ -z "$ROLE" ]; then
    choose_role
  fi
  case "$ACTION" in
    status) run bash "$DEPLOY_DIR/pm.sh" status ;;
    uninstall|purge) do_uninstall ;;
    install)
      case "$ROLE" in
        control) install_control ;;
        relay|landing) install_agent ;;
      esac
      ;;
  esac
}

# 允许被 source（测试用），直接执行时才运行
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi

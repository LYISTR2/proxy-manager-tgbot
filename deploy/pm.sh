#!/bin/bash
# pm — proxy-manager-tgbot 中文管理菜单（控制端 + agent）。
# 安装 / 更新 / 状态 / 改 Bot token / 重启 / 卸载。
# 真正的安装逻辑在 install-control.sh 和 install-agent.sh 里，本脚本只负责交互并调用它们。
# 不修改 sing-box 的入站、出站或 ExecStart。
#
# 一条命令下载运行（从你的控制端下载，公钥指纹校验；-k 只跳过系统 CA）：
#   curl -LfsS --tlsv1.2 -k --pinnedpubkey sha256//<公钥指纹> https://<控制端地址>:8443/pm.sh -o /tmp/pm.sh && sudo bash /tmp/pm.sh
# 装好后直接运行：pm      也可：pm 3（直接看状态）  pm 5（重启）

set -uo pipefail
set +x

PM_VERSION="0.4.0"
LIB_DIR=/usr/local/lib/sbrelay
PM_LINK=/usr/local/bin/pm
CONTROL_UNIT=/etc/systemd/system/sbrelay-control.service
AGENT_UNIT=/etc/systemd/system/sbrelay-agent.service
CONTROL_ENV=/etc/sbrelay/control.env
AGENT_ENV=/etc/sbrelay/agent.env
STATE_FILE=/var/lib/sbrelay/state.json

SELF=$(readlink -f "$0" 2>/dev/null || echo "$0")
SELF_DIR=$(cd "$(dirname "$SELF")" 2>/dev/null && pwd || echo /tmp)
TMP_DIR=""

if [ -t 1 ]; then
  C_G=$'\033[32m'; C_Y=$'\033[33m'; C_R=$'\033[31m'; C_B=$'\033[36m'; C_0=$'\033[0m'
else
  C_G=""; C_Y=""; C_R=""; C_B=""; C_0=""
fi
ok()   { printf '%s%s%s\n' "$C_G" "$*" "$C_0"; }
warn() { printf '%s%s%s\n' "$C_Y" "$*" "$C_0"; }
err()  { printf '%s%s%s\n' "$C_R" "$*" "$C_0" >&2; }

# 临时目录：只能在主 shell 里用 ensure_tmpdir 创建（不要放进 $(...)），
# 否则 TMP_DIR 只在子 shell 里有值，下面的 trap 拿不到路径，/tmp/pm-XXXXXX 会残留。
cleanup() {
  if [ -n "${TMP_DIR:-}" ] && [ -d "$TMP_DIR" ]; then
    rm -rf -- "$TMP_DIR"
  fi
  TMP_DIR=""
  return 0
}
on_signal() {
  local sig=$1 code=$2
  trap - "$sig"
  cleanup
  exit "$code"
}
# pm 不开 errexit：普通命令失败不会退出，这时 ERR 不清理（目录还要接着用）；
# 一旦开了 set -e，出错即退出，ERR 先清理，EXIT 再兜底。
on_err() {
  case $- in *e*) cleanup ;; esac
  return 0
}
trap cleanup EXIT
trap 'on_signal INT 130' INT
trap 'on_signal TERM 143' TERM
trap 'on_signal HUP 129' HUP
trap on_err ERR

ensure_tmpdir() {
  if [ -z "${TMP_DIR:-}" ] || [ ! -d "$TMP_DIR" ]; then
    TMP_DIR=$(mktemp -d "${TMPDIR:-/tmp}/pm-XXXXXX") || { TMP_DIR=""; return 1; }
    chmod 700 "$TMP_DIR"
  fi
}

need_root() {
  if [ "$(id -u)" -ne 0 ]; then
    err "请用 root 运行（sudo pm）。"
    exit 1
  fi
}

has_control() { [ -f "$CONTROL_UNIT" ]; }
has_agent() { [ -f "$AGENT_UNIT" ]; }
svc_state() { systemctl is-active "$1" 2>/dev/null || true; }

envget() {
  [ -f "$1" ] || return 0
  awk -F= -v k="$2" '$1==k{print substr($0,index($0,"=")+1); exit}' "$1"
}

bin_version() {
  if [ -x "$LIB_DIR/sbrelay" ]; then
    "$LIB_DIR/sbrelay" version 2>/dev/null || echo "旧版（无版本号）"
  else
    echo "未安装"
  fi
}

ask() {
  # ask <提示> <默认值>，结果写到 REPLY
  local prompt=$1 def=${2:-}
  REPLY=""
  if [ -n "$def" ]; then
    read -r -p "$prompt [默认 $def]：" REPLY || true
  else
    read -r -p "$prompt：" REPLY || true
  fi
  REPLY=${REPLY:-$def}
}

confirm() {
  local a=""
  read -r -p "$1 [y/N]：" a || true
  case "$a" in y|Y|yes|YES) return 0 ;; *) return 1 ;; esac
}

pause() {
  [ -t 0 ] || return 0
  local _x=""
  read -r -p "按回车返回菜单..." _x || true
}

# 把自己装成 /usr/local/bin/pm（从 /tmp 等处运行时）
self_install() {
  [ -f "$SELF" ] || return 0
  case "$SELF" in /dev/*|/proc/*) return 0 ;; esac
  mkdir -p "$LIB_DIR"
  if [ "$SELF" != "$LIB_DIR/pm.sh" ]; then
    install -o root -g root -m 0755 "$SELF" "$LIB_DIR/pm.sh"
  fi
  ln -sfn "$LIB_DIR/pm.sh" "$PM_LINK"
}

# 证书指纹（hex，证书 DER 的 SHA-256）校验通过后，返回 curl 用的公钥指纹 sha256//...
spki_from_pin() {
  local url=$1 pin=$2 host port conn_host certpem got
  mapfile -t _hp < <(python3 - "$url" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
print(u.hostname or "")
print(u.port or 443)
PY
  )
  host="${_hp[0]:-}"
  port="${_hp[1]:-443}"
  [ -n "$host" ] || return 1
  conn_host="$host"
  case "$host" in *:*) conn_host="[$host]" ;; esac
  certpem=$(timeout 20 openssl s_client -connect "$conn_host:$port" -servername "$host" </dev/null 2>/dev/null | openssl x509 2>/dev/null || true)
  [ -n "$certpem" ] || return 1
  got=$(printf '%s\n' "$certpem" | openssl x509 -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  [ "$got" = "$pin" ] || return 1
  printf 'sha256//%s\n' "$(printf '%s\n' "$certpem" | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64)"
}

fetch_pinned() {
  # fetch_pinned <公钥指纹> <URL> <目标文件>
  curl -LfsS --tlsv1.2 -k --pinnedpubkey "$1" --connect-timeout 20 --max-time 120 "$2" -o "$3"
}

# 找本地脚本：pm 所在目录 → /usr/local/lib/sbrelay
local_script() {
  local d
  for d in "$SELF_DIR" "$LIB_DIR"; do
    if [ -f "$d/$1" ]; then
      printf '%s\n' "$d/$1"
      return 0
    fi
  done
  return 1
}

header() {
  local cst ast role sb
  echo
  printf '%s==============================================%s\n' "$C_B" "$C_0"
  printf '%s  proxy-manager 管理菜单  (pm %s)%s\n' "$C_B" "$PM_VERSION" "$C_0"
  printf '%s==============================================%s\n' "$C_B" "$C_0"
  if has_control; then
    cst=$(svc_state sbrelay-control)
    echo "  控制端：已安装（$cst，$(bin_version)，监听 $(envget "$CONTROL_ENV" SBRELAY_LISTEN)）"
  else
    echo "  控制端：未安装"
  fi
  if has_agent; then
    ast=$(svc_state sbrelay-agent)
    role=$(envget "$AGENT_ENV" SBRELAY_ROLE)
    case "$role" in landing) role="落地机" ;; *) role="线路机" ;; esac
    echo "  agent ：已安装（$role，$ast，$(bin_version)）"
  else
    echo "  agent ：未安装"
  fi
  if systemctl list-unit-files sing-box.service >/dev/null 2>&1 && [ -n "$(systemctl list-unit-files sing-box.service --no-legend 2>/dev/null)" ]; then
    sb=$(svc_state sing-box)
    echo "  sing-box：$sb（pm 不改它的入站/出站/启动参数）"
  fi
  echo "----------------------------------------------"
  echo "  1. 安装 / 更新控制端"
  echo "  2. 安装 / 更新 agent（线路机 / 落地机）"
  echo "  3. 查看状态"
  echo "  4. 修改 Bot token"
  echo "  5. 重启服务"
  echo "  6. 卸载"
  echo "  0. 退出"
  echo "----------------------------------------------"
}

# ---------------- 1. 控制端 ----------------
control_install() {
  local script dir url pk hasbin=0 c cert key
  local -a envs=()
  script=$(local_script install-control.sh || true)
  if [ -f "$SELF_DIR/../go.mod" ] && command -v go >/dev/null; then
    hasbin=1
  elif [ -x "$SELF_DIR/sbrelay" ] && [ -x "$SELF_DIR/sbrelay-helper" ]; then
    hasbin=1
  elif [ -x "$LIB_DIR/sbrelay" ] && [ -x "$LIB_DIR/sbrelay-helper" ] && [ -n "$script" ]; then
    hasbin=1
    warn "将使用本机已安装的二进制（修复模式）。要升级版本，请在仓库目录运行 deploy/pm.sh，或从已有控制端下载。"
    if confirm "从另一台已有控制端下载新版二进制？"; then
      hasbin=0
    fi
  fi
  if [ "$hasbin" != 1 ] || [ -z "$script" ]; then
    echo "本机没有可用的控制端程序。可以从一台已经在跑的控制端下载（公钥指纹校验）。"
    ask "已有控制端地址（https://主机:端口）" ""
    url=${REPLY%/}
    ask "该控制端的公钥指纹（sha256//...）" ""
    pk=$REPLY
    if [ -z "$url" ] || [ -z "$pk" ]; then
      err "缺少地址或指纹，已取消。首次安装也可以：克隆仓库后运行 sudo bash deploy/pm.sh。"
      return 1
    fi
    ensure_tmpdir || { err "无法创建临时目录。"; return 1; }
    dir="$TMP_DIR/control"
    mkdir -p "$dir"
    for f in sbrelay sbrelay-helper; do
      fetch_pinned "$pk" "$url/pkg/$f" "$dir/$f" || { err "下载 $f 失败（地址或指纹不对）。"; return 1; }
      chmod 0755 "$dir/$f"
    done
    for f in install-control.sh install-agent.sh pm.sh; do
      fetch_pinned "$pk" "$url/$f" "$dir/$f" || { err "下载 $f 失败。"; return 1; }
    done
    script="$dir/install-control.sh"
  fi

  echo
  echo "—— 监听地址 ——"
  ask "监听地址" "$(envget "$CONTROL_ENV" SBRELAY_LISTEN | grep . || echo 0.0.0.0:8443)"
  envs+=("SBRELAY_LISTEN=$REPLY")
  ask "对外地址（agent 连接用，留空自动用本机 IP）" "$(envget "$CONTROL_ENV" SBRELAY_PUBLIC_URL)"
  [ -n "$REPLY" ] && envs+=("SBRELAY_PUBLIC_URL=${REPLY%/}")

  echo
  echo "—— 证书 ——"
  if [ -s /etc/sbrelay/tls.crt ]; then
    echo "  1. 保留现有证书（推荐，已注册的 agent 不受影响）"
    echo "  2. 导入自有证书文件"
    echo "  3. 重新生成自签证书（所有 agent 需用新指纹重装）"
    ask "请选择" 1
  else
    echo "  1. 自动生成自签证书（推荐）"
    echo "  2. 导入自有证书文件"
    ask "请选择" 1
  fi
  c=$REPLY
  case "$c" in
    2)
      ask "证书文件路径（PEM）" ""; cert=$REPLY
      ask "私钥文件路径（PEM）" ""; key=$REPLY
      if [ ! -s "$cert" ] || [ ! -s "$key" ]; then err "文件不存在，已取消。"; return 1; fi
      envs+=("SBRELAY_CERT_SRC=$cert" "SBRELAY_KEY_SRC=$key")
      ;;
    3)
      if [ -s /etc/sbrelay/tls.crt ]; then
        confirm "确定重新生成？旧指纹会失效" || { echo "已取消。"; return 1; }
        envs+=("SBRELAY_REGEN_CERT=1")
      fi
      ;;
  esac

  echo
  echo "—— Bot token ——"
  if [ -n "$(envget "$CONTROL_ENV" SBRELAY_TG_TOKEN)" ]; then
    if confirm "已有 Bot token，要换成新的吗？"; then
      envs+=("SBRELAY_OVERWRITE_TOKEN=1")
      echo "稍后会提示输入（不回显）。"
    else
      echo "保留现有 Bot token。"
    fi
  else
    echo "稍后会提示输入 Bot token（不回显）。"
  fi
  echo
  env "${envs[@]}" bash "$script"
}

# ---------------- 2. agent ----------------
# 解析面板命令。结果放全局变量；令牌只进变量，不回显。
P_URL=""; P_PIN=""; P_PUB=""; P_TOK=""
parse_panel_cmd() {
  local s=$1 re
  P_URL=""; P_PIN=""; P_PUB=""; P_TOK=""
  s=${s//\"/}
  s=${s//\'/}
  re='--url[[:space:]=]+([^[:space:]]+)';            [[ $s =~ $re ]] && P_URL=${BASH_REMATCH[1]}
  re='--pin[[:space:]=]+([0-9a-fA-F]{64})';          [[ $s =~ $re ]] && P_PIN=${BASH_REMATCH[1],,}
  re='--(pubkey|pinnedpubkey)[[:space:]=]+(sha256//[A-Za-z0-9+/=]+)'; [[ $s =~ $re ]] && P_PUB=${BASH_REMATCH[2]}
  re='SBRELAY_TOKEN=([^[:space:]]+)';                [[ $s =~ $re ]] && P_TOK=${BASH_REMATCH[1]}
  re='--token[[:space:]=]+([^[:space:]]+)';          [[ -z $P_TOK && $s =~ $re ]] && P_TOK=${BASH_REMATCH[1]}
  if [ -z "$P_URL" ]; then
    re='(https://[^[:space:]/]+)/(install-agent|pm)\.sh'; [[ $s =~ $re ]] && P_URL=${BASH_REMATCH[1]}
  fi
  P_URL=${P_URL%/}
}

get_agent_script() {
  # 优先从控制端取最新脚本，失败再用本地副本。
  # 本函数常在 $(...) 里调用，不能在这里建临时目录：调用方须先在主 shell 里 ensure_tmpdir。
  local url=$1 pk=$2 dst
  dst="${TMP_DIR:+$TMP_DIR/install-agent.sh}"
  if [ -n "$dst" ] && [ -n "$url" ] && [ -n "$pk" ] && fetch_pinned "$pk" "$url/install-agent.sh" "$dst" 2>/dev/null && head -n1 "$dst" | grep -q '^#!/bin/bash'; then
    printf '%s\n' "$dst"
    return 0
  fi
  local_script install-agent.sh
}

agent_install() {
  local role="" m line script url pin pk force_flag=""
  if [ -s /var/lib/sbrelay-agent/agent.json ] && [ -s "$AGENT_ENV" ]; then
    if has_agent; then echo "本机 agent 已注册。"; else echo "本机有保留的 agent 注册数据（之前保留数据卸载过）。"; fi
    echo "  1. 原地更新 / 修复（不需要新令牌，保留注册和 sudoers 白名单）"
    echo "  2. 用面板新命令重新注册安装"
    echo "  0. 返回"
    ask "请选择" 1
    case "$REPLY" in
      1)
        url=$(envget "$AGENT_ENV" SBRELAY_URL)
        pin=$(envget "$AGENT_ENV" SBRELAY_TLS_PIN)
        pk=$(envget "$AGENT_ENV" SBRELAY_PUBKEY)
        if [ -z "$pk" ] && [ -n "$url" ] && [ -n "$pin" ]; then
          pk=$(spki_from_pin "$url" "$pin" || true)
          [ -n "$pk" ] || { err "控制端证书与已保存的指纹不一致或连不上，已中止。"; return 1; }
        fi
        ensure_tmpdir || true
        script=$(get_agent_script "$url" "$pk") || { err "找不到 install-agent.sh。"; return 1; }
        bash "$script" --update --url "$url" --pin "$pin" --pubkey "$pk"
        return
        ;;
      2) force_flag="--force-register" ;;
      *) return 0 ;;
    esac
  fi

  echo "本机是："
  echo "  1. 线路机（可在面板里切换落地）"
  echo "  2. 落地机（只读上报）"
  ask "请选择" 1
  case "$REPLY" in 2) role=landing ;; *) role=relay ;; esac
  echo "实际角色以令牌为准（面板里点的是「添加线路机」还是「添加落地机」）。"
  echo
  echo "  1. 粘贴面板给的安装命令（推荐）"
  echo "  2. 分别输入 控制端地址 / 令牌 / 证书指纹"
  ask "请选择" 1
  m=$REPLY
  if [ "$m" = 2 ]; then
    ask "控制端地址（https://主机:端口）" ""; url=${REPLY%/}
    echo "请输入安装令牌（不回显）："
    IFS= read -rs P_TOK || true; echo
    ask "证书指纹（64 位十六进制，--pin 后面那串）" ""; pin=${REPLY,,}
    ask "公钥指纹（sha256//...，可留空，会按证书指纹自动校验得出）" ""; pk=$REPLY
  else
    echo "请粘贴面板里以 curl 开头的那一行（不回显，粘贴后回车）："
    IFS= read -rs line || true; echo
    parse_panel_cmd "$line"
    line=""
    url=$P_URL; pin=$P_PIN; pk=$P_PUB
  fi
  if [ -z "$url" ] || [ -z "$pin" ] || [ -z "$P_TOK" ]; then
    err "没有读全：控制端地址$([ -n "$url" ] && echo ✓ || echo ✗) 证书指纹$([ -n "$pin" ] && echo ✓ || echo ✗) 令牌$([ -n "$P_TOK" ] && echo ✓ || echo ✗)"
    P_TOK=""
    return 1
  fi
  echo "已读取：控制端 $url，证书指纹 ${pin:0:8}…，令牌已读取（不显示）。"
  if [ -z "$pk" ]; then
    pk=$(spki_from_pin "$url" "$pin" || true)
    [ -n "$pk" ] || { err "控制端证书与指纹不一致或连不上，已中止。"; P_TOK=""; return 1; }
  fi
  ensure_tmpdir || true
  script=$(get_agent_script "$url" "$pk") || { err "下载 install-agent.sh 失败。"; P_TOK=""; return 1; }
  # 令牌只经环境变量交给安装脚本，不出现在进程参数里
  SBRELAY_TOKEN="$P_TOK" bash "$script" $force_flag --url "$url" --pin "$pin" --pubkey "$pk" --role "$role"
  local rc=$?
  P_TOK=""
  return $rc
}

# ---------------- 3. 状态 ----------------
show_status() {
  echo
  echo "======== 状态 ========"
  echo "pm 版本：$PM_VERSION    sbrelay：$(bin_version)"
  if has_control; then
    echo
    echo "[控制端] 服务：$(svc_state sbrelay-control)，开机自启：$(systemctl is-enabled sbrelay-control 2>/dev/null || true)"
    echo "  监听：$(envget "$CONTROL_ENV" SBRELAY_LISTEN)    对外地址：$(envget "$CONTROL_ENV" SBRELAY_PUBLIC_URL)"
    if [ -s /etc/sbrelay/tls.crt ]; then
      echo "  证书指纹（--pin）：$(openssl x509 -in /etc/sbrelay/tls.crt -outform DER 2>/dev/null | sha256sum | awk '{print $1}')"
      echo "  公钥指纹（--pinnedpubkey）：sha256//$(openssl x509 -in /etc/sbrelay/tls.crt -pubkey -noout 2>/dev/null | openssl pkey -pubin -outform der 2>/dev/null | openssl dgst -sha256 -binary | openssl enc -base64)"
    fi
    if [ -n "$(envget "$CONTROL_ENV" SBRELAY_TG_TOKEN)" ]; then
      echo "  Bot token：已配置（不显示）"
    else
      echo "  Bot token：未配置"
    fi
    if [ -f "$STATE_FILE" ]; then
      python3 - "$STATE_FILE" <<'PY'
import json, sys, datetime
try:
    st = json.load(open(sys.argv[1]))
except Exception:
    print("  state.json 读取失败"); sys.exit(0)
now = datetime.datetime.now(datetime.timezone.utc)
def age(ts):
    if not ts or ts.startswith("0001"):
        return None
    import re
    m = re.match(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d)(?:\.\d+)?(Z|[+-]\d\d:\d\d)$", ts)
    if not m:
        return None
    tz = "+00:00" if m.group(2) == "Z" else m.group(2)
    t = datetime.datetime.fromisoformat(m.group(1) + tz)
    return (now - t).total_seconds()
print("  管理员：%s" % ("已绑定" if st.get("owner_id") else "未绑定（请在 TG 发 /start）"))
ms = [m for m in (st.get("machines") or {}).values() if not m.get("revoked")]
print("  已注册机器：%d 台" % len(ms))
for m in sorted(ms, key=lambda x: (x.get("role") or "", x.get("name") or "")):
    a = age(m.get("last_seen"))
    on = "在线" if (m.get("online") and a is not None and a < 90) else "离线"
    last = "从未上报" if a is None else ("%d 秒前" % a if a < 120 else "%d 分钟前" % (a // 60))
    role = "落地机" if m.get("role") == "landing" else "线路机"
    print("    - %s（%s）：%s，最后上报 %s" % (m.get("name") or m.get("id"), role, on, last))
unused = 0
for t in (st.get("tokens") or {}).values():
    if t.get("used"):
        continue
    unused += 1
print("  未使用的安装令牌：%d 个（只显示数量）" % unused)
PY
    fi
  fi
  if has_agent; then
    local url pk role
    url=$(envget "$AGENT_ENV" SBRELAY_URL)
    pk=$(envget "$AGENT_ENV" SBRELAY_PUBKEY)
    role=$(envget "$AGENT_ENV" SBRELAY_ROLE)
    echo
    echo "[agent] 服务：$(svc_state sbrelay-agent)，开机自启：$(systemctl is-enabled sbrelay-agent 2>/dev/null || true)，角色：${role:-relay}"
    echo "  控制端：$url"
    if [ -s /var/lib/sbrelay-agent/agent.json ]; then echo "  注册：已注册"; else echo "  注册：未注册"; fi
    if [ -z "$pk" ] && [ -n "$url" ]; then
      pk=$(spki_from_pin "$url" "$(envget "$AGENT_ENV" SBRELAY_TLS_PIN)" || true)
    fi
    if [ -n "$pk" ] && curl -fsS --tlsv1.2 -k --pinnedpubkey "$pk" --connect-timeout 8 --max-time 10 "$url/healthz" -o /dev/null 2>/dev/null; then
      echo "  控制端连通：正常（指纹校验通过）"
    else
      echo "  控制端连通：失败（网络不通或指纹不符）"
    fi
    local nerr nok
    nok=$(journalctl -u sbrelay-agent --since "-10min" --no-pager -o cat 2>/dev/null | grep -c '已连上控制端' || true)
    nerr=$(journalctl -u sbrelay-agent --since "-10min" --no-pager -o cat 2>/dev/null | grep -c 'poll:' || true)
    echo "  近 10 分钟：连上 ${nok} 次，轮询报错 ${nerr} 次（不在这里打印日志原文）"
    if [ -f /etc/sudoers.d/sbrelay-helper ]; then
      echo "  sudoers 白名单：$(grep -c NOPASSWD /etc/sudoers.d/sbrelay-helper) 条（$(grep -o 'sbrelay-helper [a-z]*$' /etc/sudoers.d/sbrelay-helper | awk '{print $2}' | paste -sd/ -)）"
    fi
  fi
  if ! has_control && ! has_agent; then
    echo "本机还没装控制端或 agent。"
  fi
}

# ---------------- 4. 改 Bot token ----------------
change_token() {
  local script
  if ! has_control; then err "本机没有控制端。"; return 1; fi
  script=$(local_script install-control.sh) || { err "找不到 install-control.sh（请重新运行菜单 1 修复）。"; return 1; }
  # token 由 install-control.sh 在终端不回显读取，经标准输入写入 control.env，不进进程参数和日志
  bash "$script" --set-token
}

# ---------------- 5. 重启 ----------------
restart_services() {
  local any=0
  if has_control; then systemctl restart sbrelay-control; any=1; echo "控制端：$(svc_state sbrelay-control)"; fi
  if has_agent; then systemctl restart sbrelay-agent; any=1; sleep 1; echo "agent：$(svc_state sbrelay-agent)"; fi
  [ "$any" = 1 ] || echo "本机没有需要重启的服务。"
  echo "（sing-box 未重启、未改动）"
}

# ---------------- 6. 卸载 ----------------
uninstall_menu() {
  local target mode flag script
  if ! has_control && ! has_agent; then echo "本机没有安装控制端或 agent。"; return 0; fi
  echo "卸载哪一个："
  has_control && echo "  1. 控制端"
  has_agent && echo "  2. agent"
  echo "  0. 返回"
  ask "请选择" 0
  target=$REPLY
  case "$target" in
    1) has_control || return 0 ;;
    2) has_agent || return 0 ;;
    *) return 0 ;;
  esac
  echo "  1. 只卸载服务，保留数据（state/证书/token 或 agent 注册）"
  echo "  2. 彻底清除（删除数据，无法恢复）"
  ask "请选择" 1
  mode=$REPLY
  flag=--uninstall
  if [ "$mode" = 2 ]; then
    confirm "第一次确认：确定彻底清除？" || { echo "已取消。"; return 0; }
    flag=--purge
    echo "第二次确认会在下一步要求输入 yes。"
  fi
  if [ "$target" = 1 ]; then
    script=$(local_script install-control.sh) || { err "找不到 install-control.sh。"; return 1; }
  else
    script=$(local_script install-agent.sh) || { err "找不到 install-agent.sh。"; return 1; }
  fi
  bash "$script" "$flag"
}

run_choice() {
  case "$1" in
    1) control_install ;;
    2) agent_install ;;
    3) show_status ;;
    4) change_token ;;
    5) restart_services ;;
    6) uninstall_menu ;;
    0|q|exit) exit 0 ;;
    *) warn "请输入 0-6。" ;;
  esac
}

main() {
  need_root
  for c in systemctl curl openssl python3; do
    command -v "$c" >/dev/null || { err "缺少命令 $c，请先安装。"; exit 1; }
  done
  self_install
  case "${1:-}" in
    -h|--help) sed -n '2,10p' "$SELF"; exit 0 ;;
    status) show_status; exit 0 ;;
    restart) restart_services; exit 0 ;;
    [0-6]) run_choice "$1"; exit $? ;;
    "") ;;
    *) err "未知参数。用法：pm [0-6|status|restart]"; exit 2 ;;
  esac
  while true; do
    header
    local c=""
    read -r -p "请输入数字：" c || exit 0
    run_choice "$c"
    pause
  done
}

# 允许被 source（测试用），直接执行时才进菜单
if [ "${BASH_SOURCE[0]}" = "$0" ]; then
  main "$@"
fi

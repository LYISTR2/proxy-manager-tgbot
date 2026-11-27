#!/bin/bash
# 在线路机以 root 运行：按 sb 菜单 [18] 的方式准备 official advanced_relay.sh，再调用其 _relay_config。
# 用法：official-import.sh /root/sbrelay-backups/enc2-....env <listen_port> <node_name>
set -euo pipefail
TOKEN_FILE=$1
LISTEN_PORT=$2
NODE_NAME=$3
ENTRANCE_CHOICE=${ENTRANCE_CHOICE:-7}
RELAY_IP=${RELAY_IP:-}
if [ "$(id -u)" -ne 0 ]; then echo "请用 root 运行" >&2; exit 1; fi
TOKEN=$(awk -F= '$1=="TOKEN"{print substr($0,index($0,"=")+1)}' "$TOKEN_FILE")
PASS=$(awk -F= '$1=="PASS"{print substr($0,index($0,"=")+1)}' "$TOKEN_FILE")
if [ -z "$TOKEN" ] || [ -z "$PASS" ]; then echo "token 文件缺字段" >&2; exit 1; fi

BEFORE=$(sha256sum /usr/local/etc/sing-box/config.json | awk '{print $1}')
UNIT_BEFORE=$(sha256sum /etc/systemd/system/sing-box.service | awk '{print $1}')

ADV=/usr/local/etc/sing-box/advanced_relay.sh
URL=https://raw.githubusercontent.com/0xdabiaoge/singbox-lite/main/advanced_relay.sh
# 审计要求：不接受浮动分支的第三方脚本直接以 root 执行，必须指定固定 commit 下的内容摘要。
# 首次运行会打印实际摘要；核对无误后把它写进 SBRELAY_ADV_SHA256（脚本里或环境变量）再重跑。
ADV_SHA=${SBRELAY_ADV_SHA256:-}
if [ ! -s "$ADV" ]; then
  tmp=$(mktemp)
  curl -fsSL --max-time 30 "$URL" -o "$tmp"
  bash -n "$tmp"
  got=$(sha256sum "$tmp" | awk '{print $1}')
  if [ -z "$ADV_SHA" ]; then
    rm -f "$tmp"
    echo "STOP: 需要先固定 advanced_relay.sh 的内容摘要。" >&2
    echo "本次拉取到的 SHA256=$got" >&2
    echo "核对来源后，用 SBRELAY_ADV_SHA256=$got 重跑本脚本。" >&2
    exit 5
  fi
  if [ "$got" != "$ADV_SHA" ]; then
    rm -f "$tmp"
    echo "STOP: advanced_relay.sh 摘要不符（期望 $ADV_SHA，实际 $got），已丢弃。" >&2
    exit 5
  fi
  chmod 755 "$tmp"
  mv -f "$tmp" "$ADV"
  echo "DOWNLOADED_ADVANCED_RELAY $got"
else
  if [ -n "$ADV_SHA" ]; then
    got=$(sha256sum "$ADV" | awk '{print $1}')
    if [ "$got" != "$ADV_SHA" ]; then
      echo "STOP: 本地 advanced_relay.sh 摘要不符（期望 $ADV_SHA，实际 $got）。" >&2
      exit 5
    fi
  fi
  echo "USING_EXISTING_ADVANCED_RELAY $(sha256sum "$ADV" | awk '{print $1}')"
fi

LOG=/root/sbrelay-backups/import-${LISTEN_PORT}.log
umask 077
set +e
IMPORT_TOKEN="$TOKEN" IMPORT_PASS="$PASS" IMPORT_CHOICE="$ENTRANCE_CHOICE" \
IMPORT_IP="$RELAY_IP" IMPORT_PORT="$LISTEN_PORT" IMPORT_NAME="$NODE_NAME" IMPORT_ENGINE="${IMPORT_ENGINE:-1}" \
bash -c '
  set -eo pipefail
  # 按变量名填入，避免本机同时装了 Xray 时多出的 engine_choice 把后续答案挤乱。
  read() {
    # 只拦截官方导入流程的交互变量；带 -a 的拆分（例如校验 IPv4）必须走 builtin。
    local var="${@: -1}"
    case "$var" in
      token_input) printf -v "$var" "%s" "$IMPORT_TOKEN"; return 0 ;;
      passphrase) printf -v "$var" "%s" "$IMPORT_PASS"; return 0 ;;
      relay_choice) printf -v "$var" "%s" "$IMPORT_CHOICE"; return 0 ;;
      engine_choice) printf -v "$var" "%s" "${IMPORT_ENGINE:-1}"; return 0 ;;
      input_relay_ip) printf -v "$var" "%s" "$IMPORT_IP"; return 0 ;;
      listen_port) printf -v "$var" "%s" "$IMPORT_PORT"; return 0 ;;
      node_name) printf -v "$var" "%s" "$IMPORT_NAME"; return 0 ;;
      entrance_sni) printf -v "$var" "%s" ""; return 0 ;;
    esac
    builtin read "$@"
  }
  _menu_pause() { :; }
  _menu_pause_if_needed() { :; }
  _menu_skip_pause() { :; }
  # shellcheck disable=SC1091
  source /usr/local/etc/sing-box/advanced_relay.sh
  # 覆盖脚本里的 pause（source 会重新定义）
  _menu_pause() { :; }
  _menu_pause_if_needed() { :; }
  _menu_skip_pause() { :; }
  _relay_config
' >"$LOG" 2>&1
rc=$?
set -e
unset TOKEN PASS IMPORT_TOKEN IMPORT_PASS

AFTER=$(sha256sum /usr/local/etc/sing-box/config.json | awk '{print $1}')
UNIT_AFTER=$(sha256sum /etc/systemd/system/sing-box.service | awk '{print $1}')
python3 - "$LOG" <<'PY'
import sys,re
text=open(sys.argv[1],errors="replace").read().splitlines()
skip=re.compile(r"(ss://|vless://|trojan://|hy2://|hysteria2://|分享链接|解密口令|password=|uuid=|TOKEN=|PASS=|ENC2:)", re.I)
for line in text:
    if skip.search(line):
        print("[已过滤一行含分享链接或凭据]")
        continue
    print(line)
PY
echo "CONFIG_SHA_BEFORE=$BEFORE"
echo "CONFIG_SHA_AFTER=$AFTER"
echo "UNIT_SHA_BEFORE=$UNIT_BEFORE"
echo "UNIT_SHA_AFTER=$UNIT_AFTER"
if [ "$BEFORE" != "$AFTER" ]; then
  echo "STOP: config.json 哈希变了。请用备份恢复。" >&2
  exit 3
fi
if [ "$UNIT_BEFORE" != "$UNIT_AFTER" ]; then
  echo "STOP: sing-box.service 被改动了。" >&2
  exit 3
fi
if [ "$rc" -ne 0 ]; then
  echo "IMPORT_FAILED rc=$rc" >&2
  exit "$rc"
fi
if ! jq -e --arg p "$LISTEN_PORT" '.outbounds[]? | select(.tag==("relay-out-"+$p))' /usr/local/etc/sing-box/relay.json >/dev/null; then
  echo "IMPORT_FAILED: relay.json 里没有 relay-out-${LISTEN_PORT}" >&2
  exit 4
fi
echo "IMPORT_OK port=$LISTEN_PORT name=$NODE_NAME"
echo "SERVICE=$(systemctl is-active sing-box)"

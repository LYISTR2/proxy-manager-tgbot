#!/bin/bash
# 按 singbox-lite _landing_config 的 Shadowsocks 分支生成 ENC2 Token。
set -euo pipefail
CFG=/usr/local/etc/sing-box/config.json
CLASH=/usr/local/etc/sing-box/clash.yaml
OUTDIR=${OUTDIR:-/root/sbrelay-backups}
TAG=${TAG:-SS-aes128-in-8888}
umask 077
mkdir -p "$OUTDIR"
node=$(jq -c --arg t "$TAG" '.inbounds[] | select(.tag==$t)' "$CFG")
if [ -z "$node" ]; then echo "找不到入站 $TAG" >&2; exit 1; fi
port=$(printf '%s' "$node" | jq -r '.listen_port')
method=$(printf '%s' "$node" | jq -r '.method')
password=$(printf '%s' "$node" | jq -r '.password')
token_addr=""
if [ -f "$CLASH" ]; then
  token_addr=$(python3 - "$CLASH" "$port" <<'PY'
import re, sys
from pathlib import Path
text = Path(sys.argv[1]).read_text().splitlines()
want = sys.argv[2]
in_proxies = False
cur = {}
def check(d):
    if str(d.get("port")) == want and d.get("server"):
        print(d["server"])
        sys.exit(0)
for line in text:
    if line.startswith("proxies:"):
        in_proxies = True
        continue
    if in_proxies and line and not line[:1].isspace():
        check(cur)
        break
    if not in_proxies:
        continue
    if re.match(r"\s*-\s+name:", line) and cur:
        check(cur)
        cur = {}
    m = re.match(r"\s*-?\s*(name|type|server|port|cipher):\s*(.+)$", line)
    if m:
        cur[m.group(1)] = m.group(2).strip().strip("\"'")
if cur:
    check(cur)
PY
  ) || true
fi
if [ -z "$token_addr" ]; then
  token_addr=$(curl -fsS --max-time 8 https://api.ipify.org || true)
fi
if [ -z "$token_addr" ]; then echo "无法确定落地公网地址" >&2; exit 1; fi
# 只允许 IPv4 / IPv6 / 普通主机名，长度上限防止把错误文本写进去
python3 - "$token_addr" <<'PY'
import re,sys
s=sys.argv[1].strip()
ok=bool(re.match(r"^[A-Za-z0-9.:-]+$", s) and 3 <= len(s) <= 64)
sys.exit(0 if ok else 1)
PY
outbound_json=$(jq -n --arg ip "$token_addr" --arg p "$port" --arg m "$method" --arg pw "$password" \
  '{"type":"shadowsocks","tag":"TEMP_TAG","server":$ip,"server_port":($p|tonumber),"method":$m,"password":$pw}')
passphrase=$(openssl rand -hex 32)
encrypted_token=$(printf '%s' "$outbound_json" | openssl enc -aes-256-cbc -pbkdf2 -salt -a -A -pass fd:3 3<<<"$passphrase")
[ -n "$encrypted_token" ] || { echo "加密失败" >&2; exit 1; }
f="$OUTDIR/enc2-${TAG}.env"
printf 'TOKEN=ENC2:%s\nPASS=%s\n' "$encrypted_token" "$passphrase" > "$f"
chmod 600 "$f"
dec=$(printf '%s' "$encrypted_token" | openssl enc -aes-256-cbc -pbkdf2 -d -a -A -pass fd:3 3<<<"$passphrase")
kind=$(printf '%s' "$dec" | jq -r 'if .server|test("^[0-9.]+$") then "ipv4" elif (.server|contains(":")) then "ipv6" else "host" end')
slen=$(printf '%s' "$dec" | jq -r '.server|length')
echo "$dec" | jq -e '.type=="shadowsocks" and .server_port!=null' >/dev/null
echo "TOKEN_OK file=$f bytes=$(wc -c < "$f") server_kind=$kind slen=$slen port=$port"

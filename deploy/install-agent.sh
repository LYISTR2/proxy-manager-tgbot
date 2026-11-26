#!/bin/bash
# sbrelay agent 一键安装 / 更新 / 修复 / 卸载。
# 不修改 sing-box 入站、出站或服务启动参数。
#
# 用法（由控制端面板生成，令牌不要回显、不要写进世界可读文件）：
#   export HISTCONTROL=ignorespace
#    curl -LfsS --tlsv1.2 -k --pinnedpubkey <证书指纹SPKI> https://<控制端地址>/install-agent.sh \
#      | bash -s -- --url https://<控制端地址> --pin <证书指纹> --pubkey <证书指纹SPKI> --token <token>
#   -k 只跳过系统 CA（自签证书）；真正校验的是 --pinnedpubkey。
# 卸载：同样下载后追加 --uninstall

set -euo pipefail
# 禁止 set -x，避免令牌进日志
set +x

usage() {
  cat <<'USAGE'
用法（root）：
  install-agent.sh --url https://<控制端地址> --pin <证书指纹> --pubkey sha256//<SPKI> [--token <token>]
  install-agent.sh --uninstall

环境变量可代替参数：SBRELAY_URL、SBRELAY_TLS_PIN、SBRELAY_PUBKEY、SBRELAY_TOKEN
已注册过的机器更新时不必再给令牌，不会冲掉 /var/lib/sbrelay-agent 状态。
USAGE
}

URL="${SBRELAY_URL:-}"
PIN="${SBRELAY_TLS_PIN:-}"
PUBKEY="${SBRELAY_PUBKEY:-}"
TOKEN="${SBRELAY_TOKEN:-}"
ROLE="${SBRELAY_ROLE:-}"
UNINSTALL=0
PARSE_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="${2:-}"; shift 2 ;;
    --pin) PIN="${2:-}"; shift 2 ;;
    --pubkey|--pinnedpubkey) PUBKEY="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --role) ROLE="${2:-}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --parse-only) PARSE_ONLY=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) echo "未知参数（已忽略细节以免误回显令牌）" >&2; exit 2 ;;
  esac
done

# 去掉可能的引号空白
trim() { printf '%s' "$1" | sed 's/^[[:space:]]*//;s/[[:space:]]*$//'; }
URL=$(trim "$URL")
PIN=$(trim "$PIN")
PUBKEY=$(trim "$PUBKEY")
TOKEN=$(trim "$TOKEN")
ROLE=$(trim "$ROLE")

if [ "$PARSE_ONLY" = 1 ]; then
  # 只输出解析结果，令牌只报告是否已提供，绝不回显
  tok_set=0
  [ -n "$TOKEN" ] && tok_set=1
  printf 'url=%s\n' "$URL"
  printf 'pin_len=%s\n' "${#PIN}"
  printf 'pubkey=%s\n' "$PUBKEY"
  printf 'token_set=%s\n' "$tok_set"
  printf 'role=%s\n' "$ROLE"
  printf 'uninstall=%s\n' "$UNINSTALL"
  exit 0
fi

if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行。" >&2
  exit 1
fi

uninstall_agent() {
  systemctl disable --now sbrelay-agent.service 2>/dev/null || true
  rm -f /etc/systemd/system/sbrelay-agent.service
  systemctl daemon-reload || true
  rm -f /etc/sudoers.d/sbrelay-helper
  rm -f /usr/local/lib/sbrelay/sbrelay /usr/local/lib/sbrelay/sbrelay-helper
  rm -rf /var/lib/sbrelay-agent /etc/sbrelay/agent.env
  if getent passwd sbrelay >/dev/null; then
    userdel sbrelay || true
  fi
  echo "AGENT_UNINSTALLED"
  echo "说明：/var/lib/sbrelay-helper 里的切换备份默认保留，需要时再手动删除。"
  echo "sing-box 配置未被这个卸载脚本改动。"
}

if [ "$UNINSTALL" = 1 ]; then
  uninstall_agent
  exit 0
fi

if [ -z "$URL" ] || [ -z "$PIN" ]; then
  echo "缺少 --url 或 --pin（证书指纹）。请从 Telegram 面板复制完整命令。" >&2
  exit 2
fi
URL="${URL%/}"
if ! printf '%s' "$URL" | grep -Eq '^https://[A-Za-z0-9.:_-]+(:[0-9]+)?$'; then
  echo "控制端地址不合法，需要 https://<主机>[:端口]" >&2
  exit 2
fi
if ! printf '%s' "$PIN" | grep -Eq '^[0-9a-f]{64}$'; then
  echo "证书指纹（--pin）应为 64 位小写十六进制。" >&2
  exit 2
fi
if [ -n "$PUBKEY" ] && ! printf '%s' "$PUBKEY" | grep -Eq '^sha256//[A-Za-z0-9+/=]+$'; then
  echo "公钥指纹（--pubkey）格式应为 sha256//..." >&2
  exit 2
fi
if [ -n "$ROLE" ] && [ "$ROLE" != "relay" ] && [ "$ROLE" != "landing" ]; then
  echo "角色只能是 relay 或 landing。" >&2
  exit 2
fi

ALREADY=0
if [ -s /var/lib/sbrelay-agent/agent.json ]; then
  ALREADY=1
fi
if [ "$ALREADY" != 1 ] && [ -z "$TOKEN" ]; then
  echo "首次安装需要一次性令牌（--token 或 SBRELAY_TOKEN）。" >&2
  exit 2
fi

curl_pin() {
  local dest="$1" src="$2"
  if [ -n "$PUBKEY" ]; then
    curl -LfsS --tlsv1.2 -k --pinnedpubkey "$PUBKEY" --connect-timeout 20 --max-time 120 "$src" -o "$dest"
  else
    echo "未提供 --pubkey，无法安全下载二进制。请用面板生成的完整命令。" >&2
    return 2
  fi
}

WORKDIR=$(mktemp -d /tmp/sbrelay-agent-XXXXXX)
chmod 700 "$WORKDIR"
cleanup() { rm -rf "$WORKDIR"; }
trap cleanup EXIT

echo "正在从控制端下载 agent 二进制（已启用公钥指纹校验）..."
curl_pin "$WORKDIR/sbrelay" "$URL/pkg/sbrelay"
curl_pin "$WORKDIR/sbrelay-helper" "$URL/pkg/sbrelay-helper"
chmod 0750 "$WORKDIR/sbrelay" "$WORKDIR/sbrelay-helper"
# 简单校验是 ELF
if ! head -c 4 "$WORKDIR/sbrelay" | grep -q $'\x7fELF'; then
  echo "下载的 sbrelay 不是可执行文件，已中止。" >&2
  exit 1
fi
if ! head -c 4 "$WORKDIR/sbrelay-helper" | grep -q $'\x7fELF'; then
  echo "下载的 sbrelay-helper 不是可执行文件，已中止。" >&2
  exit 1
fi

# 若尚未注册，先用令牌向控制端注册，以拿到角色（只读落地 / 可切换线路）
register_if_needed() {
  if [ "$ALREADY" = 1 ]; then
    if [ -z "$ROLE" ] && [ -f /etc/sbrelay/agent.env ]; then
      ROLE=$(awk -F= '$1=="SBRELAY_ROLE"{print substr($0,index($0,"=")+1)}' /etc/sbrelay/agent.env || true)
    fi
    [ -n "$ROLE" ] || ROLE=relay
    echo "检测到已注册状态，执行更新/修复，不重复注册。"
    return 0
  fi
  python3 - "$URL" "$PIN" "$TOKEN" "$WORKDIR/reg.json" <<'PY'
import json, ssl, sys, urllib.error, urllib.request, hashlib, socket
url, pin, token, out = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
class PinnedHTTPS(urllib.request.HTTPSHandler):
    def https_open(self, req):
        return self.do_open(self._cm, req)
    def _cm(self, host, **kw):
        ctx = ssl._create_unverified_context()
        ctx.check_hostname = False
        raw = socket.create_connection((host.split(":")[0], int(host.split(":")[1]) if ":" in host else 443), timeout=20)
        ss = ctx.wrap_socket(raw, server_hostname=host.split(":")[0])
        der = ss.getpeercert(True)
        got = hashlib.sha256(der).hexdigest()
        if got != pin:
            ss.close()
            raise SystemExit("TLS 证书指纹与面板提供的不一致，已拒绝")
        return ss
opener = urllib.request.build_opener(PinnedHTTPS())
req = urllib.request.Request(
    url.rstrip("/") + "/v1/register",
    data=json.dumps({"token": token}).encode(),
    method="POST",
    headers={"Content-Type": "application/json"},
)
try:
    with opener.open(req, timeout=20) as r:
        body = r.read()
except urllib.error.HTTPError as e:
    # 不打印响应正文（可能回显令牌相关信息）
    if e.code in (401, 403):
        raise SystemExit("注册令牌无效、已过期或已使用（已拒绝）")
    raise SystemExit("注册失败，HTTP %s" % e.code)
except SystemExit:
    raise
except Exception:
    raise SystemExit("注册失败（网络或证书校验）")
try:
    data = json.loads(body.decode())
except Exception:
    raise SystemExit("注册失败：控制端返回无法解析")
if not data.get("machine_id") or not data.get("secret"):
    raise SystemExit("注册失败：控制端返回不完整")
open(out, "w").write(json.dumps({"id": data["machine_id"], "secret": data["secret"], "role": data.get("role") or "relay", "name": data.get("name") or ""}))
PY
  ROLE=$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("role") or "relay")' "$WORKDIR/reg.json")
  echo "注册成功，角色：$ROLE"
}

register_if_needed
if [ "$ROLE" != "relay" ] && [ "$ROLE" != "landing" ]; then
  ROLE=relay
fi

if [ "$ROLE" = relay ]; then
  if [ ! -x /usr/local/bin/sing-box ] || [ ! -d /usr/local/etc/sing-box ]; then
    echo "这是一台光机：还没安装 sing-box / singbox-lite。" >&2
    echo "请先用官方脚本安装并导入落地 Token，再重新运行本安装脚本。" >&2
    exit 2
  fi
  if [ ! -f /usr/local/etc/sing-box/relay.json ]; then
    echo "已安装 sing-box，但没有 relay.json。请先用 singbox-lite 做一次中转初始化（不必已有中转）。" >&2
    exit 2
  fi
  echo "检测到已安装的 sing-box / singbox-lite，只安装或更新非 root agent 与 helper，不改动其配置和启动参数。"
fi

id -u sbrelay >/dev/null 2>&1 || useradd --system --home-dir /var/lib/sbrelay-agent --shell /usr/sbin/nologin --create-home sbrelay
mkdir -p /usr/local/lib/sbrelay /etc/sbrelay /var/lib/sbrelay-agent /var/lib/sbrelay-helper
chown sbrelay:sbrelay /var/lib/sbrelay-agent
chmod 750 /var/lib/sbrelay-agent
chown root:root /var/lib/sbrelay-helper
chmod 700 /var/lib/sbrelay-helper

# 已有 agent.json 不覆盖
if [ "$ALREADY" != 1 ] && [ -s "$WORKDIR/reg.json" ]; then
  python3 - "$WORKDIR/reg.json" /var/lib/sbrelay-agent/agent.json <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
open(sys.argv[2],"w").write(json.dumps({"id":d["id"],"secret":d["secret"]}))
PY
  chown sbrelay:sbrelay /var/lib/sbrelay-agent/agent.json
  chmod 600 /var/lib/sbrelay-agent/agent.json
fi

install -o root -g sbrelay -m 0750 "$WORKDIR/sbrelay" /usr/local/lib/sbrelay/sbrelay
install -o root -g sbrelay -m 0750 "$WORKDIR/sbrelay-helper" /usr/local/lib/sbrelay/sbrelay-helper

SUDOERS=/etc/sudoers.d/sbrelay-helper
if [ "$ROLE" = landing ]; then
  cat > "$WORKDIR/sudoers" <<'SU'
# 落地机 helper：只放行只读 status，不允许 switch/rollback。
sbrelay ALL=(root) NOPASSWD: /usr/local/lib/sbrelay/sbrelay-helper status
SU
else
  cat > "$WORKDIR/sudoers" <<'SU'
# sbrelay-helper：只放行三个固定子命令，参数写死在二进制里。
# 切换细节走 stdin JSON，避免 sudoers 通配符。
sbrelay ALL=(root) NOPASSWD: /usr/local/lib/sbrelay/sbrelay-helper status
sbrelay ALL=(root) NOPASSWD: /usr/local/lib/sbrelay/sbrelay-helper switch
sbrelay ALL=(root) NOPASSWD: /usr/local/lib/sbrelay/sbrelay-helper rollback
SU
fi
install -o root -g root -m 0440 "$WORKDIR/sudoers" "$SUDOERS"
if ! /usr/sbin/visudo -c -f "$SUDOERS"; then
  rm -f "$SUDOERS"
  echo "sudoers 校验失败，已删除，未继续安装。" >&2
  exit 1
fi

umask 077
# 更新时保留已有 env 中的 URL/PIN，不写入令牌
if [ -f /etc/sbrelay/agent.env ]; then
  # 去掉可能残留的令牌行，写回必要字段
  python3 - "$URL" "$PIN" "$ROLE" <<'PY'
import os,sys
url,pin,role=sys.argv[1:4]
path="/etc/sbrelay/agent.env"
vals={}
if os.path.exists(path):
    for line in open(path):
        line=line.rstrip("\n")
        if not line or line.startswith("#") or "=" not in line:
            continue
        k,v=line.split("=",1)
        if k=="SBRELAY_TOKEN":
            continue
        vals[k]=v
vals["SBRELAY_URL"]=url
vals["SBRELAY_TLS_PIN"]=pin
vals["SBRELAY_ROLE"]=role
vals["SBRELAY_HELPER"]="/usr/local/lib/sbrelay/sbrelay-helper"
vals["SBRELAY_AGENT_STATE"]="/var/lib/sbrelay-agent"
with open(path,"w") as f:
    for k in ("SBRELAY_URL","SBRELAY_TLS_PIN","SBRELAY_ROLE","SBRELAY_HELPER","SBRELAY_AGENT_STATE"):
        f.write("%s=%s\n"%(k,vals[k]))
PY
else
  cat > /etc/sbrelay/agent.env <<ENV
SBRELAY_URL=${URL}
SBRELAY_TLS_PIN=${PIN}
SBRELAY_ROLE=${ROLE}
SBRELAY_HELPER=/usr/local/lib/sbrelay/sbrelay-helper
SBRELAY_AGENT_STATE=/var/lib/sbrelay-agent
ENV
fi
chown root:sbrelay /etc/sbrelay/agent.env
chmod 640 /etc/sbrelay/agent.env
chmod 750 /etc/sbrelay

cat > "$WORKDIR/sbrelay-agent.service" <<'UNIT'
[Unit]
Description=sbrelay line-agent (connects out to control plane)
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=sbrelay
Group=sbrelay
EnvironmentFile=/etc/sbrelay/agent.env
ExecStart=/usr/local/lib/sbrelay/sbrelay agent
WorkingDirectory=/var/lib/sbrelay-agent
Restart=on-failure
RestartSec=3s

[Install]
WantedBy=multi-user.target
UNIT
install -o root -g root -m 0644 "$WORKDIR/sbrelay-agent.service" /etc/systemd/system/sbrelay-agent.service
systemctl daemon-reload
systemctl enable --now sbrelay-agent.service
systemctl restart sbrelay-agent.service
sleep 2
if systemctl is-active --quiet sbrelay-agent.service; then
  echo "AGENT_INSTALLED"
  echo "服务已启动（角色：$ROLE）。更新不会冲掉已有注册状态。"
else
  echo "AGENT_STARTED_CHECK_LOGS"
  echo "服务未能保持运行。请在本机查看：journalctl -u sbrelay-agent -n 50（日志已打码，请勿把完整日志转发到不安全的地方）。"
  exit 1
fi

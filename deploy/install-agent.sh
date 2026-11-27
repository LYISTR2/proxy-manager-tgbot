#!/bin/bash
# sbrelay agent 一键安装 / 更新 / 修复 / 卸载。
# 线路机：若尚未安装 sing-box，自动安装并搭建 SS2022 节点。
#         已有真实中转或已有 sbrelay-ss2022-in 则保留不覆盖；
#         空骨架 relay.json（文件非空但没有 shadowsocks / 可切换入站）会写入 sbrelay-ss2022-in，不整份覆盖。
# 落地机：若尚未安装 sing-box，自动安装并搭建 SS2022 落地入站并上报给控制端。
#         已有 config.json 但没有 Shadowsocks 入站时，追加 sbrelay-landing-in，不改已有入站/出站/路由；
#         已有 SS 入站则沿用（优先 sbrelay-landing-in，否则首个 shadowsocks）。
#
# 用法（由控制端面板生成，令牌不要回显、不要写进世界可读文件）：
#   export HISTCONTROL=ignorespace
#    curl -LfsS --tlsv1.2 -k --pinnedpubkey <证书指纹SPKI> https://<控制端地址>/install-agent.sh \
#      | SBRELAY_TOKEN=<token> bash -s -- --url https://<控制端地址> --pin <证书指纹> --pubkey <证书指纹SPKI>
#   -k 只跳过系统 CA（自签证书）；真正校验的是 --pinnedpubkey。
#   令牌走环境变量，不出现在进程参数里。
# 卸载：--uninstall（保留注册数据）或 --purge（彻底清除，需输入 yes）
# 已注册机器更新：直接再运行一次，不带参数也行（URL/指纹从 /etc/sbrelay/agent.env 读取）。

set -euo pipefail
# 禁止 set -x，避免令牌进日志
set +x

usage() {
  cat <<'USAGE'
用法（root）：
  install-agent.sh --url https://<控制端地址> --pin <证书指纹> --pubkey sha256//<SPKI> [--token <token>]
  install-agent.sh --update                 已注册机器原地更新（读 /etc/sbrelay/agent.env）
  install-agent.sh --force-register         忽略已有 agent.json，用新令牌重新注册
  install-agent.sh --setup-only --role relay|landing
      只做/补写 sing-box 入站（测试或单独修复用）。目录可用 SBRELAY_SINGBOX_DIR，
      二进制可用 SBRELAY_SINGBOX_BIN。
  install-agent.sh --uninstall              卸载服务，保留注册数据和切换备份
  install-agent.sh --purge                  卸载并删除注册数据、切换备份（需输入 yes）

环境变量可代替参数：SBRELAY_URL、SBRELAY_TLS_PIN、SBRELAY_PUBKEY、SBRELAY_TOKEN、SBRELAY_SS_PORT、SBRELAY_SS_PASSWORD、SBRELAY_PUBLIC_IP、SBRELAY_SINGBOX_DIR、SBRELAY_SINGBOX_BIN
已注册过的机器更新时不必再给令牌，不会冲掉 /var/lib/sbrelay-agent 状态。
USAGE
}

URL="${SBRELAY_URL:-}"
PIN="${SBRELAY_TLS_PIN:-}"
PUBKEY="${SBRELAY_PUBKEY:-}"
TOKEN="${SBRELAY_TOKEN:-}"
ROLE="${SBRELAY_ROLE:-}"
UNINSTALL=0
PURGE=0
PARSE_ONLY=0
FORCE_REGISTER=0
SETUP_ONLY=0

while [ $# -gt 0 ]; do
  case "$1" in
    --url) URL="${2:-}"; shift 2 ;;
    --pin) PIN="${2:-}"; shift 2 ;;
    --pubkey|--pinnedpubkey) PUBKEY="${2:-}"; shift 2 ;;
    --token) TOKEN="${2:-}"; shift 2 ;;
    --role) ROLE="${2:-}"; shift 2 ;;
    --uninstall) UNINSTALL=1; shift ;;
    --purge) UNINSTALL=1; PURGE=1; shift ;;
    --update) shift ;;
    --force-register) FORCE_REGISTER=1; shift ;;
    --setup-only) SETUP_ONLY=1; shift ;;
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
  printf 'purge=%s\n' "$PURGE"
  exit 0
fi

# 测试或单独修复时可设：SBRELAY_SINGBOX_DIR、SBRELAY_SINGBOX_BIN、SBRELAY_SS_PORT、SBRELAY_SS_PASSWORD
SINGBOX_DIR=${SBRELAY_SINGBOX_DIR:-/usr/local/etc/sing-box}
SINGBOX_BIN=${SBRELAY_SINGBOX_BIN:-/usr/local/bin/sing-box}

pick_free_port() {
  if [ -n "${SBRELAY_SS_PORT:-}" ]; then
    echo "$SBRELAY_SS_PORT"
    return 0
  fi
  python3 - <<'PORTPY'
import random, socket
for _ in range(50):
    p = random.randint(20000, 59999)
    s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
    try:
        s.bind(("::", p))
        s.close()
        print(p)
        raise SystemExit(0)
    except OSError:
        s.close()
print(random.randint(20000, 59999))
PORTPY
}

# 在 conf 目录的 relay.json / config.json 里按角色补写 SS2022 入站。
# 打印 CREATED/WRITTEN/APPENDED/SKIP_EXISTING（不回显密码）。非 0 表示失败。
ensure_ss_inbound() {
  local role="$1" port="$2" password="$3"
  python3 - "$role" "$SINGBOX_DIR" "$port" "$password" <<'INBPY'
import json, os, sys

role, conf_dir, port_s, password = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]
port = int(port_s)

def load(path):
    if not os.path.isfile(path) or os.path.getsize(path) == 0:
        return None
    with open(path, encoding="utf-8") as f:
        return json.load(f)

def has_switchable_ss(doc, prefer_tag):
    for ib in (doc or {}).get("inbounds") or []:
        if not isinstance(ib, dict):
            continue
        if prefer_tag and ib.get("tag") == prefer_tag:
            return True
        if ib.get("type") == "shadowsocks":
            return True
    return False

def dump(path, doc):
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(doc, f, indent=2, ensure_ascii=False)
        f.write("\n")
    os.replace(tmp, path)

ss = {
    "type": "shadowsocks",
    "tag": "",
    "listen": "::",
    "listen_port": port,
    "method": "2022-blake3-aes-128-gcm",
    "password": password,
}

if role == "relay":
    path = os.path.join(conf_dir, "relay.json")
    tag = "sbrelay-ss2022-in"
    ss["tag"] = tag
    doc = load(path)
    if doc is not None and has_switchable_ss(doc, tag):
        print("SKIP_EXISTING")
        sys.exit(0)
    created = doc is None
    if doc is None:
        doc = {"inbounds": [], "outbounds": [], "route": {"rules": []}}
    if not isinstance(doc.get("inbounds"), list):
        doc["inbounds"] = []
    route = doc.get("route")
    if not isinstance(route, dict):
        route = {}
        doc["route"] = route
    if not isinstance(route.get("rules"), list):
        route["rules"] = []
    doc["inbounds"].append(ss)
    route["rules"].append({"inbound": tag, "outbound": "direct"})
    dump(path, doc)
    print("CREATED" if created else "WRITTEN")
elif role == "landing":
    path = os.path.join(conf_dir, "config.json")
    tag = "sbrelay-landing-in"
    ss["tag"] = tag
    doc = load(path)
    if doc is not None and has_switchable_ss(doc, tag):
        print("SKIP_EXISTING")
        sys.exit(0)
    if doc is None:
        doc = {
            "log": {"level": "info", "timestamp": True},
            "inbounds": [ss],
            "outbounds": [{"type": "direct", "tag": "direct"}],
            "route": {"final": "direct"},
        }
        dump(path, doc)
        print("CREATED")
        sys.exit(0)
    if not isinstance(doc.get("inbounds"), list):
        doc["inbounds"] = []
    doc["inbounds"].append(ss)
    dump(path, doc)
    print("APPENDED")
else:
    sys.exit("未知角色")
INBPY
}

setup_singbox_node() {
  local role="$1"
  mkdir -p "$SINGBOX_DIR"
  chmod 755 "$SINGBOX_DIR" 2>/dev/null || true
  local need_unit=0
  local need_restart=0
  local port pass action
  local bak_dir=""

  rollback_cfg() {
    if [ -n "$bak_dir" ] && [ -d "$bak_dir" ]; then
      if [ -f "$bak_dir/relay.json" ] || [ -f "$bak_dir/relay.json.__absent" ]; then
        if [ -f "$bak_dir/relay.json" ]; then
          cp -a "$bak_dir/relay.json" "$SINGBOX_DIR/relay.json"
        else
          rm -f "$SINGBOX_DIR/relay.json"
        fi
      fi
      if [ -f "$bak_dir/config.json" ] || [ -f "$bak_dir/config.json.__absent" ]; then
        if [ -f "$bak_dir/config.json" ]; then
          cp -a "$bak_dir/config.json" "$SINGBOX_DIR/config.json"
        else
          rm -f "$SINGBOX_DIR/config.json"
        fi
      fi
      echo "sing-box check 失败，已回滚本次写入的配置。" >&2
    fi
  }

  snapshot() {
    local f=$1
    if [ -z "$bak_dir" ]; then
      bak_dir=$(mktemp -d /tmp/sbrelay-cfgbak-XXXXXX)
    fi
    if [ -e "$SINGBOX_DIR/$f" ]; then
      cp -a "$SINGBOX_DIR/$f" "$bak_dir/$f"
    else
      : > "$bak_dir/$f.__absent"
    fi
  }

  # 写进了 SS 密码的配置只给 root 读；sing-box 若以非 root 用户运行则不收紧，避免起不来。
  restrict_secret_file() {
    local f=$1 u=""
    if [ "$SETUP_ONLY" != 1 ] && command -v systemctl >/dev/null 2>&1; then
      u=$(systemctl show -p User --value sing-box 2>/dev/null || true)
    fi
    if [ -z "$u" ] || [ "$u" = root ]; then
      chmod 600 "$f" 2>/dev/null || true
    else
      echo "提示：sing-box 以用户 $u 运行，未收紧 $f 的权限，请自行确认其他用户不可读。" >&2
    fi
  }

  run_check() {
    if [ "$role" = relay ]; then
      "$SINGBOX_BIN" check -c "$SINGBOX_DIR/config.json" -c "$SINGBOX_DIR/relay.json"
    else
      "$SINGBOX_BIN" check -c "$SINGBOX_DIR/config.json"
    fi
  }

  if [ "$role" = relay ]; then
    if [ ! -s "$SINGBOX_DIR/config.json" ]; then
      snapshot config.json
      cat > "$SINGBOX_DIR/config.json" <<'CFG'
{
  "log": {
    "level": "info",
    "timestamp": true
  },
  "outbounds": [
    {
      "type": "direct",
      "tag": "direct"
    }
  ],
  "route": {
    "final": "direct"
  }
}
CFG
      chmod 600 "$SINGBOX_DIR/config.json" 2>/dev/null || true
      need_restart=1
    fi
    snapshot relay.json
    port=$(pick_free_port)
    if [ -n "${SBRELAY_SS_PASSWORD:-}" ]; then
      pass=$SBRELAY_SS_PASSWORD
    else
      pass=$(openssl rand -base64 16)
    fi
    action=$(ensure_ss_inbound relay "$port" "$pass")
    unset pass
    case "$action" in
      CREATED|WRITTEN)
        echo "已为线路机写入 SS2022 入站 sbrelay-ss2022-in（端口 ${port}，2022-blake3-aes-128-gcm），节点链接会推送到 Telegram。"
        need_restart=1
        if ! run_check; then
          rollback_cfg
          rm -rf "$bak_dir"
          return 1
        fi
        restrict_secret_file "$SINGBOX_DIR/relay.json"
        ;;
      SKIP_EXISTING)
        echo "检测到已有可切换的 Shadowsocks / sbrelay-ss2022-in 入站，已保留原配置。"
        ;;
      *)
        echo "写入线路机入站失败。" >&2
        rollback_cfg
        rm -rf "$bak_dir"
        return 1
        ;;
    esac
    rm -rf "$bak_dir"
    if [ "$SETUP_ONLY" != 1 ] && [ ! -f /etc/systemd/system/sing-box.service ]; then
      cat > /etc/systemd/system/sing-box.service <<'SBUNIT'
[Unit]
Description=sing-box service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json -c /usr/local/etc/sing-box/relay.json
Restart=on-failure
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SBUNIT
      need_unit=1
      need_restart=1
    fi
  else
    snapshot config.json
    port=$(pick_free_port)
    if [ -n "${SBRELAY_SS_PASSWORD:-}" ]; then
      pass=$SBRELAY_SS_PASSWORD
    else
      pass=$(openssl rand -base64 16)
    fi
    action=$(ensure_ss_inbound landing "$port" "$pass")
    unset pass
    case "$action" in
      CREATED)
        echo "已自动为落地机生成 SS2022 落地服务 sbrelay-landing-in（端口 ${port}，2022-blake3-aes-128-gcm）。"
        need_restart=1
        if ! run_check; then
          rollback_cfg
          rm -rf "$bak_dir"
          return 1
        fi
        restrict_secret_file "$SINGBOX_DIR/config.json"
        ;;
      APPENDED)
        echo "已有配置无 Shadowsocks 入站，已追加 sbrelay-landing-in（端口 ${port}），未改动已有入站/出站/路由。"
        need_restart=1
        if ! run_check; then
          rollback_cfg
          rm -rf "$bak_dir"
          return 1
        fi
        restrict_secret_file "$SINGBOX_DIR/config.json"
        ;;
      SKIP_EXISTING)
        echo "检测到已有 Shadowsocks 入站（优先 sbrelay-landing-in，否则沿用首个 shadowsocks），已保留原配置。"
        ;;
      *)
        echo "写入落地机入站失败。" >&2
        rollback_cfg
        rm -rf "$bak_dir"
        return 1
        ;;
    esac
    rm -rf "$bak_dir"
    if [ "$SETUP_ONLY" != 1 ] && [ ! -f /etc/systemd/system/sing-box.service ]; then
      cat > /etc/systemd/system/sing-box.service <<'SBUNIT'
[Unit]
Description=sing-box service
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/sing-box run -c /usr/local/etc/sing-box/config.json
Restart=on-failure
RestartSec=3s
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
SBUNIT
      need_unit=1
      need_restart=1
    fi
  fi

  if [ "$SETUP_ONLY" = 1 ]; then
    return 0
  fi
  if [ "$need_unit" = 1 ]; then
    systemctl daemon-reload
    systemctl enable sing-box.service >/dev/null 2>&1 || true
  fi
  if [ "$need_restart" = 1 ] || ! systemctl is-active --quiet sing-box.service; then
    systemctl restart sing-box.service
  fi
}

if [ "$SETUP_ONLY" = 1 ]; then
  if [ "$ROLE" != "relay" ] && [ "$ROLE" != "landing" ]; then
    echo "--setup-only 需要 --role relay 或 landing。" >&2
    exit 2
  fi
  if ! command -v python3 >/dev/null 2>&1; then
    echo "缺少依赖命令 python3。" >&2
    exit 1
  fi
  setup_singbox_node "$ROLE"
  exit $?
fi


if [ "$(id -u)" -ne 0 ]; then
  echo "请用 root 运行。" >&2
  exit 1
fi

for cmd in systemctl curl openssl python3; do
  if ! command -v "$cmd" >/dev/null 2>&1; then
    echo "缺少依赖命令 $cmd，请先安装。" >&2
    exit 1
  fi
done

uninstall_agent() {
  systemctl disable --now sbrelay-agent.service 2>/dev/null || true
  rm -f /etc/systemd/system/sbrelay-agent.service
  systemctl daemon-reload || true
  rm -f /etc/sudoers.d/sbrelay-helper
  # 本机若也装了控制端，保留共用的二进制和 pm。
  # 保留数据卸载时 pm 也留着（不含秘密），这样之后运行 pm → 2 → 1 即可免令牌恢复；只有彻底清除才删 pm。
  local no_control=0 purged=0
  [ -f /etc/systemd/system/sbrelay-control.service ] || no_control=1
  if [ "$no_control" = 1 ]; then
    rm -f /usr/local/lib/sbrelay/sbrelay /usr/local/lib/sbrelay/sbrelay-helper /usr/local/lib/sbrelay/install-agent.sh
  fi
  if [ "$PURGE" = 1 ]; then
    echo "即将删除本机 agent 注册数据（/var/lib/sbrelay-agent、/etc/sbrelay/agent.env）和切换备份（/var/lib/sbrelay-helper）。"
    local ans=""
    read -r -p "确认彻底删除？输入 yes 继续：" ans || true
    if [ "$ans" = yes ]; then
      rm -rf /var/lib/sbrelay-agent /var/lib/sbrelay-helper /etc/sbrelay/agent.env /etc/sbrelay/public_ip
      rmdir /etc/sbrelay 2>/dev/null || true
      if getent passwd sbrelay >/dev/null; then
        userdel sbrelay || true
      fi
      purged=1
      echo "已删除 agent 数据。控制端面板里的这台机器也可在面板中点击删除。"
    else
      echo "已取消删除数据；服务已卸载，数据保留。"
    fi
  else
    echo "说明：注册数据（/var/lib/sbrelay-agent、/etc/sbrelay/agent.env）和切换备份（/var/lib/sbrelay-helper）已保留，重新安装时无需新令牌。"
  fi
  if [ "$no_control" = 1 ]; then
    if [ "$purged" = 1 ]; then
      rm -f /usr/local/lib/sbrelay/pm.sh /usr/local/bin/pm
      rmdir /usr/local/lib/sbrelay 2>/dev/null || true
    elif [ -e /usr/local/bin/pm ]; then
      echo "恢复：运行 pm，选 2 → 1（原地更新，不需要新令牌）。"
    fi
  fi
  echo "AGENT_UNINSTALLED"
  echo "sing-box 配置未被这个卸载脚本改动。"
}

if [ "$UNINSTALL" = 1 ]; then
  uninstall_agent
  exit 0
fi

# 更新已注册机器时，缺的参数从 agent.env 补（这些都不是秘密）
envget() {
  [ -f /etc/sbrelay/agent.env ] || return 0
  awk -F= -v k="$1" '$1==k{print substr($0,index($0,"=")+1); exit}' /etc/sbrelay/agent.env
}
[ -n "$URL" ] || URL=$(envget SBRELAY_URL)
[ -n "$PIN" ] || PIN=$(envget SBRELAY_TLS_PIN)
[ -n "$PUBKEY" ] || PUBKEY=$(envget SBRELAY_PUBKEY)

if [ -z "$URL" ] || [ -z "$PIN" ]; then
  echo "缺少 --url 或 --pin（证书指纹）。请从 Telegram 面板复制完整命令。" >&2
  exit 2
fi
URL="${URL%/}"
if ! printf '%s' "$URL" | grep -Eq '^https://(\[[0-9A-Fa-f:]+\]|[A-Za-z0-9._-]+)(:[0-9]+)?$'; then
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
if [ "$FORCE_REGISTER" != 1 ] && [ -s /var/lib/sbrelay-agent/agent.json ]; then
  ALREADY=1
fi
if [ "$ALREADY" != 1 ] && [ -z "$TOKEN" ]; then
  echo "首次安装需要一次性令牌（SBRELAY_TOKEN 环境变量或 --token）。" >&2
  exit 2
fi

# 从 URL 提取 host 与 port（兼容 IPv4、域名与 [IPv6]）
extract_host_port() {
  python3 - "$1" <<'PY'
import sys, urllib.parse
u = urllib.parse.urlsplit(sys.argv[1])
h = u.hostname or ""
p = u.port or 443
print(h)
print(p)
PY
}

# 只有证书指纹（--pin）时：取对端证书，确认与指纹一致后再算出公钥指纹，供 curl --pinnedpubkey 使用
if [ -z "$PUBKEY" ]; then
  mapfile -t _hp < <(extract_host_port "$URL")
  host="${_hp[0]:-}"
  port="${_hp[1]:-443}"
  conn_host="$host"
  case "$host" in *:*) conn_host="[$host]" ;; esac
  certpem=$(timeout 20 openssl s_client -connect "$conn_host:$port" -servername "$host" </dev/null 2>/dev/null | openssl x509 2>/dev/null || true)
  got=$(printf '%s\n' "$certpem" | openssl x509 -outform DER 2>/dev/null | sha256sum | awk '{print $1}')
  if [ -z "$certpem" ] || [ "$got" != "$PIN" ]; then
    echo "无法取得控制端证书，或证书指纹不一致，已中止。" >&2
    exit 2
  fi
  PUBKEY="sha256//$(printf '%s\n' "$certpem" | openssl x509 -pubkey -noout | openssl pkey -pubin -outform der | openssl dgst -sha256 -binary | openssl enc -base64)"
  echo "已按证书指纹校验控制端证书，并得到公钥指纹。"
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
chmod 0755 "$WORKDIR/sbrelay" "$WORKDIR/sbrelay-helper"
# 简单校验是 ELF
if ! head -c 4 "$WORKDIR/sbrelay" | grep -q $'\x7fELF'; then
  echo "下载的 sbrelay 不是可执行文件，已中止。" >&2
  exit 1
fi
if ! head -c 4 "$WORKDIR/sbrelay-helper" | grep -q $'\x7fELF'; then
  echo "下载的 sbrelay-helper 不是可执行文件，已中止。" >&2
  exit 1
fi

# 自动安装 sing-box（若本机尚未安装）
ensure_singbox() {
  if [ -x /usr/local/bin/sing-box ]; then
    return 0
  fi
  echo "本机未安装 sing-box，正在自动下载安装官方稳定版..."
  local arch sb_arch ver url tgz
  arch=$(uname -m)
  case "$arch" in
    x86_64|amd64) sb_arch=amd64 ;;
    aarch64|arm64) sb_arch=arm64 ;;
    *) echo "不支持的 CPU 架构：$arch，请手动安装 /usr/local/bin/sing-box。" >&2; return 1 ;;
  esac
  ver=${SBRELAY_SINGBOX_VERSION:-}
  if [ -z "$ver" ]; then
    ver=$(curl -fsSL --max-time 20 https://api.github.com/repos/SagerNet/sing-box/releases/latest 2>/dev/null \
      | python3 -c 'import json,sys; print(json.load(sys.stdin)["tag_name"].lstrip("v"))' 2>/dev/null || true)
  fi
  ver=${ver:-1.11.4}
  url="https://github.com/SagerNet/sing-box/releases/download/v${ver}/sing-box-${ver}-linux-${sb_arch}.tar.gz"
  tgz="$WORKDIR/sing-box.tar.gz"
  curl -fL --connect-timeout 20 --max-time 180 "$url" -o "$tgz"
  tar -xzf "$tgz" -C "$WORKDIR"
  local bin
  bin=$(find "$WORKDIR" -maxdepth 2 -type f -name sing-box | head -n1)
  if [ -z "$bin" ]; then
    echo "解压 sing-box 失败。" >&2
    return 1
  fi
  install -o root -g root -m 0755 "$bin" /usr/local/bin/sing-box
  echo "已安装 sing-box：$(/usr/local/bin/sing-box version | head -n1)"
}

detect_public_ip() {
  local ip="${SBRELAY_PUBLIC_IP:-}"
  if [ -z "$ip" ] && [ -s /etc/sbrelay/public_ip ]; then
    ip=$(tr -d '[:space:]' < /etc/sbrelay/public_ip)
  fi
  if [ -z "$ip" ]; then
    for u in https://api.ipify.org https://ifconfig.me/ip https://ipv4.icanhazip.com; do
      ip=$(curl -fsS --max-time 8 "$u" 2>/dev/null | tr -d '[:space:]' || true)
      if printf '%s' "$ip" | grep -Eq '^[0-9A-Fa-f.:]{3,64}$'; then
        break
      fi
      ip=""
    done
  fi
  if [ -z "$ip" ]; then
    ip=$(hostname -I 2>/dev/null | awk '{print $1}')
  fi
  printf '%s' "$ip"
}

# 先确保 sing-box 二进制可用，再向控制端消耗一次性令牌注册（避免环境安装失败白白消耗令牌）
ensure_singbox

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
  # 令牌经环境变量传给 python，不进进程参数
  SBRELAY_REG_TOKEN="$TOKEN" python3 - "$URL" "$PIN" "$WORKDIR/reg.json" <<'PY'
import json, os, ssl, sys, hashlib, http.client, urllib.parse
url, pin, out = sys.argv[1], sys.argv[2], sys.argv[3]
token = os.environ.pop("SBRELAY_REG_TOKEN", "")
u = urllib.parse.urlsplit(url.rstrip("/"))

class PinnedHTTPS(http.client.HTTPSConnection):
    """只认面板给的证书指纹（证书 DER 的 SHA-256），不依赖系统 CA。"""
    def connect(self):
        http.client.HTTPConnection.connect(self)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        self.sock = ctx.wrap_socket(self.sock, server_hostname=self.host)
        if hashlib.sha256(self.sock.getpeercert(True)).hexdigest() != pin:
            self.sock.close()
            raise SystemExit("TLS 证书指纹与面板提供的不一致，已拒绝")

try:
    conn = PinnedHTTPS(u.hostname, u.port or 443, timeout=20)
    conn.request("POST", "/v1/register", body=json.dumps({"token": token}),
                 headers={"Content-Type": "application/json"})
    resp = conn.getresponse()
    code, body = resp.status, resp.read()
    conn.close()
except SystemExit:
    raise
except Exception:
    raise SystemExit("注册失败（网络或证书校验）")
# 不打印响应正文（可能回显令牌相关信息）
if code in (401, 403):
    raise SystemExit("注册令牌无效、已过期或已使用（已拒绝）")
if code != 200:
    raise SystemExit("注册失败，HTTP %s" % code)
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

id -u sbrelay >/dev/null 2>&1 || useradd --system --home-dir /var/lib/sbrelay-agent --shell /usr/sbin/nologin --create-home sbrelay
mkdir -p /usr/local/lib/sbrelay /etc/sbrelay /var/lib/sbrelay-agent /var/lib/sbrelay-helper
chown sbrelay:sbrelay /var/lib/sbrelay-agent
chmod 750 /var/lib/sbrelay-agent
# 保留数据卸载后重装时，用户 uid 可能变化，修正已有注册文件属主
if [ -f /var/lib/sbrelay-agent/agent.json ]; then
  chown sbrelay:sbrelay /var/lib/sbrelay-agent/agent.json
  chmod 600 /var/lib/sbrelay-agent/agent.json
fi
chown root:root /var/lib/sbrelay-helper
chmod 700 /var/lib/sbrelay-helper
chown root:root /etc/sbrelay
chmod 755 /etc/sbrelay

# 立刻保存注册凭据，避免后续步骤异常导致令牌浪费
if [ "$ALREADY" != 1 ] && [ -s "$WORKDIR/reg.json" ]; then
  python3 - "$WORKDIR/reg.json" /var/lib/sbrelay-agent/agent.json <<'PY'
import json,sys
d=json.load(open(sys.argv[1]))
open(sys.argv[2],"w").write(json.dumps({"id":d["id"],"secret":d["secret"]}))
PY
  chown sbrelay:sbrelay /var/lib/sbrelay-agent/agent.json
  chmod 600 /var/lib/sbrelay-agent/agent.json
fi

# 记录公网 IP（供 helper 上报 SS2022 节点地址）
PUB_IP=$(detect_public_ip)
if [ -n "$PUB_IP" ]; then
  printf '%s\n' "$PUB_IP" > /etc/sbrelay/public_ip
  chmod 644 /etc/sbrelay/public_ip
fi

# 按角色自动初始化 SS2022 节点（已有配置不覆盖）
setup_singbox_node "$ROLE"

# 二进制设为 root:root 0755，确保同机同时运行控制端(sbrelayctl)与 agent(sbrelay)互不冲突
install -o root -g root -m 0755 "$WORKDIR/sbrelay" /usr/local/lib/sbrelay/sbrelay
install -o root -g root -m 0755 "$WORKDIR/sbrelay-helper" /usr/local/lib/sbrelay/sbrelay-helper
# 顺带安装 pm 管理菜单（控制端有就装；失败不影响 agent）
if curl_pin "$WORKDIR/pm.sh" "$URL/pm.sh" 2>/dev/null && head -n1 "$WORKDIR/pm.sh" | grep -q '^#!/bin/bash'; then
  install -o root -g root -m 0755 "$WORKDIR/pm.sh" /usr/local/lib/sbrelay/pm.sh
  ln -sfn /usr/local/lib/sbrelay/pm.sh /usr/local/bin/pm
fi
if curl_pin "$WORKDIR/install-agent.sh" "$URL/install-agent.sh" 2>/dev/null && head -n1 "$WORKDIR/install-agent.sh" | grep -q '^#!/bin/bash'; then
  install -o root -g root -m 0755 "$WORKDIR/install-agent.sh" /usr/local/lib/sbrelay/install-agent.sh
fi

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
  python3 - "$URL" "$PIN" "$ROLE" "$PUBKEY" <<'PY'
import os,sys
url,pin,role,pubkey=sys.argv[1:5]
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
vals["SBRELAY_PUBKEY"]=pubkey
vals["SBRELAY_HELPER"]="/usr/local/lib/sbrelay/sbrelay-helper"
vals["SBRELAY_AGENT_STATE"]="/var/lib/sbrelay-agent"
with open(path,"w") as f:
    for k in ("SBRELAY_URL","SBRELAY_TLS_PIN","SBRELAY_PUBKEY","SBRELAY_ROLE","SBRELAY_HELPER","SBRELAY_AGENT_STATE"):
        f.write("%s=%s\n"%(k,vals[k]))
PY
else
  cat > /etc/sbrelay/agent.env <<ENV
SBRELAY_URL=${URL}
SBRELAY_TLS_PIN=${PIN}
SBRELAY_PUBKEY=${PUBKEY}
SBRELAY_ROLE=${ROLE}
SBRELAY_HELPER=/usr/local/lib/sbrelay/sbrelay-helper
SBRELAY_AGENT_STATE=/var/lib/sbrelay-agent
ENV
fi
chown root:sbrelay /etc/sbrelay/agent.env
chmod 640 /etc/sbrelay/agent.env

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
  echo "服务已启动（角色：$ROLE）。请回到 Telegram 面板查看节点信息与切换落地。"
else
  echo "AGENT_STARTED_CHECK_LOGS"
  echo "服务未能保持运行。请在本机查看：journalctl -u sbrelay-agent -n 50（日志已打码，请勿把完整日志转发到不安全的地方）。"
  exit 1
fi

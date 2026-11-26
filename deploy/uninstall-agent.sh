#!/bin/bash
# 卸载 agent。不改 sing-box 配置。
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
exec "$DIR/install-agent.sh" --uninstall "$@"

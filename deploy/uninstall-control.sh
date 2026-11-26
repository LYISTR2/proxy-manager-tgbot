#!/bin/bash
# 卸载控制端。不改 sing-box。默认保留 /var/lib/sbrelay 与 /etc/sbrelay。
set -euo pipefail
DIR=$(cd "$(dirname "$0")" && pwd)
exec "$DIR/install-control.sh" --uninstall "$@"

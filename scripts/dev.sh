#!/usr/bin/env bash
# 开发启动：加载 env 后跑 Tauri 壳（无头服务器需 xvfb + 软渲染）。
# 用法:
#   bash scripts/dev.sh                      # 仅壳（云端模式）
#   HANA_CLOUD_BASE_URL=... HANA_DAEMON_TOKEN=... bash scripts/dev.sh   # 壳+daemon
set -euo pipefail
cd "$(dirname "$0")/../src-tauri"

# 加载 cargo 环境
# shellcheck disable=SC1091
[ -f "$HOME/.cargo/env" ] && source "$HOME/.cargo/env"

# 版本断言（≥2.10.3，CVE-2026-42184）
bash ../scripts/check-tauri-version.sh

# 无头 Linux 服务器必需：强制软渲染，否则 WebKitGTK 初始化卡死
# （见 Task 3/7 排查记录：无硬件 GL 时默认合成渲染会卡住 setup）
export WEBKIT_DISABLE_COMPOSITING_MODE=1
export WEBKIT_DISABLE_DMABUF_RENDERER=1
export LIBGL_ALWAYS_SOFTWARE=1

# 有显示环境直接跑；无头服务器用 xvfb-run
if [ -n "${DISPLAY:-}" ]; then
  exec cargo run
else
  echo "[dev] 无 DISPLAY，用 xvfb-run 虚拟显示 + 软渲染"
  exec xvfb-run -a cargo run
fi

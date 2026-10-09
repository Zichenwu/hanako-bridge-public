#!/usr/bin/env bash
# 安装 Rust 工具链（rustup 官方源，装到 ~/.cargo，不污染系统）
set -euo pipefail

if command -v cargo >/dev/null 2>&1; then
  echo "[install-rust] cargo 已存在: $(cargo --version)，跳过"
  exit 0
fi

echo "[install-rust] 下载 rustup-init..."
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs -o /tmp/rustup-init.sh
# 静默安装 stable，默认 host triple
sh /tmp/rustup-init.sh -y --default-toolchain stable --profile minimal
rm -f /tmp/rustup-init.sh

# 让当前 shell 立即可用
# shellcheck disable=SC1091
source "$HOME/.cargo/env"
echo "[install-rust] 完成: $(cargo --version)"

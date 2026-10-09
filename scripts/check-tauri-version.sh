#!/usr/bin/env bash
# 断言 src-tauri/Cargo.lock 解析出的 tauri 版本 ≥ 2.10.3（CVE-2026-42184）
# 用法: bash scripts/check-tauri-version.sh  → 退出码 0=合格 1=不合格
set -euo pipefail

MIN="2.10.3"
LOCK="$(dirname "$0")/../src-tauri/Cargo.lock"

if [ ! -f "$LOCK" ]; then
  echo "[check-tauri-version] 未找到 $LOCK（尚未 cargo build），跳过"
  exit 0
fi

# 从 Cargo.lock 提取 tauri 包版本
VER=$(awk '/^name = "tauri"$/{f=1} f&&/^version = /{gsub(/"/,"",$3);print $3;exit}' "$LOCK")
if [ -z "${VER:-}" ]; then
  echo "[check-tauri-version] ❌ Cargo.lock 中未找到 tauri 包"
  exit 1
fi

# 版本比较：MAJOR.MINOR.PATCH
ver_ge() {  # ver_ge A B → A≥B
  [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -n1)" = "$2" ]
}

if ver_ge "$VER" "$MIN"; then
  echo "[check-tauri-version] ✅ tauri $VER ≥ $MIN"
  exit 0
else
  echo "[check-tauri-version] ❌ tauri $VER < $MIN（CVE-2026-42184，必须升级）"
  exit 1
fi

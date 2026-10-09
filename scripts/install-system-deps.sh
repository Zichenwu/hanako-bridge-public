#!/usr/bin/env bash
# 安装 Tauri 2 Linux 系统依赖（WebKitGTK 等）
# 已核实：本机 apt 源为阿里云镜像 ubuntu noble，libgtk-3/librsvg2 已有
set -euo pipefail

PKGS=(
  libwebkit2gtk-4.1-dev
  libsoup-3.0-dev
  libjavascriptcoregtk-4.1-dev
  libgtk-3-dev
  librsvg2-dev
  libxdo-dev
  libssl-dev
  pkg-config
  build-essential
  curl
  wget
  file
)

SUDO=""
if [ "$(id -u)" -ne 0 ]; then
  SUDO="sudo"
fi

echo "[system-deps] apt update..."
$SUDO apt-get update -qq

echo "[system-deps] 安装: ${PKGS[*]}"
$SUDO apt-get install -y -qq "${PKGS[@]}"

echo "[system-deps] 完成"

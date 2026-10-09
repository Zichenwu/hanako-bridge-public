// approval.js — Hanako 确认窗口逻辑
// 安全红线：无 iframe，无远程脚本，仅调用本地 Tauri IPC 命令

"use strict";

// Tauri 2 IPC：从 window.__TAURI__ 命名空间获取
const { invoke } = window.__TAURI__.core;

/** 当前待确认的 task_id（用于 respond_approval） */
let currentTaskId = null;

/** 当前请求的路径（用于 trust_session 时确定信任目录） */
let currentPath = null;

// ─── 加载待确认请求 ─────────────────────────────────────────────

async function loadPending() {
  try {
    const req = await invoke("get_pending_approval");

    const loadingEl = document.getElementById("loading");
    const noPendingEl = document.getElementById("no-pending");
    const buttonsEl = document.getElementById("buttons");

    if (!req) {
      // 无待确认请求（可能已被处理或已超时）
      if (loadingEl) loadingEl.style.display = "none";
      if (noPendingEl) noPendingEl.style.display = "block";
      return;
    }

    // 隐藏 loading，显示按钮
    if (loadingEl) loadingEl.style.display = "none";
    if (buttonsEl) buttonsEl.style.display = "flex";

    currentTaskId = req.task_id;
    currentPath = req.path;

    // 填充信息
    setText("agent", req.agent_id || "—");
    setOp("op", req.op || "—");
    setText("path", req.path || "—");

    // 备份路径
    const backupRow = document.getElementById("backup-row");
    const backupEl = document.getElementById("backup");
    if (req.backup_path && backupEl && backupRow) {
      backupEl.textContent = "已备份到 " + req.backup_path;
      backupRow.style.display = "flex";
    }

    // diff 预览
    const diffWrapper = document.getElementById("diff-wrapper");
    const diffEl = document.getElementById("diff");
    if (req.diff_preview && diffEl && diffWrapper) {
      diffEl.textContent = req.diff_preview;
      diffWrapper.style.display = "block";
    }
  } catch (err) {
    console.error("[approval] loadPending 失败:", err);
    const loadingEl = document.getElementById("loading");
    if (loadingEl) loadingEl.textContent = "加载失败: " + String(err);
  }
}

// ─── 工具函数 ────────────────────────────────────────────────────

function setText(id, text) {
  const el = document.getElementById(id);
  if (el) el.textContent = text;
}

function setOp(id, op) {
  const el = document.getElementById(id);
  if (!el) return;
  el.textContent = op;
  // 操作类型徽章着色
  el.className = "value op-badge";
  if (op === "delete") el.classList.add("op-delete");
  else if (op === "write") el.classList.add("op-write");
  else if (op === "edit") el.classList.add("op-edit");
}

// ─── 用户决策 ─────────────────────────────────────────────────────

/**
 * 提交用户决策。
 * @param {"approved"|"rejected"|"trust_session"} decision
 */
async function respond(decision) {
  if (!currentTaskId) {
    console.warn("[approval] currentTaskId 为空，忽略响应");
    return;
  }

  // 禁用按钮，防止重复点击
  const buttons = document.querySelectorAll(".btn");
  buttons.forEach((b) => {
    b.disabled = true;
    b.style.opacity = "0.5";
  });

  try {
    // trust_session 时传回路径，让 Rust 端提取 parent 作为信任目录
    const trustPath =
      decision === "trust_session" && currentPath ? currentPath : null;

    await invoke("respond_approval", {
      taskId: currentTaskId,
      decision: decision,
      trustPath: trustPath,
    });

    // 关闭窗口
    const { getCurrentWindow } = window.__TAURI__.window;
    const win = getCurrentWindow();
    await win.close();
  } catch (err) {
    console.error("[approval] respond 失败:", err);
    // 解除禁用，允许用户重试
    buttons.forEach((b) => {
      b.disabled = false;
      b.style.opacity = "";
    });
  }
}

// ─── 页面初始化 ───────────────────────────────────────────────────

// DOMContentLoaded 后加载请求，确保 Tauri IPC 已就绪
document.addEventListener("DOMContentLoaded", () => {
  // CSP `default-src 'self'` 禁内联事件处理器：按钮绑定必须在这里做，不能写 onclick=（审核 R2-N1）
  for (const btn of document.querySelectorAll("button[data-decision]")) {
    btn.addEventListener("click", () => respond(btn.dataset.decision));
  }
  loadPending();
});

// approval.js — Hanako 写文件 / 删除确认窗口
// 安全红线：无 iframe，无远程脚本，仅调用本地 Tauri IPC 命令
//
// 2026-10-29：窗口改为**复用**（不再每个请求关旧建新）。Rust 侧排队，同时只展示一组；
// 同一助手同一会话的连续删除合并成一组，一次「全部允许 / 全部拒绝」。
// 本页每秒拉一次当前组：组变了就重绘；Rust 收起窗口时页面不需要做任何事。
// 提交时回传**用户看到的**那些 task_id——展示期间新并进来的不会被一并批准。

"use strict";

const { invoke } = window.__TAURI__.core;

/** 当前展示的一组（get_pending_approval 的返回值） */
let current = null;
/** 当前组的签名：组 id + 条目 id 列表，用于判断是否需要重绘 */
let currentSig = "";
let submitting = false;
/** 本组到期时刻（本地时钟，仅用于倒计时展示） */
let deadline = 0;

function el(id) {
  return document.getElementById(id);
}

function setText(id, text) {
  const e = el(id);
  if (e) e.textContent = text;
}

function setOp(op) {
  const e = el("op");
  if (!e) return;
  const label = { delete: "删除", write: "写入", edit: "修改" }[op] || op;
  e.textContent = label;
  e.className = "value op-badge";
  if (op === "delete") e.classList.add("op-delete");
  else if (op === "write") e.classList.add("op-write");
  else if (op === "edit") e.classList.add("op-edit");
}

function sigOf(req) {
  return req ? req.group_id + "|" + req.items.map((i) => i.task_id).join(",") : "";
}

function render(req) {
  const loading = el("loading");
  const noPending = el("no-pending");
  const buttons = el("buttons");
  if (loading) loading.style.display = "none";

  if (!req) {
    current = null;
    currentSig = "";
    if (noPending) noPending.style.display = "block";
    if (buttons) buttons.style.display = "none";
    el("list-wrapper").style.display = "none";
    el("queue-hint").style.display = "none";
    setText("countdown", "");
    return;
  }
  if (noPending) noPending.style.display = "none";
  if (buttons) buttons.style.display = "flex";

  current = req;
  currentSig = sigOf(req);
  deadline = Date.now() + (Number(req.remaining_sec) || 0) * 1000;

  const items = Array.isArray(req.items) && req.items.length ? req.items : [req];
  const multi = items.length > 1;

  setText("agent", req.agent_id || "—");
  setOp(req.op || "—");
  setText("title", multi ? `Hanako 想删除 ${items.length} 个文件` : req.op === "delete" ? "Hanako 想删除一个文件" : "Hanako 需要修改你的文件");

  // 单条：显示路径行；多条：路径行隐藏，改为清单
  el("path-row").style.display = multi ? "none" : "flex";
  setText("path", items[0].path || "—");
  const list = el("list");
  list.replaceChildren(...items.map((i) => {
    const li = document.createElement("li");
    li.textContent = i.path; // textContent：文件名不会被当成 HTML
    return li;
  }));
  el("list-wrapper").style.display = multi ? "block" : "none";

  // 备份：删除是移入备份区（可回滚），多条时只给一句总说明
  const backupRow = el("backup-row");
  if (multi) {
    setText("backup", "删除前都会先备份，可以回滚");
    backupRow.style.display = "flex";
  } else if (items[0].backup_path) {
    setText("backup", "已备份到 " + items[0].backup_path);
    backupRow.style.display = "flex";
  } else {
    backupRow.style.display = "none";
  }

  const diffWrapper = el("diff-wrapper");
  if (!multi && items[0].diff_preview) {
    setText("diff", items[0].diff_preview);
    diffWrapper.style.display = "block";
  } else {
    diffWrapper.style.display = "none";
  }

  setText("approve", multi ? `全部允许（${items.length}）` : "同意");
  setText("reject", multi ? "全部拒绝" : "拒绝");

  const q = Number(req.queued_after) || 0;
  el("queue-hint").style.display = q > 0 ? "block" : "none";
  setText("queue-hint", q > 0 ? `之后还有 ${q} 个请求等你确认` : "");

  setButtons(true);
  tickCountdown();
}

function setButtons(enabled) {
  for (const b of document.querySelectorAll(".btn")) {
    b.disabled = !enabled;
    b.style.opacity = enabled ? "" : "0.5";
  }
}

function tickCountdown() {
  if (!current) return;
  const left = Math.max(0, Math.ceil((deadline - Date.now()) / 1000));
  setText("countdown", left > 0 ? `${left} 秒内不处理将自动拒绝` : "已超时");
}

async function refresh() {
  if (submitting) return;
  try {
    const req = await invoke("get_pending_approval");
    if (sigOf(req) !== currentSig) render(req);
  } catch (err) {
    console.error("[approval] 拉取失败:", err);
  }
}
// Rust 展示窗口时会调它，让新请求立刻出现（不必等下一次轮询）
window.__hanakoApprovalRefresh = refresh;

/**
 * 提交决定。
 * @param {"approved"|"rejected"} decision
 */
async function respond(decision) {
  if (!current || submitting) return;
  submitting = true;
  setButtons(false);
  const shown = current;
  try {
    await invoke("respond_approval", {
      taskId: shown.group_id,
      decision,
      taskIds: (shown.items || []).map((i) => i.task_id),
    });
  } catch (err) {
    // 组已超时 / 已被别处结算：不报错给用户，直接拉最新一组
    console.warn("[approval] respond 失败:", err);
  } finally {
    submitting = false;
    currentSig = "";
    await refresh();
  }
}

document.addEventListener("DOMContentLoaded", () => {
  // CSP `default-src 'self'` 禁内联事件处理器：按钮绑定必须在这里做，不能写 onclick=（审核 R2-N1）
  for (const btn of document.querySelectorAll("button[data-decision]")) {
    btn.addEventListener("click", () => respond(btn.dataset.decision));
  }
  refresh();
  setInterval(() => {
    tickCountdown();
    refresh();
  }, 1000);
});

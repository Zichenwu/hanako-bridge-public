// settings.js — 设置窗（S1）：连接状态行 + 每个文件夹一张卡 + 不在电脑前时。
// 取代旧版「云端地址 / Token / 节点标识」三个输入框——登录改走浏览器授权码（票 14）。
// 放宽权限（加目录 / 看和改 / 一直允许上云 / 授权助手）只在这里发生，网页侧没有对应路径。
"use strict";

const root = document.getElementById("root");
let last = null;
let errMsg = "";
let removeId = null;        // 正在显示「移除确认」的目录
let trustId = null;         // 正在显示「开永久上传确认」的目录
let previewTrustId = null;  // 正在显示「开永久预览确认」的目录（与 trustId 是两个独立状态，
                            // 否则两张确认框会互相顶掉，用户以为点的是预览其实开了上传）
let advOpen = false;        // 底部「高级」是否展开
let nameEdit = null;       // 正在编辑电脑名：null = 未编辑；字符串 = 输入框当前值（轮询重绘不丢输入）

function statusRow(o) {
  const c = o.connection, a = o.auth;
  let dot = "", sub = "";
  if (a.state === "need_reauth") { dot = "warn"; sub = t("set.needReauth"); }
  else if (a.state === "signed_out" && !c.configured) { dot = "off"; sub = t("set.signedOut"); }
  else if (c.connected) { sub = c.agent_id ? t("set.connected", { agent: teamOf(c.agent_id) }) : t("set.connectedNoAgent"); }
  else { dot = "off"; sub = c.last_connected ? t("set.retrying", { time: c.last_connected }) : t("set.retryingNever"); }
  const needLogin = a.state === "signed_out" || a.state === "need_reauth";
  return h("div", { class: "status" },
    h("span", { class: "dot " + dot }),
    h("div", { style: "min-width:0" }, nameView(o), h("br"), h("small", {}, sub)),
    h("div", { class: "r" },
      needLogin
        ? h("button", { type: "button", class: "btn sm pri", onclick: () => act(() => invoke("auth_login", { agentId: null })) }, t("set.login"))
        : h("button", { type: "button", class: "btn sm", onclick: () => act(() => invoke("auth_logout")) }, t("set.signOut"))));
}

// 电脑名：只影响网页上的显示（身份不变，已绑定的对话不受影响）。空 = 恢复默认（主机名）。
function nameView(o) {
  const shown = o.display_name || o.display_default || o.machine;
  if (nameEdit === null) {
    return h("span", { class: "name-view" },
      h("b", { title: t("set.name.hint") }, shown),
      h("button", { type: "button", class: "link-btn", onclick: () => { nameEdit = o.display_name || ""; render(); focusName(); } }, t("set.name.edit")));
  }
  const save = () => { const v = nameEdit; nameEdit = null; act(() => invoke("ui_set_display_name", { name: v })); };
  return h("span", { class: "name-edit" },
    h("input", { type: "text", class: "name-inp", id: "name-inp", maxlength: "32", value: nameEdit, placeholder: o.display_default || o.machine,
      oninput: (e) => { nameEdit = e.target.value; },
      onkeydown: (e) => { if (e.key === "Enter") save(); else if (e.key === "Escape") { nameEdit = null; render(); } } }),
    h("button", { type: "button", class: "btn sm pri", onclick: save }, t("common.save")),
    h("button", { type: "button", class: "btn sm", onclick: () => { nameEdit = null; render(); } }, t("common.cancel")));
}
function focusName() { const el = document.getElementById("name-inp"); if (el) { el.focus(); el.select(); } }

function removeConfirm(f) {
  return h("div", { class: "inline-confirm" },
    h("div", {}, t("set.remove.confirm")),
    h("div", { class: "btns" },
      h("button", { type: "button", class: "btn sm", onclick: () => { removeId = null; render(); } }, t("common.cancel")),
      h("button", { type: "button", class: "btn sm dangerous", onclick: () => { removeId = null; act(() => invoke("ui_remove_folder", { rootId: f.root_id })); } }, t("folder.remove"))));
}

function trustConfirm(f) {
  return h("div", { class: "inline-confirm", style: "background:rgba(var(--accent-rgb),.07)" },
    h("div", {}, t("set.trust.confirm", { folder: f.name })),
    h("div", { style: "font-size:11.5px;color:var(--text)" }, t("set.trust.limits")),
    h("div", { class: "btns" },
      h("button", { type: "button", class: "btn sm", onclick: () => { trustId = null; render(); } }, t("common.cancel")),
      h("button", { type: "button", class: "btn sm pri", onclick: () => { trustId = null; act(() => invoke("ui_set_upload", { rootId: f.root_id, pref: "always" })); } }, t("folder.upload.always"))));
}

/// 开「永久允许在网页预览」的确认。与 trustConfirm 文案与按钮全独立——
/// 预览不出境（只在网页显示、不保存到云端），说辞不能和上传混用。
function previewTrustConfirm(f) {
  return h("div", { class: "inline-confirm", style: "background:rgba(var(--accent-rgb),.07)" },
    h("div", {}, t("set.previewTrust.confirm", { folder: f.name })),
    h("div", { style: "font-size:11.5px;color:var(--text)" }, t("set.previewTrust.limits")),
    h("div", { class: "btns" },
      h("button", { type: "button", class: "btn sm", onclick: () => { previewTrustId = null; render(); } }, t("common.cancel")),
      h("button", { type: "button", class: "btn sm pri", onclick: () => { previewTrustId = null; act(() => invoke("ui_set_preview", { rootId: f.root_id, pref: "always" })); } }, t("folder.preview.always"))));
}

function foldersSection(o) {
  const p = o.policy;
  const multi = p.agents.length > 1;
  const sec = h("div", { class: "sect" },
    h("div", { class: "sh" }, h("span", {}, t("set.folders")),
      h("button", { type: "button", class: "add", onclick: () => act(() => invoke("ui_pick_folder", { grantTo: null })) }, t("set.addFolder"))));
  if (p.folders.length === 0) sec.append(h("div", { class: "p" }, t("set.noFolders")));
  for (const f of p.folders) {
    sec.append(folderCard({
      folder: f, agents: p.agents, showAgents: multi,
      onMode: (m) => act(() => invoke("ui_set_mode", { rootId: f.root_id, mode: m })),
      onAgent: (a, on) => act(() => invoke("ui_set_agent", { rootId: f.root_id, agent: a, allowed: on })),
      // 「一直允许」要先确认；回到「每次问」是收紧，直接生效。
      // 预览与上传各写各的字段、各用各的确认框，刻意不共用（ADR 决策 1）
      onPreview: (v) => { if (v === "always") { previewTrustId = f.root_id; render(); } else { previewTrustId = null; act(() => invoke("ui_set_preview", { rootId: f.root_id, pref: "ask" })); } },
      inlinePreviewTrust: previewTrustId === f.root_id ? previewTrustConfirm(f) : null,
      onUpload: (v) => { if (v === "always") { trustId = f.root_id; render(); } else { trustId = null; act(() => invoke("ui_set_upload", { rootId: f.root_id, pref: "ask" })); } },
      inlineTrust: trustId === f.root_id ? trustConfirm(f) : null,
      onRemove: () => { removeId = f.root_id; render(); },
      inlineRemove: removeId === f.root_id ? removeConfirm(f) : null,
    }));
  }
  return sec;
}

function moreSection(o) {
  const on = o.policy.web_confirm;
  return h("div", { class: "sect" },
    h("div", { class: "sh" }, h("span", {}, t("set.away"))),
    h("div", { class: "more" },
      h("div", { class: "row" },
        h("div", { class: "tx" }, t("set.away.webConfirm"), h("small", {}, t("set.away.webConfirm.d"))),
        h("button", { type: "button", class: "sw" + (on ? " on" : ""), role: "switch", "aria-checked": String(on),
          onclick: () => act(() => invoke("ui_set_web_confirm", { on: !on })) })),
      h("div", { class: "row" },
        h("div", { class: "tx" }, t("set.backup"), h("small", {}, t("set.backup.d", { size: o.backup_size }))),
        h("button", { type: "button", class: "add", onclick: () => act(() => invoke("ui_open_backup_dir")) }, t("set.backup.open")))));
}

/// 底部「高级」：默认折叠，只放少数人需要调的项（预览大小上限三档）。
/// 只有 50/100/200 三档，不提供自由输入——自由输入能设出服务端兜不住的值。
function advancedSection(o) {
  const cur = o.policy.preview_limit_mb;
  const sec = h("div", { class: "sect" },
    h("div", { class: "sh" },
      h("button", { type: "button", class: "add", onclick: () => { advOpen = !advOpen; render(); } },
        (advOpen ? "▾ " : "▸ ") + t("set.advanced"))));
  if (!advOpen) return sec;
  sec.append(h("div", { class: "more" },
    h("div", { class: "row" },
      h("div", { class: "tx" }, t("set.previewLimit"), h("small", {}, t("set.previewLimit.d"))),
      seg([[50, "50 MB"], [100, "100 MB"], [200, "200 MB"]], cur,
        (mb) => act(() => invoke("ui_set_preview_limit", { mb }))))));
  return sec;
}

function render() {
  if (!last) return;
  const kids = [statusRow(last)];
  if (last.auth_error && last.auth.state !== "signed_in") kids.push(h("div", { class: "err" }, t("set.loginFailed", { err: last.auth_error })));
  if (last.policy_error) kids.push(h("div", { class: "err" }, t("set.policyBroken")));
  kids.push(foldersSection(last), moreSection(last), advancedSection(last),
    h("div", { class: "relax" },
      svg('<rect x="5" y="11" width="14" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 8 0v4"/>', null, 12), t("set.relaxHint")));
  if (errMsg) kids.push(h("div", { class: "err" }, errMsg));
  root.replaceChildren(...kids);
}

async function act(fn) {
  errMsg = "";
  try { await fn(); } catch (e) { errMsg = t("set.saveFailed", { err: errText(e) }); }
  try { last = await invoke("ui_overview"); } catch (e) { errMsg = errText(e); }
  render();
}

document.addEventListener("DOMContentLoaded", () => {
  applyI18n();
  document.title = t("set.title");
  // render 只依赖 last/removeId/trustId/previewTrustId/advOpen，轮询重绘不会丢掉已展开的确认框
  pollOverview((o) => { last = o; const typing = nameEdit !== null && document.activeElement && document.activeElement.id === "name-inp"; const pos = typing ? document.activeElement.selectionStart : null; render(); if (typing) { const el = document.getElementById("name-inp"); if (el) { el.focus(); el.setSelectionRange(pos, pos); } } }, 3000);
});

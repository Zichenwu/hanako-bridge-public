// auth-request.js — 授权请求弹窗：网页「请求使用这台电脑」在本机确认。
// 置顶但不抢焦点；60 秒无响应 = 拒绝（倒计时只是展示，真正的超时在 Rust 侧 AUTH_REQUEST_TIMEOUT）；
// 一个文件夹都没勾时「允许」是禁用的（最后一道校验在 Rust 侧 apply_auth_grant）。
"use strict";

const root = document.getElementById("root");
const TOTAL_SEC = 60;
let data = null;            // {request, folders}
let picked = new Set();     // 勾选的 rootId
let startedAt = Date.now();
let errMsg = "";
let expired = false;
let submitting = false;

function remaining() { return Math.max(0, TOTAL_SEC - Math.floor((Date.now() - startedAt) / 1000)); }

function render() {
  if (!data) return;
  const req = data.request;
  const cross = req.origin === "web_cross";
  const left = remaining();
  const folders = data.folders;
  const kids = [
    h("div", { class: "who" },
      h("span", { class: "av" }),
      h("div", {},
        h("b", {}, t("auth.who", { team: teamOf(req.agent_id) })),
        h("div", { class: "src" + (cross ? " warn" : "") },
          svg('<rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8M12 17v4"/>', null, 12),
          h("span", {}, cross ? t("auth.srcCross") : t("auth.srcLocal"))))),
    h("div", { class: "p" }, t("auth.p")),
  ];
  // 目录列表独立滚动：目录多时「允许/拒绝」必须始终可见，否则用户只能等 60 秒超时
  const list = h("div", { class: "pick-list" });
  if (folders.length === 0) list.append(h("div", { class: "note" }, t("auth.noFolders")));
  for (const f of folders) {
    const on = picked.has(f.root_id);
    list.append(h("label", { class: "chk" },
      h("input", { type: "checkbox", checked: on, onchange: (e) => { e.target.checked ? picked.add(f.root_id) : picked.delete(f.root_id); render(); } }),
      h("span", { class: "nm-ell", title: f.path }, f.name),
      h("span", { class: "d" }, t(f.mode === "ro" ? "folder.mode.ro" : "folder.mode.rw"))));
  }
  kids.push(list);
  kids.push(h("button", { type: "button", class: "add", style: "align-self:flex-start", disabled: submitting,
    onclick: pickNew }, t("auth.addFolder")));
  kids.push(h("div", { class: "timer" }, h("i", { style: `width:${(left / TOTAL_SEC) * 100}%` })));
  if (errMsg) kids.push(h("div", { class: "err" }, errMsg));
  if (expired) kids.push(h("div", { class: "err" }, t("auth.expired")));
  kids.push(h("div", { class: "btns" },
    h("button", { type: "button", class: "btn", disabled: submitting || expired, onclick: () => submit(false) }, t("auth.reject")),
    h("button", { type: "button", class: "btn pri", disabled: submitting || expired || picked.size === 0, onclick: () => submit(true) }, t("auth.allow"))));
  kids.push(h("div", { class: "foot" }, h("span", {}, expired ? "" : t("auth.timeout", { sec: left }))));
  root.replaceChildren(...kids);
}

async function pickNew() {
  errMsg = "";
  try {
    const id = await invoke("ui_pick_folder", { grantTo: null });
    if (id) {
      // 新选的目录默认勾上（用户刚为这个请求选的），但是否"允许"仍要用户点
      const fresh = await invoke("get_pending_auth_request");
      if (fresh) { data = fresh; picked.add(id); }
    }
  } catch (e) { errMsg = t("auth.failed", { err: errText(e) }); }
  render();
}

async function submit(allow) {
  if (submitting) return;
  submitting = true; errMsg = ""; render();
  try {
    await invoke("respond_auth_request", { requestId: data.request.request_id, allow, picked: allow ? [...picked] : [] });
    await invoke("ui_close_window", { label: "auth-request" });
  } catch (e) {
    // 请求已超时被清理时，后端会报"不存在或已超时"：按拒绝展示，不让用户以为点成功了
    expired = /超时|不存在/.test(errText(e));
    errMsg = expired ? "" : t("auth.failed", { err: errText(e) });
    submitting = false;
    render();
  }
}

async function load() {
  try {
    data = await invoke("get_pending_auth_request");
    if (!data) { await invoke("ui_close_window", { label: "auth-request" }); return; }
    startedAt = Date.now();
    render();
  } catch (e) { errMsg = t("auth.failed", { err: errText(e) }); root.replaceChildren(h("div", { class: "err" }, errMsg)); }
}

document.addEventListener("DOMContentLoaded", () => {
  applyI18n();
  document.title = t("auth.title");
  load();
  setInterval(() => {
    if (!data || expired) return;
    if (remaining() === 0) { expired = true; invoke("ui_close_window", { label: "auth-request" }); return; }
    render();
  }, 1000);
});

// preview-ask.js — 本地文件预览确认弹窗（与上传弹窗同骨架，文案与通道独立）。
// 置顶不抢焦点；60 秒无响应 = 拒绝（倒计时只是展示，真正的超时在 Rust 侧 PREVIEW_ASK_TIMEOUT）。
// 只有「只看这一个 / 本对话该文件夹 / 拒绝」——没有永久：永久只能去设置里开。
// 承诺文案 data.notice（只在网页显示，不保存到云端）由 Rust 下发、测试锁住，这里原样展示不改写。
// 用户可见处只显示文件名与目录显示名，不显示任何绝对路径。
"use strict";

const root = document.getElementById("root");
const TOTAL_SEC = 60;
let data = null;
let scope = "once";
let startedAt = Date.now();
let errMsg = "";
let expired = false;
let submitting = false;

function remaining() { return Math.max(0, TOTAL_SEC - Math.floor((Date.now() - startedAt) / 1000)); }

function fmtSize(n) {
  if (n >= 1048576) return (n / 1048576).toFixed(1) + " MB";
  if (n >= 1024) return (n / 1024).toFixed(0) + " KB";
  return n + " B";
}

function render() {
  if (!data) return;
  const cross = data.origin === "other_device";
  const left = remaining();
  const kids = [
    h("div", { class: "flow" },
      h("div", { class: "end" }, h("small", {}, t("pv.from", { folder: data.folder_name })), h("div", { class: "nm", title: data.file_name }, data.file_name), h("small", {}, fmtSize(data.size)))),
    h("div", {},
      h("div", { class: "who" }, t("pv.reason")),
      h("div", { class: "src" }, data.notice),
      cross ? h("div", { class: "src warn" }, t("pv.srcCross")) : null),
    h("label", { class: "opt" + (scope === "once" ? " on" : "") },
      h("input", { type: "radio", name: "scope", checked: scope === "once", onchange: () => { scope = "once"; render(); } }),
      h("div", {}, t("pv.once"))),
    h("label", { class: "opt" + (scope === "session" ? " on" : "") },
      h("input", { type: "radio", name: "scope", checked: scope === "session", onchange: () => { scope = "session"; render(); } }),
      h("div", {}, h("span", {}, t("pv.session", { folder: data.folder_name })), h("small", {}, t("pv.session.d")))),
  ].filter(Boolean);
  if (errMsg) kids.push(h("div", { class: "err" }, errMsg));
  if (expired) kids.push(h("div", { class: "err" }, t("pv.expired")));
  kids.push(h("div", { class: "timer" }, h("i", { style: `width:${(left / TOTAL_SEC) * 100}%` })));
  kids.push(h("div", { class: "btns" },
    h("button", { type: "button", class: "btn", disabled: submitting || expired, onclick: () => submit("reject") }, t("pv.reject")),
    h("button", { type: "button", class: "btn pri", disabled: submitting || expired, onclick: () => submit(scope) }, t("pv.allow"))));
  kids.push(h("div", { class: "foot" }, h("span", {}, expired ? "" : t("pv.timeout", { sec: left })), h("span", {}, t("pv.alwaysHint", { folder: data.folder_name }))));
  root.replaceChildren(...kids);
}

async function submit(choice) {
  if (submitting) return;
  submitting = true; errMsg = ""; render();
  try {
    await invoke("respond_preview_ask", { askId: data.ask_id, choice });
    await invoke("ui_close_window", { label: "preview-ask" });
  } catch (e) {
    expired = /超时|不存在/.test(errText(e));
    errMsg = expired ? "" : t("pv.failed", { err: errText(e) });
    submitting = false;
    render();
  }
}

async function load() {
  try {
    data = await invoke("get_pending_preview_ask");
    if (!data) { await invoke("ui_close_window", { label: "preview-ask" }); return; }
    startedAt = Date.now();
    render();
  } catch (e) { root.replaceChildren(h("div", { class: "err" }, t("pv.failed", { err: errText(e) }))); }
}

document.addEventListener("DOMContentLoaded", () => {
  applyI18n();
  document.title = t("pv.title");
  load();
  setInterval(() => {
    if (!data || expired) return;
    if (remaining() === 0) { expired = true; invoke("ui_close_window", { label: "preview-ask" }); return; }
    render();
  }, 1000);
});

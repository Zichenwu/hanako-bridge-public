// upload-ask.js — 上传偏好弹窗（设计稿 f-upload.html：U3 流向图 + U2 单选范围）。
// 置顶不抢焦点；60 秒无响应 = 拒绝（倒计时只是展示，真正的超时在 Rust 侧 UPLOAD_ASK_TIMEOUT）。
// 只有「只传这一个 / 本对话该文件夹 / 拒绝」三种结果——**没有永久**：永久只能去设置里开（底部只给引导文案）。
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
  const team = teamOf(data.agent_id);
  const reason = data.purpose ? t("up.reason", { team, purpose: data.purpose }) : t("up.reasonNone", { team });
  const kids = [
    h("div", { class: "flow" },
      h("div", { class: "end" }, h("small", {}, t("up.from", { folder: data.folder_name })), h("div", { class: "nm", title: data.file_name }, data.file_name), h("small", {}, fmtSize(data.size))),
      h("div", { class: "arrow" }, svg('<path d="M1 7h24M20 2l5 5-5 5"/>', null, 20), t("up.arrow")),
      h("div", { class: "end" }, h("small", {}, t("up.to")), h("small", {}, t("up.visible")))),
    h("div", {},
      h("div", { class: "who" }, reason),
      cross ? h("div", { class: "src warn" }, t("up.srcCross")) : null),
    h("label", { class: "opt" + (scope === "once" ? " on" : "") },
      h("input", { type: "radio", name: "scope", checked: scope === "once", onchange: () => { scope = "once"; render(); } }),
      h("div", {}, t("up.once"))),
    h("label", { class: "opt" + (scope === "session" ? " on" : "") },
      h("input", { type: "radio", name: "scope", checked: scope === "session", onchange: () => { scope = "session"; render(); } }),
      h("div", {}, h("span", {}, t("up.session", { folder: data.folder_name })), h("small", {}, t("up.session.d")))),
    h("div", { class: "alt" }, t("up.rejectHint")),
  ].filter(Boolean);
  if (errMsg) kids.push(h("div", { class: "err" }, errMsg));
  if (expired) kids.push(h("div", { class: "err" }, t("up.expired")));
  kids.push(h("div", { class: "timer" }, h("i", { style: `width:${(left / TOTAL_SEC) * 100}%` })));
  kids.push(h("div", { class: "btns" },
    h("button", { type: "button", class: "btn", disabled: submitting || expired, onclick: () => submit("reject") }, t("up.reject")),
    h("button", { type: "button", class: "btn pri", disabled: submitting || expired, onclick: () => submit(scope) }, t("up.allow"))));
  kids.push(h("div", { class: "foot" }, h("span", {}, expired ? "" : t("up.timeout", { sec: left })), h("span", {}, t("up.alwaysHint", { folder: data.folder_name }))));
  root.replaceChildren(...kids);
}

async function submit(choice) {
  if (submitting) return;
  submitting = true; errMsg = ""; render();
  try {
    await invoke("respond_upload_ask", { askId: data.ask_id, choice });
    await invoke("ui_close_window", { label: "upload-ask" });
  } catch (e) {
    // 请求已超时被清理时，后端报"不存在或已超时"：按拒绝展示，不让用户以为点成功了
    expired = /超时|不存在/.test(errText(e));
    errMsg = expired ? "" : t("up.failed", { err: errText(e) });
    submitting = false;
    render();
  }
}

async function load() {
  try {
    data = await invoke("get_pending_upload_ask");
    if (!data) { await invoke("ui_close_window", { label: "upload-ask" }); return; }
    startedAt = Date.now();
    render();
  } catch (e) { root.replaceChildren(h("div", { class: "err" }, t("up.failed", { err: errText(e) }))); }
}

document.addEventListener("DOMContentLoaded", () => {
  applyI18n();
  document.title = t("up.title");
  load();
  setInterval(() => {
    if (!data || expired) return;
    if (remaining() === 0) { expired = true; invoke("ui_close_window", { label: "upload-ask" }); return; }
    render();
  }, 1000);
});

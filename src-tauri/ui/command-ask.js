// command-ask.js — 本机命令确认窗（ADR 0013）。
// 只能在这台电脑上点；网页不能代批。45 秒无响应 = 拒绝（倒计时只是展示，真正的超时在 Rust 侧 CommandBridge）。
// 选项：仅此一次 / 本会话内这条命令不再问 / 拒绝。命令原文与工作目录由 Rust 下发，这里原样展示不改写。
"use strict";

const root = document.getElementById("root");
const TOTAL_SEC = 45;
let data = null;
let scope = "once";
let startedAt = Date.now();
let errMsg = "";
let expired = false;
let submitting = false;

function remaining() { return Math.max(0, TOTAL_SEC - Math.floor((Date.now() - startedAt) / 1000)); }

function render() {
  if (!data) return;
  const left = remaining();
  const kids = [
    h("div", { class: "who" }, t("cmd.who", { agent: data.agent_id })),
    h("div", {}, h("small", {}, t("cmd.label")), h("div", { class: "cmd" }, data.command)),
    h("div", {}, h("small", {}, t("cmd.cwd")), h("div", { class: "cwd" }, data.cwd)),
    data.reason ? h("div", { class: "src" }, t("cmd.reason", { reason: data.reason })) : null,
    data.read_only_root ? h("div", { class: "ro" }, t("cmd.readOnly")) : null,
    h("div", { class: "src warn" }, t("cmd.outside")),
    h("label", { class: "opt" + (scope === "once" ? " on" : "") },
      h("input", { type: "radio", name: "scope", checked: scope === "once", onchange: () => { scope = "once"; render(); } }),
      h("div", {}, t("cmd.once"))),
    h("label", { class: "opt" + (scope === "session" ? " on" : "") },
      h("input", { type: "radio", name: "scope", checked: scope === "session", onchange: () => { scope = "session"; render(); } }),
      h("div", {}, h("span", {}, t("cmd.session")), h("small", {}, t("cmd.session.d")))),
  ].filter(Boolean);
  if (errMsg) kids.push(h("div", { class: "err" }, errMsg));
  if (expired) kids.push(h("div", { class: "err" }, t("cmd.expired")));
  kids.push(h("div", { class: "timer" }, h("i", { style: `width:${(left / TOTAL_SEC) * 100}%` })));
  kids.push(h("div", { class: "btns" },
    h("button", { type: "button", class: "btn", disabled: submitting || expired, onclick: () => submit("reject") }, t("cmd.reject")),
    h("button", { type: "button", class: "btn pri", disabled: submitting || expired, onclick: () => submit(scope) }, t("cmd.allow"))));
  kids.push(h("div", { class: "foot" }, h("span", {}, expired ? "" : t("cmd.timeout", { sec: left })), h("span", {}, t("cmd.localOnly"))));
  root.replaceChildren(...kids);
}

async function submit(choice) {
  if (submitting) return;
  submitting = true; errMsg = ""; render();
  try {
    await invoke("respond_command_ask", { taskId: data.task_id, choice });
    await invoke("ui_close_window", { label: "command-ask" });
  } catch (e) {
    expired = /超时|不存在/.test(errText(e));
    errMsg = expired ? "" : t("cmd.failed", { err: errText(e) });
    submitting = false;
    render();
  }
}

async function load() {
  try {
    data = await invoke("get_pending_command_ask");
    if (!data) { await invoke("ui_close_window", { label: "command-ask" }); return; }
    startedAt = Date.now();
    render();
  } catch (e) { root.replaceChildren(h("div", { class: "err" }, t("cmd.failed", { err: errText(e) }))); }
}

document.addEventListener("DOMContentLoaded", () => {
  applyI18n();
  document.title = t("cmd.title");
  load();
  setInterval(() => {
    if (!data || expired) return;
    if (remaining() === 0) { expired = true; invoke("ui_close_window", { label: "command-ask" }); return; }
    render();
  }, 1000);
});

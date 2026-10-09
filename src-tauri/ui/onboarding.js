// onboarding.js — 首次引导（G2）：登录 → 选文件夹（卡内勾助手）→ 完成。
// 状态来自后端（ui_overview 轮询），页面只持有「当前步骤」与「本次选中的目录」。
"use strict";

const root = document.getElementById("root");
let step = null;            // 1 | 2 | 3；null = 首次渲染前，由状态决定起点
let last = null;            // 最近一次 ui_overview
let pickedId = null;        // 本次引导选中的目录 rootId
let busy = false;
let errMsg = "";
let loginRequested = false; // 用户点过"用浏览器登录"

const signedIn = (o) => o.auth.state === "signed_in";

function renderSteps(cur) {
  return h("div", { class: "steps" },
    h("span", { class: cur === 1 ? "on" : "done" }, t("onb.step.login")),
    h("span", { class: cur === 2 ? "on" : (cur > 2 ? "done" : "") }, t("onb.step.folder")));
}

function stepLogin(o) {
  const a = o.auth;
  const wrap = [renderSteps(1), h("div", { class: "p", "data-tagline": "" }, t("onb.tagline"))];
  if (a.state === "awaiting") {
    wrap.push(
      h("div", { class: "h1" }, t("onb.login.h")),
      h("div", { class: "p" }, t("onb.login.p")),
      h("div", { class: "mono", style: "font-size:22px;letter-spacing:.18em;text-align:center;padding:10px;border:1px dashed var(--border);border-radius:10px;background:var(--bg)" }, a.user_code),
      h("div", { class: "foot" },
        h("span", {}, t("onb.login.wait", { n: 10 })),
        h("button", { type: "button", class: "add", onclick: () => invoke("ui_open_url", { url: a.verification_url }).catch(() => {}) }, t("onb.login.reopen"))));
  } else {
    wrap.push(
      h("div", { class: "h1" }, t("onb.login.start.h")),
      h("div", { class: "p" }, t("onb.login.start.p")),
      (loginRequested && !busy) && h("div", { class: "err" }, o.auth_error ? t("set.loginFailed", { err: o.auth_error }) : t("onb.login.failed")));
  }
  wrap.push(h("div", { class: "sp" }),
    h("div", { class: "btns" },
      h("button", { type: "button", class: "btn", onclick: () => invoke("ui_close_window", { label: "onboarding" }) }, t("onb.later")),
      a.state !== "awaiting" && h("button", { type: "button", class: "btn pri", onclick: startLogin }, t("onb.login.start"))));
  return wrap;
}

async function startLogin() {
  loginRequested = false;
  errMsg = "";
  try { await invoke("auth_login", { agentId: null }); loginRequested = true; } catch (e) { errMsg = errText(e); }
  await refresh();
}

function currentFolder(o) {
  return o.policy.folders.find((f) => f.root_id === pickedId) || null;
}

function stepFolder(o) {
  const f = currentFolder(o);
  const multi = o.policy.agents.length > 1;
  const body = [renderSteps(2),
    h("div", { class: "h1" }, t("onb.folder.h")),
    h("div", { class: "p" }, t("onb.folder.p"))];
  if (!f) {
    body.push(h("div", { class: "pick" },
      svg('<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><path d="M12 11v5M9.5 13.5h5"/>', "big"),
      h("div", { style: "flex:1;font-size:12.5px;color:var(--text-light)" }, t("onb.folder.empty")),
      h("button", { type: "button", class: "btn pri", disabled: busy, onclick: pickFolder }, t("onb.folder.pick"))));
  } else {
    body.push(folderCard({
      folder: f, agents: o.policy.agents, showAgents: multi,
      onChange: pickFolder,
      onMode: (m) => act(() => invoke("ui_set_mode", { rootId: f.root_id, mode: m })),
      onAgent: (a, on) => act(() => invoke("ui_set_agent", { rootId: f.root_id, agent: a, allowed: on })),
    }));
    if (multi) {
      const who = o.connection.agent_id || o.auth.agent_id;
      body.push(h("div", { class: "foot" }, h("span", {}, t("onb.folder.defaultAgent", { team: teamOf(who) }))));
    }
    body.push(h("div", { class: "note" }, h("b", {}, t("onb.disclosure.lead")), t("onb.disclosure")));
  }
  if (errMsg) body.push(h("div", { class: "err" }, errMsg));
  body.push(h("div", { class: "sp" }),
    h("div", { class: "btns" },
      h("button", { type: "button", class: "btn l", onclick: () => { step = 1; render(); } }, t("onb.back")),
      h("button", { type: "button", class: "btn pri", disabled: !f || busy, onclick: () => { step = 3; render(); } }, t("onb.finish"))));
  return body;
}

function stepDone(o) {
  const f = currentFolder(o);
  return [
    h("div", { class: "ok-ico" }, svg('<path d="M5 12l5 5 9-10"/>', null, 20)),
    h("div", { class: "h1" }, t("onb.done.h")),
    h("div", { class: "p" }, t("onb.done.p", { node: o.machine, folder: f ? f.name : "" })),
    h("div", { class: "note" }, t("onb.done.note")),
    errMsg && h("div", { class: "err" }, errMsg),
    h("div", { class: "sp" }),
    h("div", { class: "btns" },
      h("button", { type: "button", class: "btn", onclick: () => invoke("ui_close_window", { label: "onboarding" }) }, t("onb.close")),
      h("button", { type: "button", class: "btn pri", onclick: openWeb }, t("onb.openWeb")))];
}

async function openWeb() {
  try { await invoke("ui_open_web"); } catch (e) { errMsg = errText(e); render(); }
}

async function pickFolder() {
  if (busy) return;
  busy = true; errMsg = ""; render();
  try {
    const grantTo = (last && (last.connection.agent_id || last.auth.agent_id)) || null;
    const id = await invoke("ui_pick_folder", { grantTo });
    if (id) pickedId = id;
  } catch (e) { errMsg = errText(e); }
  busy = false;
  await refresh();
}

async function act(fn) {
  errMsg = "";
  try { await fn(); } catch (e) { errMsg = t("set.saveFailed", { err: errText(e) }); }
  await refresh();
}

function render() {
  if (!last) return;
  if (step == null) step = signedIn(last) || last.connection.connected ? 2 : 1;
  // 登录在第 1 步进行中完成 → 自动进入第 2 步
  if (step === 1 && signedIn(last)) step = 2;
  const kids = step === 1 ? stepLogin(last) : step === 2 ? stepFolder(last) : stepDone(last);
  root.replaceChildren(...kids.filter(Boolean));
}

async function refresh() {
  try { last = await invoke("ui_overview"); } catch (e) { errMsg = errText(e); }
  render();
}

document.addEventListener("DOMContentLoaded", () => {
  applyI18n();
  document.title = t("onb.title");
  pollOverview((o) => { last = o; render(); }, 2000);
});

// ui-common.js — 三个原生窗口共用的小工具（无框架、无远程脚本、无 iframe）。
"use strict";

const { invoke } = window.__TAURI__.core;

/** 创建元素：h("div", {class:"x", onclick:fn}, child1, "text")。文本一律走 textContent，杜绝 XSS。 */
function h(tag, attrs, ...kids) {
  const el = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs || {})) {
    if (v == null || v === false) continue;
    if (k === "class") el.className = v;
    else if (k.startsWith("on") && typeof v === "function") el.addEventListener(k.slice(2), v);
    else if (k === "html") throw new Error("不允许 innerHTML");
    else el.setAttribute(k, v === true ? "" : v);
  }
  for (const kid of kids.flat()) {
    if (kid == null || kid === false) continue;
    el.append(kid.nodeType ? kid : document.createTextNode(String(kid)));
  }
  return el;
}

const FOLDER_ICON = '<path d="M3 7a2 2 0 0 1 2-2h4l2 2h8a2 2 0 0 1 2 2v8a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/>';

/** SVG 图标（内容是本文件内的常量，不含用户数据）。 */
function svg(inner, cls, size) {
  const s = document.createElementNS("http://www.w3.org/2000/svg", "svg");
  s.setAttribute("viewBox", "0 0 24 24");
  s.setAttribute("fill", "none");
  s.setAttribute("stroke", "currentColor");
  s.setAttribute("stroke-width", "1.6");
  if (cls) s.setAttribute("class", cls);
  if (size) { s.setAttribute("width", size); s.setAttribute("height", size); }
  s.innerHTML = inner; // 仅常量
  return s;
}

/** 分段按钮：opts=[[value,label],...]。 */
function seg(opts, current, onPick) {
  return h("span", { class: "seg" }, opts.map(([v, label]) =>
    h("button", { type: "button", class: v === current ? "on" : "", onclick: () => onPick(v) }, label)));
}

/** 助手勾选 chip：Team 标签即名字。 */
function agentChip(agentId, on, onToggle) {
  return h("span", { class: "ag" + (on ? " on" : ""), role: "checkbox", "aria-checked": String(on), tabindex: "0",
    onclick: onToggle, onkeydown: (e) => { if (e.key === " " || e.key === "Enter") { e.preventDefault(); onToggle(); } } },
    h("span", { class: "ck" }), teamOf(agentId));
}

/** 用户主目录前缀缩写成 ~（只影响显示，不影响 title 里的真实路径）。 */
function shortPath(p) {
  return String(p || "").replace(/^\/home\/[^/]+|^\/Users\/[^/]+|^[A-Za-z]:\\Users\\[^\\]+/, "~");
}

/**
 * 目录卡：引导与设置窗共用（"学一次，到处认得"）。
 * opts: {folder, agents(候选), showAgents, onMode, onAgent(agent,bool), onPreview, onUpload, onRemove, onChange, inlinePreviewTrust, inlineTrust, inlineRemove}
 *
 * 「允许在网页预览」与「允许助手把原文件传到云端」是**并列的两行**、各写各的字段
 * （本地文件预览 ADR 决策 1）：用户为方便预览而放开一个，不得带动另一个。
 */
function folderCard(opts) {
  const f = opts.folder;
  const card = h("div", { class: "fcard" },
    h("div", { class: "hd" },
      svg(FOLDER_ICON, "ico"),
      h("div", { class: "sub" }, h("span", { class: "nm", title: f.name }, f.name), h("span", { class: "path", title: f.path }, shortPath(f.path))),
      opts.onChange && h("button", { type: "button", class: "add", onclick: opts.onChange }, t("onb.folder.change"))),
    h("div", { class: "rw" }, h("span", { class: "k" }, t("folder.mode")),
      h("span", { class: "v" }, seg([["ro", t("folder.mode.ro")], ["rw", t("folder.mode.rw")]], f.mode, opts.onMode))));
  if (opts.showAgents) {
    const none = f.agents.length === 0;
    card.append(h("div", { class: "rw" }, h("span", { class: "k" }, t("folder.agents")),
      h("span", { class: "v" },
        opts.agents.map((a) => agentChip(a, f.agents.includes(a), () => opts.onAgent(a, !f.agents.includes(a)))),
        none && h("span", { style: "font-size:11.5px;color:var(--text-light)" }, t("folder.agents.none")))));
  }
  // 预览在上传之前：预览是「只在网页看」的轻动作，上传是「字节进云端」的重动作，
  // 从轻到重排列，避免用户顺手点到更重的那个
  if (opts.onPreview) {
    card.append(h("div", { class: "rw" }, h("span", { class: "k" }, t("folder.preview")),
      h("span", { class: "v" }, seg([["ask", t("folder.preview.ask")], ["always", t("folder.preview.always")]], f.preview, opts.onPreview))));
  }
  if (opts.inlinePreviewTrust) card.append(opts.inlinePreviewTrust);
  if (opts.onUpload) {
    card.append(h("div", { class: "rw" }, h("span", { class: "k" }, t("folder.upload")),
      h("span", { class: "v" }, seg([["ask", t("folder.upload.ask")], ["always", t("folder.upload.always")]], f.upload, opts.onUpload))));
  }
  if (opts.inlineTrust) card.append(opts.inlineTrust);
  if (opts.onRemove) {
    card.append(h("div", { class: "ft" }, h("button", { type: "button", class: "rm", onclick: opts.onRemove }, t("folder.remove"))));
  }
  if (opts.inlineRemove) card.append(opts.inlineRemove);
  return card;
}

/** 轮询概览；页面卸载时停止。 */
function pollOverview(cb, ms) {
  let stopped = false;
  const tick = async () => {
    if (stopped) return;
    try { cb(await invoke("ui_overview")); } catch (e) { console.warn("[ui] ui_overview 失败:", e); }
  };
  tick();
  const id = setInterval(tick, ms || 3000);
  window.addEventListener("unload", () => { stopped = true; clearInterval(id); });
}

/** 从 Tauri 错误里取人话。 */
function errText(e) { return typeof e === "string" ? e : (e && e.message) || String(e); }

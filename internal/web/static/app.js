// Guardian for RouterOS UI – vanilla JS, no build step, no external resources.
// Texts live in i18n.js (window.GUARDIAN_I18N), the theme is applied early by theme.js.
"use strict";

(() => {
  const REFRESH_MS = 15000;
  const ONLINE_MS = 5 * 60 * 1000;
  const NEW_MS = 24 * 3600 * 1000;
  const REPO_URL = "https://github.com/Marteva/routeros-guardian";
  const LANGS = ["en", "cs", "de", "pl", "ru", "es", "pt"];
  const LANG_NAMES = { en: "English", cs: "Čeština", de: "Deutsch", pl: "Polski", ru: "Русский", es: "Español", pt: "Português" };
  // model.Kinds (server); labels are kind.<k> in the catalog
  const KINDS = ["phone", "tablet", "computer", "tv", "camera", "iot", "speaker", "console", "printer", "nas", "network", "unknown"];
  const DETECTORS = ["new_device", "new_country", "new_asn", "upload_spike", "dest_fanout"];
  const SEVERITIES = ["info", "warning", "critical"];
  const SENSITIVITIES = ["low", "normal", "high"];
  const CATALOG = window.GUARDIAN_I18N || {};

  /** localStorage that never throws (private mode, disabled storage) */
  const storage = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) {
      try { if (v == null) localStorage.removeItem(k); else localStorage.setItem(k, v); } catch { /* unavailable */ }
    },
  };

  const state = {
    status: null,
    devices: [],
    alerts: [],
    alertFilter: "open",
    alertsShown: 30,
    deviceQuery: "",
    detailMac: null,
    detailData: null,
    detailDirty: false,
    busy: new Set(),
    sort: loadSort(),
    expanded: new Set(), // groupKey of expanded multi-MAC rows (when expandAll is off)
    expandAll: storage.get("guardian.expandAll") === "1", // all groups open by default
    collapsed: new Set(), // groupKey of rows closed by hand while expandAll is on
    merge: false, // merge (select) mode
    selected: new Set(), // rowKey of selected rows in merge mode
    settings: null, // last GET/PUT /api/settings
    draft: null, // settings form values
    settingsErr: null,
  };

  // ------------------------------------------------------------------ i18n
  let lang = "en";
  let fmt = null;

  function storedLang() {
    const v = storage.get("guardian.lang");
    return LANGS.includes(v) ? v : null;
  }
  function browserLang() {
    for (const l of navigator.languages || [navigator.language || ""]) {
      const base = String(l).toLowerCase().split("-")[0];
      if (LANGS.includes(base)) return base;
    }
    return null;
  }

  function setLang(l) {
    lang = LANGS.includes(l) ? l : "en";
    document.documentElement.lang = lang;
    // keep the browser's region for formatting when it matches the language (en-GB, pt-BR…)
    const loc = (navigator.languages || []).find((x) => String(x).toLowerCase().split("-")[0] === lang) || lang;
    fmt = {
      plural: new Intl.PluralRules(loc),
      num: new Intl.NumberFormat(loc, { maximumFractionDigits: 2 }),
      n0: new Intl.NumberFormat(loc, { maximumFractionDigits: 0 }),
      n1: new Intl.NumberFormat(loc, { maximumFractionDigits: 1 }),
      pct: new Intl.NumberFormat(loc, { style: "percent", maximumFractionDigits: 0 }),
      dt: new Intl.DateTimeFormat(loc, { day: "numeric", month: "numeric", hour: "2-digit", minute: "2-digit" }),
      d: new Intl.DateTimeFormat(loc, { day: "numeric", month: "numeric", year: "numeric" }),
      day: new Intl.DateTimeFormat(loc, { weekday: "short", day: "numeric", month: "numeric" }),
      rel: new Intl.RelativeTimeFormat(loc, { style: "short", numeric: "always" }),
      coll: new Intl.Collator(loc, { sensitivity: "base", numeric: true }),
    };
  }

  function message(key) {
    const c = CATALOG[lang] || {};
    if (Object.prototype.hasOwnProperty.call(c, key)) return c[key];
    const en = CATALOG.en || {};
    return Object.prototype.hasOwnProperty.call(en, key) ? en[key] : key;
  }

  /** t(key, {n: 3, name: "x"}) – plural entries are objects selected by params.n */
  function t(key, p) {
    let m = message(key);
    if (m && typeof m === "object") {
      const n = p && typeof p.n === "number" ? p.n : 0;
      m = m[fmt.plural.select(n)] ?? m.other;
    }
    return String(m).replace(/\{(\w+)\}/g, (all, k) => {
      if (!p || p[k] == null || p[k] instanceof Node) return all;
      return typeof p[k] === "number" ? fmt.num.format(p[k]) : String(p[k]);
    });
  }

  /** like t, but DOM nodes in params are inserted as nodes (e.g. <b>) */
  function tn(key, p) {
    const m = t(key, p);
    const out = [];
    let last = 0;
    m.replace(/\{(\w+)\}/g, (all, k, off) => {
      out.push(m.slice(last, off), p && p[k] instanceof Node ? p[k] : all);
      last = off + all.length;
      return all;
    });
    out.push(m.slice(last));
    return out.filter((x) => x !== "");
  }

  const quote = (s) => t("fmt.quoted", { s });

  function applyStatic() {
    document.querySelectorAll("[data-i18n]").forEach((el) => { el.textContent = t(el.dataset.i18n); });
    document.querySelectorAll("[data-i18n-attr]").forEach((el) => {
      for (const pair of el.dataset.i18nAttr.split(";")) {
        const [attr, key] = pair.split(":");
        if (attr && key) el.setAttribute(attr.trim(), t(key.trim()));
      }
    });
    const sel = $("#lang-select");
    if (sel) sel.value = lang;
    renderThemeBtn();
    renderMergeToggle();
  }

  function switchLang(l) {
    storage.set("guardian.lang", l);
    setLang(l);
    rerenderAll();
  }

  function rerenderAll() {
    applyStatic();
    renderStatus();
    renderAlerts();
    renderDevices();
    if ($("#detail").open && state.detailData && !state.detailDirty) renderDetail(state.detailData);
    if ($("#settings").open) renderSettings();
  }

  // ------------------------------------------------------------------ theme
  const THEME_ICON = { auto: "◐", light: "☀", dark: "☾" };
  const THEME_NEXT = { auto: "light", light: "dark", dark: "auto" };
  let theme = (() => {
    const v = document.documentElement.getAttribute("data-theme");
    return v === "light" || v === "dark" ? v : "auto";
  })();

  function setTheme(v) {
    theme = v;
    if (v === "auto") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", v);
    storage.set("guardian.theme", v === "auto" ? null : v);
    renderThemeBtn();
  }
  function renderThemeBtn() {
    const b = $("#theme-btn");
    if (!b) return;
    const label = t("theme.label", { mode: t("theme." + theme) });
    b.textContent = THEME_ICON[theme];
    b.title = label + " – " + t("theme.change");
    b.setAttribute("aria-label", label);
  }

  // ------------------------------------------------------------------ sorting
  // (loadSort runs during state init, so it must not use the consts below)
  function loadSort() {
    try {
      const v = JSON.parse(localStorage.getItem("guardian.sort") || "null");
      if (v && ["name", "vendor", "ip", "mac", "tx", "rx", "status"].includes(v.key) && (v.dir === "asc" || v.dir === "desc")) return v;
    } catch { /* storage unavailable */ }
    return { key: "name", dir: "asc" };
  }
  const SORT_KEYS = ["name", "vendor", "ip", "mac", "tx", "rx", "status"];
  // natural first direction per column: bytes biggest first, the rest ascending
  const SORT_FIRST_DIR = { tx: "desc", rx: "desc" };

  function saveSort() {
    storage.set("guardian.sort", JSON.stringify(state.sort));
  }
  function setSort(key, dir) {
    if (!SORT_KEYS.includes(key)) return;
    if (!dir) dir = state.sort.key === key ? (state.sort.dir === "asc" ? "desc" : "asc") : (SORT_FIRST_DIR[key] || "asc");
    state.sort = { key, dir };
    saveSort();
    renderDevices();
  }

  /** IPv4 "192.168.1.10" -> sortable number; non-IPv4 -> NaN */
  function ipNum(ip) {
    const p = (ip || "").split(".");
    if (p.length !== 4) return NaN;
    let n = 0;
    for (const x of p) {
      if (!/^\d{1,3}$/.test(x) || Number(x) > 255) return NaN;
      n = n * 256 + Number(x);
    }
    return n;
  }

  const cmpStr = (a, b) => fmt.coll.compare(a || "", b || "");

  function statusRank(d) {
    if (d.quarantined) return 0;
    if (d.partiallyQuarantined) return 1;
    if (d.openAlerts > 0) return 2;
    if (Date.now() - ts(d.lastSeen) < ONLINE_MS) return 3;
    return 4;
  }

  /** Compare rows by column; empty vendor/IP always go last, ties fall back to name + MAC. */
  function compareDevices(a, b, key, dir) {
    const sign = dir === "desc" ? -1 : 1;
    let r = 0;
    switch (key) {
      case "vendor":
        if (!a.vendor !== !b.vendor) return a.vendor ? -1 : 1;
        r = cmpStr(a.vendor, b.vendor);
        break;
      case "ip": {
        const x = ipNum(a.ip), y = ipNum(b.ip);
        if (Number.isNaN(x) !== Number.isNaN(y)) return Number.isNaN(x) ? 1 : -1;
        r = Number.isNaN(x) ? cmpStr(a.ip, b.ip) : x - y;
        break;
      }
      case "mac": r = cmpStr(a.mac, b.mac); break;
      case "tx": r = (a.tx24h || 0) - (b.tx24h || 0); break;
      case "rx": r = (a.rx24h || 0) - (b.rx24h || 0); break;
      case "status":
        r = statusRank(a) - statusRank(b);
        if (!r) r = ts(b.lastSeen) - ts(a.lastSeen); // more recent first
        break;
      default: break; // name
    }
    if (r) return sign * Math.sign(r);
    r = cmpStr(a.name, b.name) || cmpStr(a.mac, b.mac);
    return key === "name" ? sign * r : r;
  }

  function renderSortUI() {
    const { key, dir } = state.sort;
    document.querySelectorAll("table.devices th[data-sort]").forEach((th) => {
      const on = th.dataset.sort === key;
      th.setAttribute("aria-sort", on ? (dir === "asc" ? "ascending" : "descending") : "none");
      th.querySelector(".arrow").textContent = on ? (dir === "asc" ? "▲" : "▼") : "";
    });
    $("#sort-select").value = key;
    const btn = $("#sort-dir");
    btn.textContent = dir === "asc" ? "▲" : "▼";
    btn.title = dir === "asc" ? t("dev.sortAsc") : t("dev.sortDesc");
  }

  const isGroup = (d) => Array.isArray(d.members) && d.members.length > 1;
  /** stable key of a multi-MAC group (survives a change of the primary MAC) */
  const groupKey = (d) => (d.group === "manual" ? "m:" + d.groupId : "h:" + (d.hostname || d.mac).trim().toLowerCase());
  /** key of a row in the device list (selection in merge mode) */
  const rowKey = (d) => (isGroup(d) ? groupKey(d) : "d:" + d.mac);
  const rowMacs = (d) => (isGroup(d) ? d.members.map((m) => m.mac) : [d.mac]);

  // ------------------------------------------------------------------ utils
  const $ = (sel) => document.querySelector(sel);

  /** h("div", {class: "x", onclick: fn}, "text", child) – safe DOM builder */
  function h(tag, attrs, ...children) {
    const el = document.createElement(tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null || v === false) continue;
      if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else if (k === "class") el.className = v;
      else if (k === "text") el.textContent = v;
      else el.setAttribute(k, v === true ? "" : String(v));
    }
    append(el, children);
    return el;
  }
  function append(el, children) {
    for (const c of children.flat()) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }
  const SVGNS = "http://www.w3.org/2000/svg";
  function s(tag, attrs, ...children) {
    const el = document.createElementNS(SVGNS, tag);
    for (const [k, v] of Object.entries(attrs || {})) {
      if (v == null) continue;
      if (k.startsWith("on")) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, String(v));
    }
    for (const c of children.flat()) {
      if (c == null) continue;
      el.append(c instanceof Node ? c : document.createTextNode(String(c)));
    }
    return el;
  }

  const UNITS = ["B", "kB", "MB", "GB", "TB", "PB"];

  /** localized byte formatting: 1,2 GB / 1.2 GB */
  function fmtBytes(n) {
    n = Number(n) || 0;
    if (n < 1000) return fmt.n0.format(n) + " B";
    let i = 0;
    while (n >= 1000 && i < UNITS.length - 1) { n /= 1000; i++; }
    return (n >= 100 ? fmt.n0 : fmt.n1).format(n) + " " + UNITS[i];
  }

  const isZero = (x) => !x || x.startsWith("0001-01-01");
  const ts = (x) => (isZero(x) ? 0 : Date.parse(x));

  function ago(x) {
    if (!ts(x)) return t("time.never");
    const sec = Math.max(0, Math.round((Date.now() - ts(x)) / 1000));
    if (sec < 60) return fmt.rel.format(-sec, "second");
    const min = Math.round(sec / 60);
    if (min < 60) return fmt.rel.format(-min, "minute");
    const hr = Math.round(min / 60);
    if (hr < 48) return fmt.rel.format(-hr, "hour");
    return fmt.rel.format(-Math.round(hr / 24), "day");
  }

  const fmtTime = (x) => (ts(x) ? fmt.dt.format(new Date(ts(x))) : "–");
  const fmtDate = (x) => (ts(x) ? fmt.d.format(new Date(ts(x))) : "–");

  function remaining(untilMs) {
    const ms = untilMs - Date.now();
    const hours = Math.max(1, Math.ceil(ms / 3600000));
    if (hours <= 24) return t("unit.hours", { n: hours });
    return t("unit.days", { n: Math.ceil(ms / 86400000) });
  }

  const KIND_ICON = {
    phone: "📱", tablet: "📱", computer: "💻", laptop: "💻", desktop: "🖥️", tv: "📺",
    camera: "📷", iot: "💡", printer: "🖨️", console: "🎮", speaker: "🔊", watch: "⌚",
    router: "📡", network: "📡", nas: "🗄️", server: "🗄️", car: "🚗", appliance: "🔌",
  };
  const kindIcon = (k) => KIND_ICON[k] || "❔";
  const kindLabel = (k) => {
    if (!k) return t("kind.unknown");
    const v = t("kind." + k);
    return v === "kind." + k ? k : v;
  };
  const sevLabel = (sv) => (SEVERITIES.includes(sv) ? t("sev." + sv) : sv);
  const alertKind = (k) => {
    const v = t("alert." + k);
    return v === "alert." + k ? k : v;
  };

  function flag(cc) {
    if (!cc || cc.length !== 2) return "🌐";
    const A = 0x1f1e6;
    const u = cc.toUpperCase();
    return String.fromCodePoint(A + u.charCodeAt(0) - 65, A + u.charCodeAt(1) - 65);
  }

  let toastTimer;
  function toast(msg, isErr) {
    const el = $("#toast");
    el.textContent = msg;
    el.classList.toggle("err", !!isErr);
    el.classList.remove("hidden");
    clearTimeout(toastTimer);
    toastTimer = setTimeout(() => el.classList.add("hidden"), isErr ? 6000 : 3000);
  }

  // ------------------------------------------------------------------ API
  async function api(method, path, body) {
    const opt = { method, headers: { Accept: "application/json" }, cache: "no-store" };
    if (method !== "GET") {
      opt.headers["X-Guardian"] = "1";
      if (body !== undefined) {
        opt.headers["Content-Type"] = "application/json";
        opt.body = JSON.stringify(body);
      }
    }
    const res = await fetch("api/" + path, opt);
    let data = null;
    try { data = await res.json(); } catch { /* empty */ }
    if (!res.ok) {
      const err = new Error((data && data.error) || `HTTP ${res.status}`);
      err.status = res.status;
      throw err;
    }
    return data;
  }

  // ------------------------------------------------------------------ status bar
  function renderFoot() {
    const st = state.status;
    const parts = ["Guardian for RouterOS"];
    if (st && st.version) parts.push(" ", st.version);
    if (st && ts(st.startedAt)) parts.push(" · ", t("foot.running", { time: fmtTime(st.startedAt) }));
    parts.push(" · ", h("a", { href: REPO_URL, target: "_blank", rel: "noopener noreferrer" }, t("foot.source")));
    $("#foot").replaceChildren(...parts);
  }

  function renderStatus() {
    renderFoot();
    const st = state.status;
    const box = $("#status");
    if (!st) return;
    box.replaceChildren();
    if (st.learning) {
      box.append(h("span", { class: "chip learn", title: t("st.learning.title") },
        ...tn("st.learning", { left: h("b", {}, remaining(ts(st.learningUntil))) })));
    }
    const pollAge = Date.now() - ts(st.lastPoll);
    const stale = !ts(st.lastPoll) || pollAge > 2 * 60 * 1000;
    box.append(h("span", { class: "chip" + (st.lastError ? " bad" : stale ? " warn" : ""), title: st.lastError || t("st.pollTime", { ms: st.lastPollMs }) },
      st.lastError ? t("st.pollError") : "⟳", " ", ago(st.lastPoll)));
    box.append(h("span", { class: "chip" + (st.routerCpu >= 80 ? " warn" : ""), title: t("st.cpu.title") },
      "CPU ", h("b", {}, fmt.pct.format((st.routerCpu || 0) / 100))));
    const ft = st.connCount ? st.fasttrackCount / st.connCount : 0;
    box.append(h("span", { class: "chip", title: t("st.conns.title", { n: st.connCount, ft: st.fasttrackCount }) },
      ...tn("st.conns", { n: h("b", {}, fmt.n0.format(st.connCount)), ft: fmt.pct.format(ft) })));
    box.append(h("span", { class: "chip hide-s" }, ...tn("st.devices", { n: h("b", {}, fmt.n0.format(st.deviceCount)) })));

    const banner = $("#error-banner");
    if (st.lastError) {
      banner.textContent = t("st.pollFailed", { err: st.lastError });
      banner.classList.remove("hidden");
    } else banner.classList.add("hidden");
  }

  // ------------------------------------------------------------------ alerts
  /** row (single device or group) containing mac */
  function rowByMac(mac) {
    return state.devices.find((d) => d.mac === mac || (d.members || []).some((m) => m.mac === mac));
  }

  function alertItem(a, opts = {}) {
    const name = a.deviceName || (rowByMac(a.mac) || {}).name || a.mac;
    const li = h("li", { class: `alert ${a.severity}${a.acked ? " acked" : ""}` });
    const body = h("div", {},
      h("div", { class: "alert-meta" },
        h("span", { class: `sev ${a.severity}` }, sevLabel(a.severity)),
        h("span", {}, alertKind(a.kind)),
        h("span", { title: fmtTime(a.time) }, ago(a.time)),
        a.mac && !opts.noDevice ? h("button", { class: "link", type: "button", onclick: () => openDetail(a.mac) }, name) : null),
      h("div", { class: "alert-title" }, a.title || alertKind(a.kind)),
      a.detail ? h("div", { class: "alert-detail" }, a.detail) : null);
    const act = h("div", {});
    if (!a.acked) {
      act.append(h("button", {
        class: "btn small", type: "button",
        onclick: async (e) => {
          e.target.disabled = true;
          try {
            await api("POST", `alerts/${a.id}/ack`);
            a.acked = true;
            toast(t("alerts.ackDone"));
            await refresh();
          } catch (err) { toast(err.message, true); e.target.disabled = false; }
        },
      }, t("alerts.ack")));
    } else act.append(h("span", { class: "muted", title: t("alerts.acked") }, "✓"));
    li.append(body, act); // first grid column is the colour stripe (::before)
    return li;
  }

  function renderAlerts() {
    const list = $("#alerts");
    const shown = state.alerts.slice(0, state.alertsShown);
    list.replaceChildren(...shown.map((a) => alertItem(a)));
    const open = state.alerts.filter((a) => !a.acked).length;
    $("#alerts-count").textContent = fmt.n0.format(state.alertFilter === "open" ? open : state.alerts.length);
    const empty = $("#alerts-empty");
    empty.textContent = state.alertFilter === "open" ? t("alerts.emptyOpen") : t("alerts.empty");
    empty.classList.toggle("hidden", state.alerts.length > 0);
    if (state.alerts.length > state.alertsShown) {
      list.append(h("li", { class: "more" }, h("button", {
        class: "btn small", type: "button",
        onclick: () => { state.alertsShown += 50; renderAlerts(); },
      }, t("alerts.more", { n: state.alerts.length - state.alertsShown }))));
    }
  }

  // ------------------------------------------------------------------ devices
  function statusBadges(d) {
    const out = [];
    const now = Date.now();
    if (d.quarantined) out.push(h("span", { class: "badge quar" }, t("dev.quar")));
    else if (d.partiallyQuarantined) {
      const n = (d.members || []).filter((m) => m.quarantined).length;
      out.push(h("span", { class: "badge quar part", title: t("dev.quarPart.title") }, t("dev.quarPart", { q: n, total: d.members.length })));
    }
    if (now - ts(d.lastSeen) < ONLINE_MS) out.push(h("span", { class: "badge online" }, t("dev.online")));
    else out.push(h("span", { class: "badge", title: fmtTime(d.lastSeen) }, t("dev.offline", { ago: ago(d.lastSeen) })));
    if (now - ts(d.firstSeen) < NEW_MS) out.push(h("span", { class: "badge new" }, t("dev.new")));
    if (d.openAlerts > 0) out.push(h("span", { class: "badge alerts", title: t("dev.openAlerts") }, `⚠ ${fmt.n0.format(d.openAlerts)}`));
    return out;
  }

  function quarantineSwitch(d) {
    const macs = isGroup(d) ? d.members.map((m) => m.mac) : [d.mac];
    const busy = macs.some((m) => state.busy.has(m));
    return h("button", {
      class: "switch" + (d.partiallyQuarantined ? " part" : ""), type: "button", role: "switch",
      "aria-checked": d.quarantined ? "true" : "false",
      "aria-label": t("dev.quarSwitch", { name: d.name }),
      title: d.quarantined ? t("dev.quarOff") : isGroup(d) ? t("dev.quarOnGroup", { n: macs.length }) : t("dev.quarOn"),
      disabled: busy,
      onclick: (e) => { e.stopPropagation(); toggleQuarantine(d); },
    });
  }

  function matches(d, q) {
    if (!q) return true;
    return [d.name, d.hostname, d.comment, d.vendor, d.ip, d.mac, d.note, kindLabel(d.kind),
      ...(d.members || []).flatMap((m) => [m.mac, m.ip])]
      .some((x) => x && x.toLowerCase().includes(q));
  }

  function toggleSelect(d, on) {
    const k = rowKey(d);
    if (on === undefined) on = !state.selected.has(k);
    if (on) state.selected.add(k); else state.selected.delete(k);
    const hadFocus = document.activeElement && document.activeElement.classList.contains("sel");
    renderDevices();
    if (hadFocus) {
      const cb = document.querySelector(`input.sel[data-key="${CSS.escape(k)}"]`);
      if (cb) cb.focus();
    }
  }

  function deviceRow(d) {
    const group = isGroup(d);
    const gk = groupKey(d);
    const key = rowKey(d);
    const open = group && isOpen(gk);
    const selected = state.merge && state.selected.has(key);
    const sub = [d.hostname && d.hostname !== d.name ? d.hostname : null, kindLabel(d.kind),
      group ? t(d.group === "manual" ? "group.manual" : "group.auto") : null].filter(Boolean).join(" · ");
    const macBadge = group ? h("button", {
      class: "badge macs", type: "button", "aria-expanded": open ? "true" : "false",
      title: d.group === "manual" ? t("dev.macsManual.title") : t("dev.macs.title"),
      onclick: (e) => {
        e.stopPropagation();
        const set = state.expandAll ? state.collapsed : state.expanded;
        if (set.has(gk)) set.delete(gk); else set.add(gk);
        renderDevices();
      },
    }, `${d.members.length} MAC ${open ? "▴" : "▾"}`) : null;
    const sel = state.merge ? h("input", {
      type: "checkbox", class: "sel", "data-key": key, checked: selected,
      "aria-label": t("merge.select", { name: d.name }),
      onclick: (e) => e.stopPropagation(),
      onchange: (e) => toggleSelect(d, e.target.checked),
    }) : null;
    const activate = () => (state.merge ? toggleSelect(d) : openDetail(d.mac));
    const tr = h("tr", { class: (d.quarantined ? "quarantined" : "") + (selected ? " selected" : ""), onclick: activate, tabindex: "0",
      onkeydown: (e) => { if (e.key === "Enter" && e.target === tr) activate(); } },
      h("td", { class: "c-name" }, h("div", { class: "dev-name" },
        sel,
        h("span", { class: "kind", title: kindLabel(d.kind) }, kindIcon(d.kind)),
        h("span", { class: "n" }, d.name, macBadge ? " " : null, macBadge, h("span", { class: "sub" }, sub)))),
      h("td", { class: "hide-s" }, d.vendor || h("span", { class: "muted" }, "–")),
      h("td", { class: "c-ip mono" }, d.ip || "–", group ? h("span", { class: "muted", title: t("dev.moreIps") }, ` +${d.members.length - 1}`) : null),
      h("td", { class: "hide-m mono" }, d.mac, d.randomized ? h("span", { class: "muted", title: t("dev.randomMac") }, " 🎲") : null),
      h("td", { class: "num c-tx" }, fmtBytes(d.tx24h)),
      h("td", { class: "num c-rx" }, fmtBytes(d.rx24h)),
      h("td", { class: "c-status" }, statusBadges(d)),
      h("td", { class: "c-q" }, quarantineSwitch(d)));
    if (!open) return [tr];
    const rows = [tr, ...d.members.map((m) => {
      const md = { ...m, name: `${d.name} (${m.mac})` };
      const online = Date.now() - ts(m.lastSeen) < ONLINE_MS;
      const mr = h("tr", { class: "member" + (m.quarantined ? " quarantined" : ""), onclick: () => openDetail(m.mac), tabindex: "0",
        onkeydown: (e) => { if (e.key === "Enter" && e.target === mr) openDetail(m.mac); } },
        h("td", { class: "c-name" }, h("div", { class: "dev-name" },
          h("span", { class: "n mono" }, "↳ " + m.mac,
            h("span", { class: "sub" }, m.mac === d.mac ? t("dev.member.primary") : t("dev.member.other"))))),
        h("td", { class: "hide-s" }),
        h("td", { class: "c-ip mono" }, m.ip || "–"),
        h("td", { class: "hide-m" }),
        h("td", { class: "num c-tx" }, fmtBytes(m.tx24h)),
        h("td", { class: "num c-rx" }, fmtBytes(m.rx24h)),
        h("td", { class: "c-status" },
          m.quarantined ? h("span", { class: "badge quar" }, t("dev.quar")) : null,
          online ? h("span", { class: "badge online" }, t("dev.online"))
            : h("span", { class: "badge", title: fmtTime(m.lastSeen) }, t("dev.offline", { ago: ago(m.lastSeen) }))),
        h("td", { class: "c-q" }, quarantineSwitch(md)));
      return mr;
    })];
    rows.push(h("tr", { class: "member group-foot" }, h("td", { colspan: "8" }, h("div", { class: "group-foot-in" },
      h("span", { class: "muted" }, d.group === "manual" ? t("group.manual.help") : t("group.auto.help")),
      d.group === "manual" ? h("button", {
        class: "btn small", type: "button",
        onclick: (e) => { e.stopPropagation(); unmergeGroup(d); },
      }, t("group.unmerge")) : null))));
    return rows;
  }

  function renderDevices() {
    const q = state.deviceQuery.trim().toLowerCase();
    const { key, dir } = state.sort;
    const list = state.devices.filter((d) => matches(d, q)).sort((a, b) => compareDevices(a, b, key, dir));
    $("#devices").replaceChildren(...list.flatMap(deviceRow));
    $("table.devices").classList.toggle("selecting", state.merge);
    renderSortUI();
    $("#devices-count").textContent = q ? `${fmt.n0.format(list.length)}/${fmt.n0.format(state.devices.length)}` : fmt.n0.format(state.devices.length);
    $("#devices-empty").classList.toggle("hidden", list.length > 0);
    renderExpandToggle();
    renderMergeBar();
  }

  // ------------------------------------------------------------------ expand all
  const isOpen = (gk) => (state.expandAll ? !state.collapsed.has(gk) : state.expanded.has(gk));

  function renderExpandToggle() {
    const b = $("#expand-btn");
    if (!b) return;
    const hasGroups = state.devices.some(isGroup);
    const allOpen = hasGroups && state.devices.filter(isGroup).every((d) => isOpen(groupKey(d)));
    b.classList.toggle("hidden", !hasGroups);
    b.textContent = t(allOpen ? "dev.collapseAll" : "dev.expandAll");
    b.title = t("dev.expandAll.title");
    b.setAttribute("aria-pressed", allOpen ? "true" : "false");
    b.classList.toggle("active", allOpen);
  }

  function toggleExpandAll() {
    const allOpen = state.devices.filter(isGroup).every((d) => isOpen(groupKey(d)));
    state.expandAll = !allOpen;
    state.expanded.clear();
    state.collapsed.clear();
    storage.set("guardian.expandAll", state.expandAll ? "1" : null);
    renderDevices();
  }

  // ------------------------------------------------------------------ merge
  const selectedRows = () => state.devices.filter((d) => state.selected.has(rowKey(d)));

  function renderMergeToggle() {
    const b = $("#merge-btn");
    if (!b) return;
    b.textContent = t("merge.mode");
    b.title = t("merge.mode.title");
    b.setAttribute("aria-pressed", state.merge ? "true" : "false");
    b.classList.toggle("active", state.merge);
  }

  function setMergeMode(on) {
    state.merge = on;
    state.selected.clear();
    renderMergeToggle();
    renderDevices();
  }

  function renderMergeBar() {
    const bar = $("#mergebar");
    bar.classList.toggle("hidden", !state.merge);
    if (!state.merge) return;
    const n = selectedRows().length;
    $("#merge-info").textContent = n < 2 ? t("merge.hint") : t("merge.selected", { n });
    const go = $("#merge-do");
    go.textContent = t("merge.do", { n });
    go.disabled = n < 2;
    $("#merge-cancel").textContent = t("common.cancel");
  }

  async function mergeSelected() {
    const rows = selectedRows();
    if (rows.length < 2) return;
    const ok = await confirmDialog(t("merge.confirmTitle"),
      t("merge.confirmText", { list: rows.map((d) => quote(d.name)).join(", ") }), t("merge.confirmBtn"), false);
    if (!ok) return;
    try {
      await api("POST", "devices/merge", { macs: rows.flatMap(rowMacs) });
      toast(t("merge.done"));
      setMergeMode(false);
    } catch (err) { toast(err.message, true); }
    await refresh();
  }

  async function unmergeGroup(d) {
    const ok = await confirmDialog(t("group.unmerge.confirmTitle"), t("group.unmerge.confirmText", { name: quote(d.name) }),
      t("group.unmerge"), false);
    if (!ok) return false;
    try {
      await api("POST", `devices/${encodeURIComponent(d.mac)}/unmerge`);
      state.expanded.delete(groupKey(d));
      toast(t("group.unmerged"));
    } catch (err) { toast(err.message, true); return false; }
    await refresh();
    return true;
  }

  // ------------------------------------------------------------------ confirm dialog
  const normWord = (x) => x.trim().toLocaleUpperCase(lang);

  /** modal yes/no; word = the user must type this word to enable OK */
  function confirmDialog(title, text, okLabel, danger, word) {
    const dlg = $("#confirm");
    $("#confirm-title").textContent = title;
    $("#confirm-text").textContent = text;
    const ok = $("#confirm-ok");
    ok.textContent = okLabel;
    ok.className = "btn " + (danger ? "danger" : "primary");
    $("#confirm-cancel").textContent = t("common.back");
    const wrap = $("#confirm-word-wrap");
    const input = $("#confirm-word");
    wrap.classList.toggle("hidden", !word);
    // OK is the form's only submit button, so Enter in the word field confirms –
    // and does nothing while OK is disabled.
    if (word) {
      $("#confirm-word-label").textContent = t("reset.typeWord", { word });
      input.value = "";
      ok.disabled = true;
      input.oninput = () => { ok.disabled = normWord(input.value) !== normWord(word); };
    } else {
      ok.disabled = false;
      input.oninput = null;
    }
    return new Promise((resolve) => {
      dlg.addEventListener("close", () => resolve(dlg.returnValue === "ok"), { once: true });
      dlg.returnValue = "cancel";
      dlg.showModal();
      if (word) input.focus();
    });
  }

  async function toggleQuarantine(d) {
    const group = isGroup(d);
    const on = !d.quarantined;
    // a group switches all its MACs; members already in the wanted state are skipped
    const targets = group ? d.members.filter((m) => !!m.quarantined !== on) : [d];
    const ips = targets.map((m) => m.ip).filter(Boolean).join(", ") || t("common.noIp");
    const what = group
      ? t("quar.whatGroup", { name: quote(d.name), macs: t("unit.macs", { n: targets.length }), ips })
      : t("quar.what", { name: quote(d.name), ip: d.ip || t("common.noIp") });
    const ok = await confirmDialog(
      on ? t("quar.onTitle") : t("quar.offTitle"),
      on ? t("quar.onText", { what }) : t("quar.offText", { what }),
      on ? t("quar.onBtn") : t("quar.offBtn"), on);
    if (!ok) return;
    targets.forEach((m) => state.busy.add(m.mac));
    renderDevices();
    const errors = [];
    try {
      for (const m of targets) {
        try {
          await api(on ? "POST" : "DELETE", `devices/${encodeURIComponent(m.mac)}/quarantine`);
        } catch (err) {
          errors.push(group ? `${m.mac}: ${err.message}` : err.message);
        }
      }
    } finally {
      targets.forEach((m) => state.busy.delete(m.mac));
    }
    if (errors.length) toast(t("quar.error", { err: errors.join("; ") }), true);
    else toast(on ? t("quar.done", { name: d.name }) : t("quar.released", { name: d.name }));
    await refresh();
  }

  // ------------------------------------------------------------------ detail
  async function openDetail(mac) {
    state.detailMac = mac;
    state.detailData = null;
    state.detailDirty = false;
    const dlg = $("#detail");
    const d = rowByMac(mac);
    $("#detail-title").textContent = d ? d.name : mac;
    $("#detail-body").replaceChildren(h("p", { class: "muted" }, t("app.loading")));
    if (!dlg.open) dlg.showModal();
    await loadDetail(true);
  }

  /** a form control inside el has focus */
  const editingIn = (el) => {
    const a = document.activeElement;
    return !!a && el.contains(a) && /^(INPUT|SELECT|TEXTAREA)$/.test(a.tagName);
  };

  async function loadDetail(force) {
    const mac = state.detailMac;
    if (!mac || !$("#detail").open) return;
    // do not clobber the form while the user is editing it
    if (!force && (state.detailDirty || editingIn($("#detail-body")))) return;
    try {
      const data = await api("GET", `devices/${encodeURIComponent(mac)}`);
      if (state.detailMac !== mac) return;
      if (!force && (state.detailDirty || editingIn($("#detail-body")))) return;
      state.detailData = data;
      state.detailDirty = false;
      renderDetail(data);
    } catch (err) {
      $("#detail-body").replaceChildren(h("p", { class: "banner" }, err.message));
    }
  }

  async function saveKind(d, row, kind, select) {
    // one physical device: apply the choice to all its MACs
    const macs = row && isGroup(row) ? row.members.map((m) => m.mac) : [d.mac];
    select.disabled = true;
    try {
      for (const mac of macs) await api("PATCH", `devices/${encodeURIComponent(mac)}`, { kind });
      toast(t("common.saved"));
      state.detailDirty = false;
      await refresh();
      await loadDetail(true);
    } catch (err) {
      toast(err.message, true);
      select.disabled = false;
    }
  }

  function renderDetail(data) {
    const d = data.device;
    const row = rowByMac(d.mac);
    $("#detail-title").textContent = `${kindIcon(d.kind)} ${d.name}`;

    const input = h("input", { type: "text", id: "note-input", maxlength: "200",
      "aria-label": t("detail.name"),
      placeholder: d.comment ? t("detail.notePhComment", { c: d.comment }) : t("detail.notePh"), value: d.note || "",
      oninput: () => { state.detailDirty = true; } });
    const noteForm = h("form", {
      class: "note-form",
      onsubmit: async (e) => {
        e.preventDefault();
        const btn = noteForm.querySelector("button");
        btn.disabled = true;
        try {
          await api("PATCH", `devices/${encodeURIComponent(d.mac)}`, { note: input.value });
          toast(t("common.saved"));
          state.detailDirty = false;
          input.blur();
          await refresh();
          await loadDetail(true);
        } catch (err) { toast(err.message, true); } finally { btn.disabled = false; }
      },
    }, input, h("button", { class: "btn primary", type: "submit" }, t("common.save")));

    // kind selector: "" = automatic (shows the guess)
    const auto = d.kindAuto || "unknown";
    const kindSel = h("select", { id: "kind-select", "aria-describedby": "kind-help" },
      h("option", { value: "" }, t("detail.kindAuto", { kind: `${kindIcon(auto)} ${kindLabel(auto)}` })),
      KINDS.map((k) => h("option", { value: k }, `${kindIcon(k)} ${kindLabel(k)}`)));
    kindSel.value = d.kindOverride || "";
    kindSel.addEventListener("change", () => saveKind(d, row, kindSel.value, kindSel));
    const groupN = row && isGroup(row) ? row.members.length : 0;
    const kindBox = h("div", { class: "field mt" },
      h("label", { for: "kind-select" }, t("detail.kind")),
      kindSel,
      h("p", { class: "help", id: "kind-help" }, t("detail.kindHelp"), groupN ? " " + t("detail.kindGroup", { n: groupN }) : ""));

    const fact = (k, v) => h("div", {}, h("dt", {}, k), h("dd", {}, v || "–"));
    const facts = h("dl", { class: "facts" },
      fact(t("fact.ip"), h("span", { class: "mono" }, d.ip || "–")),
      fact(t("fact.mac"), h("span", { class: "mono" }, d.mac + (d.randomized ? " " + t("fact.random") : ""))),
      fact(t("fact.hostname"), d.hostname),
      d.comment && d.comment !== d.hostname ? fact(t("fact.comment"), d.comment) : null,
      fact(t("fact.vendor"), d.vendor),
      d.classId ? fact(t("fact.classId"), d.classId) : null,
      fact(t("fact.firstSeen"), fmtTime(d.firstSeen)),
      fact(t("fact.lastSeen"), `${fmtTime(d.lastSeen)} (${ago(d.lastSeen)})`),
      fact(t("fact.24h"), `↑ ${fmtBytes(d.tx24h)} · ↓ ${fmtBytes(d.rx24h)}`),
      fact(t("fact.status"), statusBadges(d)));

    const qBtn = h("button", {
      class: "btn" + (d.quarantined ? "" : " danger"), type: "button",
      onclick: async () => { await toggleQuarantine(d); await loadDetail(true); },
    }, d.quarantined ? t("dev.quarOff") : t("dev.quarOn"));

    const chartInfo = h("div", { class: "chart-info muted" }, t("detail.chartHint"));
    // other MACs of the same physical device (grouped in the device list)
    const manual = !!d.groupId;
    const others = row && isGroup(row) ? row.members.filter((m) => m.mac !== d.mac) : [];
    const unmergeBtn = manual ? h("button", {
      class: "btn small", type: "button",
      onclick: async () => { if (await unmergeGroup(row && isGroup(row) ? row : d)) await loadDetail(true); },
    }, t("group.unmerge")) : null;
    let othersBox = null;
    if (others.length) {
      othersBox = h("div", { class: "mt" },
        h("div", { class: "muted" }, manual ? t("detail.othersManual") : t("detail.others")),
        h("ul", { class: "others" }, others.map((m) => h("li", {},
          h("button", { class: "link mono", type: "button", onclick: () => openDetail(m.mac) }, m.mac),
          ` · ${m.ip || t("common.noIp")} · ${ago(m.lastSeen)}`, m.quarantined ? " · " + t("detail.inQuarantine") : ""))),
        unmergeBtn ? h("div", { class: "mt-s" }, unmergeBtn) : null);
    } else if (manual) {
      othersBox = h("div", { class: "mt" }, h("div", { class: "muted" }, t("detail.loneMember")), h("div", { class: "mt-s" }, unmergeBtn));
    }

    const sections = [
      h("section", {}, h("h3", {}, t("detail.name")), noteForm, kindBox),
      h("section", {}, facts, othersBox, h("div", { class: "actions mt" }, qBtn)),
      h("section", {}, h("h3", {}, t("detail.traffic")),
        h("div", { class: "chart-wrap" }, chart(data.hours, chartInfo)),
        h("div", { class: "legend" },
          h("span", {}, h("i", { class: "rx" }), t("detail.rx")),
          h("span", {}, h("i", { class: "tx" }), t("detail.tx"))),
        chartInfo),
      h("section", {}, h("h3", {}, t("detail.dests")), destTable(data.dests)),
    ];
    if (data.alerts && data.alerts.length) {
      sections.push(h("section", {}, h("h3", {}, t("detail.alerts")),
        h("ul", { class: "alerts" }, data.alerts.slice(0, 20).map((a) => alertItem(a, { noDevice: true })))));
    }
    $("#detail-body").replaceChildren(...sections);
  }

  /** 7×24 hourly bars: download above the axis, upload mirrored below. */
  function chart(hours, info) {
    const N = 7 * 24;
    const W = 840, H = 220, top = 8, bottom = 22, mid = top + (H - top - bottom) * 0.62;
    const upH = mid - top, downH = H - bottom - mid - 2;
    const bw = W / N;
    const end = new Date(); end.setMinutes(0, 0, 0);
    const startMs = end.getTime() - (N - 1) * 3600000;
    const slots = Array.from({ length: N }, (_, i) => ({ t: startMs + i * 3600000, tx: 0, rx: 0, conns: 0, dst: 0 }));
    for (const x of hours || []) {
      const i = Math.round((ts(x.hour) - startMs) / 3600000);
      if (i >= 0 && i < N) { slots[i].tx += x.tx; slots[i].rx += x.rx; slots[i].conns += x.newConns; slots[i].dst += x.distinctDst; }
    }
    const maxRx = Math.max(1, ...slots.map((x) => x.rx));
    const maxTx = Math.max(1, ...slots.map((x) => x.tx));
    const svg = s("svg", { class: "chart", viewBox: `0 0 ${W} ${H}`, role: "img", "aria-label": t("detail.chartLabel") });
    // day separators + labels
    for (let i = 0; i < N; i++) {
      const dt = new Date(slots[i].t);
      if (dt.getHours() === 0) {
        const x = i * bw;
        svg.append(s("line", { class: "grid", x1: x, x2: x, y1: top, y2: H - bottom }));
        svg.append(s("text", { class: "axis", x: x + 3, y: H - 6 }, fmt.day.format(dt)));
      }
    }
    svg.append(s("line", { class: "grid", x1: 0, x2: W, y1: mid, y2: mid }));
    svg.append(s("text", { class: "axis", x: W - 4, y: top + 10, "text-anchor": "end" }, "↓ max " + fmtBytes(maxRx)));
    svg.append(s("text", { class: "axis", x: W - 4, y: H - bottom - 4, "text-anchor": "end" }, "↑ max " + fmtBytes(maxTx)));
    const show = (x) => {
      info.textContent = t("detail.chartInfo", { time: fmt.dt.format(new Date(x.t)), rx: fmtBytes(x.rx), tx: fmtBytes(x.tx), conns: x.conns, dst: x.dst });
    };
    slots.forEach((x, i) => {
      const label = `${fmt.dt.format(new Date(x.t))} – ↓ ${fmtBytes(x.rx)}, ↑ ${fmtBytes(x.tx)}`;
      const g = s("g", { onclick: () => show(x), onmouseenter: () => show(x) }, s("title", {}, label));
      // transparent hit area covering the whole column
      g.append(s("rect", { x: i * bw, y: top, width: bw, height: H - bottom - top, fill: "transparent" }));
      if (x.rx > 0) {
        const hh = Math.max(1, (x.rx / maxRx) * upH);
        g.append(s("rect", { class: "rx", x: i * bw + 0.5, y: mid - hh, width: Math.max(1, bw - 1), height: hh, rx: 1 }));
      }
      if (x.tx > 0) {
        const hh = Math.max(1, (x.tx / maxTx) * downH);
        g.append(s("rect", { class: "tx", x: i * bw + 0.5, y: mid + 2, width: Math.max(1, bw - 1), height: hh, rx: 1 }));
      }
      svg.append(g);
    });
    return svg;
  }

  function destTable(dests) {
    if (!dests || !dests.length) return h("p", { class: "muted" }, t("dest.empty"));
    const max = Math.max(1, ...dests.map((x) => x.bytes));
    return h("div", { class: "table-wrap" }, h("table", { class: "simple" },
      h("thead", {}, h("tr", {}, h("th", {}, t("dest.country")), h("th", {}, t("dest.network")), h("th", { class: "num" }, t("dest.data")), h("th", { class: "hide-s" }, t("dest.last")))),
      h("tbody", {}, dests.slice(0, 25).map((x) => {
        const bar = h("div", { class: "bar" });
        bar.style.width = Math.max(2, (100 * x.bytes) / max) + "%";
        return h("tr", {},
          h("td", { title: x.country || t("dest.unknownCountry") }, flag(x.country), " ", x.country || "?"),
          h("td", {}, x.asOrg || t("dest.unknownNet"), x.asn ? h("span", { class: "muted mono" }, ` AS${x.asn}`) : null, bar),
          h("td", { class: "num" }, fmtBytes(x.bytes)),
          h("td", { class: "hide-s muted", title: t("dest.firstSeen", { date: fmtDate(x.firstSeen) }) }, ago(x.lastSeen)));
      }))));
  }

  // ------------------------------------------------------------------ settings
  const NOTIFY_FIELDS = ["telegramToken", "telegramChatId", "ntfyUrl", "ntfyToken", "notifyMin", "language"];
  const DETECT_FIELDS = ["learnPeriodDays", "sensitivity", "disabledDetectors", "dedupWindowHours", "retentionDays"];
  const SECRET_FIELDS = ["telegramToken", "ntfyToken"];
  // [min, max] of the numeric fields (same limits as settings.Validate on the server)
  const LIMITS = { learnPeriodDays: [1, 60], dedupWindowHours: [1 / 60, 168], retentionDays: [14, 365] };

  /** form values from the server state; secrets: null = unchanged, "" = delete, text = new value */
  function draftFrom(st) {
    return {
      telegramToken: null, telegramChatId: st.telegramChatId || "", ntfyUrl: st.ntfyUrl || "", ntfyToken: null,
      notifyMin: st.notifyMin, language: st.language || "en",
      learnPeriodDays: String(st.learnPeriodDays), sensitivity: st.sensitivity,
      disabledDetectors: [...(st.disabledDetectors || [])],
      dedupWindowHours: String(st.dedupWindowHours), retentionDays: String(st.retentionDays),
    };
  }

  function fieldChanged(f) {
    const st = state.settings, d = state.draft;
    if (!st || !d) return false;
    if (SECRET_FIELDS.includes(f)) return d[f] !== null;
    if (f === "disabledDetectors") return [...d[f]].sort().join() !== [...st[f]].sort().join();
    if (f === "language") return d.language !== (st.language || "en");
    if (f in LIMITS) return Number(d[f]) !== st[f];
    return String(d[f]) !== String(st[f] ?? "");
  }
  const sectionDirty = (fields) => fields.some(fieldChanged);
  const settingsDirty = () => sectionDirty(NOTIFY_FIELDS) || sectionDirty(DETECT_FIELDS);

  /** client-side checks with localized messages; returns an error text or "" */
  function validateSection(fields) {
    const d = state.draft, st = state.settings;
    for (const f of fields) {
      if (!(f in LIMITS) || !fieldChanged(f)) continue;
      const v = Number(d[f]);
      const [lo, hi] = LIMITS[f];
      if (d[f] === "" || !Number.isFinite(v) || v < lo - 1e-9 || v > hi) {
        return t("set.err.range", { field: t("set." + f), min: fmt.num.format(lo), max: fmt.num.format(hi) });
      }
    }
    if (fields === NOTIFY_FIELDS) {
      const tokenSet = d.telegramToken === null ? st.telegramTokenSet : d.telegramToken !== "";
      if (tokenSet !== (d.telegramChatId.trim() !== "")) return t("set.err.tgPair");
      const u = d.ntfyUrl.trim();
      if (u && !/^https?:\/\/[^/\s]+\/+[^\s]+$/i.test(u)) return t("set.err.ntfyUrl");
    }
    return "";
  }

  function patchFor(fields) {
    const d = state.draft;
    const p = {};
    for (const f of fields) {
      if (!fieldChanged(f)) continue;
      if (f in LIMITS) p[f] = Number(d[f]);
      else if (f === "disabledDetectors") p[f] = [...d[f]];
      else p[f] = typeof d[f] === "string" ? d[f].trim() : d[f];
    }
    return p;
  }

  async function openSettings() {
    const dlg = $("#settings");
    state.settingsErr = null;
    $("#settings-body").replaceChildren(h("p", { class: "muted" }, t("app.loading")));
    if (!dlg.open) dlg.showModal();
    try {
      state.settings = await api("GET", "settings");
      state.draft = draftFrom(state.settings);
    } catch (err) {
      state.settings = null;
      state.settingsErr = err.message;
    }
    renderSettings();
  }

  async function closeSettings() {
    if (settingsDirty()) {
      const ok = await confirmDialog(t("set.discardTitle"), t("set.discardText"), t("set.discard"), true);
      if (!ok) return;
    }
    $("#settings").close();
  }

  /** marks the "unsaved" hints without re-rendering (keeps focus) */
  function updateDirtyMarks() {
    for (const [id, fields] of [["notify", NOTIFY_FIELDS], ["detect", DETECT_FIELDS]]) {
      const el = document.getElementById(`dirty-${id}`);
      if (el) el.classList.toggle("hidden", !sectionDirty(fields));
    }
  }

  function bindInput(el, field, transform) {
    el.addEventListener("input", () => {
      state.draft[field] = transform ? transform(el.value) : el.value;
      updateDirtyMarks();
    });
    return el;
  }

  /** labelled form field with optional help text */
  function field(id, label, control, help, extra) {
    if (help) control.setAttribute("aria-describedby", id + "-help");
    control.id = id;
    return h("div", { class: "field" },
      h("label", { for: id }, label), extra ? h("div", { class: "inline" }, control, extra) : control,
      help ? h("p", { class: "help", id: id + "-help" }, help) : null);
  }

  function secretField(id, field_, label, isSet, help) {
    const d = state.draft;
    const cleared = d[field_] === "";
    const input = h("input", {
      type: "password", autocomplete: "new-password", spellcheck: "false",
      placeholder: cleared ? t("set.tokenCleared") : isSet ? t("set.tokenSaved") : "", value: cleared ? "" : d[field_] || "",
      disabled: cleared,
    });
    bindInput(input, field_, (v) => (v === "" ? null : v));
    let btn = null;
    if (isSet || cleared) {
      btn = h("button", {
        class: "btn small", type: "button",
        onclick: () => {
          if (cleared) {
            state.draft[field_] = null;
            if (field_ === "telegramToken") state.draft.telegramChatId = state.settings.telegramChatId || "";
          } else {
            state.draft[field_] = "";
            // a Telegram chat ID without a token is useless (and rejected)
            if (field_ === "telegramToken") state.draft.telegramChatId = "";
          }
          renderSettings();
        },
      }, cleared ? t("set.keep") : t("common.delete"));
    }
    return field(id, label, input, help, btn);
  }

  function learnInfo() {
    const st = state.settings;
    const until = st ? ts(st.learningUntil) : 0;
    if (!until) return h("div", { id: "learn-info" });
    if (until > Date.now()) {
      const periodMs = st.learnPeriodDays * 86400000;
      const pct = Math.min(1, Math.max(0, 1 - (until - Date.now()) / periodMs));
      const fill = h("span");
      fill.style.width = (pct * 100).toFixed(1) + "%";
      return h("div", { id: "learn-info", class: "learn-info" },
        h("div", { class: "progress", role: "progressbar", "aria-valuemin": "0", "aria-valuemax": "100",
          "aria-valuenow": String(Math.round(pct * 100)), "aria-label": t("set.learn.progressLabel") }, fill),
        h("p", { class: "help" }, t("set.learn.progress", { pct: fmt.pct.format(pct), left: remaining(until), until: fmtTime(st.learningUntil) })));
    }
    return h("div", { id: "learn-info", class: "learn-info" }, h("p", { class: "help ok" }, t("set.learn.done", { date: fmtDate(st.learningUntil) })));
  }

  function updateLearnInfo() {
    const el = document.getElementById("learn-info");
    if (el && state.settings) el.replaceWith(learnInfo());
  }

  function sectionHead(id, title, intro) {
    return [h("div", { class: "set-head" }, h("h3", { id: `set-${id}-h` }, title),
      h("span", { class: "badge dirty hidden", id: `dirty-${id}` }, t("set.unsaved"))),
    intro ? h("p", { class: "help intro" }, intro) : null];
  }

  async function saveSection(fields, errEl, btn) {
    errEl.textContent = "";
    const msg = validateSection(fields);
    if (msg) { errEl.textContent = msg; return false; }
    const patch = patchFor(fields);
    if (!Object.keys(patch).length) return true;
    if (btn) btn.disabled = true;
    try {
      const res = await api("PUT", "settings", patch);
      const fresh = draftFrom(res);
      state.settings = res;
      for (const f of fields) state.draft[f] = fresh[f];
      toast(t("set.saved"));
      renderSettings();
      refresh();
      return true;
    } catch (err) {
      errEl.textContent = t("set.saveFailed", { err: err.message });
      return false;
    } finally {
      if (btn) btn.disabled = false;
    }
  }

  function notifySection() {
    const st = state.settings, d = state.draft;
    const errEl = h("p", { class: "form-err", role: "alert" });
    const result = h("p", { class: "test-result", id: "test-result", "aria-live": "polite" });

    const chat = bindInput(h("input", { type: "text", value: d.telegramChatId, inputmode: "numeric", autocomplete: "off", placeholder: "123456789" }), "telegramChatId");
    const ntfyUrl = bindInput(h("input", { type: "url", value: d.ntfyUrl, autocomplete: "off", placeholder: "https://ntfy.sh/…" }), "ntfyUrl");
    const sev = bindInput(h("select", {}, SEVERITIES.map((x) => h("option", { value: x }, t("sev." + x)))), "notifyMin");
    sev.value = d.notifyMin;
    const langSel = bindInput(h("select", {}, LANGS.map((x) => h("option", { value: x }, LANG_NAMES[x]))), "language");
    langSel.value = d.language;

    const howto = h("details", { class: "howto" },
      h("summary", {}, t("set.tg.howto")),
      h("ol", {}, h("li", {}, t("set.tg.step1")), h("li", {}, t("set.tg.step2")), h("li", {}, t("set.tg.step3"))));

    const save = h("button", { class: "btn primary", type: "submit" }, t("common.save"));
    const test = h("button", {
      class: "btn", type: "button",
      onclick: async () => {
        result.className = "test-result";
        if (sectionDirty(NOTIFY_FIELDS) && !(await saveSection(NOTIFY_FIELDS, errEl, test))) return;
        test.disabled = true;
        const r = document.getElementById("test-result") || result;
        r.className = "test-result";
        r.textContent = t("set.testSending");
        try {
          await api("POST", "settings/test-notify");
          r.className = "test-result ok";
          r.textContent = t("set.testOk");
        } catch (err) {
          r.className = "test-result err";
          r.textContent = t("set.testFail", { err: err.message });
        } finally { test.disabled = false; }
      },
    }, t("set.test"));

    return h("form", {
      class: "set-section", "aria-labelledby": "set-notify-h", novalidate: true,
      onsubmit: (e) => { e.preventDefault(); saveSection(NOTIFY_FIELDS, errEl, save); },
    },
    ...sectionHead("notify", t("set.notify"), t("set.notify.intro")),
    h("fieldset", {}, h("legend", {}, "Telegram"),
      secretField("set-tg-token", "telegramToken", t("set.tg.token"), st.telegramTokenSet, t("set.tg.tokenHelp")),
      field("set-tg-chat", t("set.tg.chat"), chat, t("set.tg.chatHelp")),
      howto),
    h("fieldset", {}, h("legend", {}, "ntfy"),
      field("set-ntfy-url", t("set.ntfy.url"), ntfyUrl, t("set.ntfy.urlHelp")),
      secretField("set-ntfy-token", "ntfyToken", t("set.ntfy.token"), st.ntfyTokenSet, t("set.ntfy.tokenHelp"))),
    h("div", { class: "grid2" },
      field("set-sev", t("set.notifyMin"), sev, t("set.notifyMin.help")),
      field("set-lang", t("set.language"), langSel, t("set.language.help"))),
    errEl,
    h("div", { class: "actions start" }, save, test),
    result);
  }

  function detectSection() {
    const d = state.draft;
    const errEl = h("p", { class: "form-err", role: "alert" });
    const num = (f, step) => bindInput(h("input", { type: "number", inputmode: "decimal", min: String(LIMITS[f][0]), max: String(LIMITS[f][1]), step, value: d[f] }), f);

    const sens = h("fieldset", { "aria-describedby": "set-sens-help" }, h("legend", {}, t("set.sens")),
      h("p", { class: "help", id: "set-sens-help" }, t("set.sens.help")),
      h("div", { class: "radios" }, SENSITIVITIES.map((x) => h("label", { class: "radio" },
        h("input", { type: "radio", name: "sensitivity", value: x, checked: d.sensitivity === x,
          onchange: () => { state.draft.sensitivity = x; updateDirtyMarks(); } }),
        h("span", {}, h("b", {}, t(`set.sens.${x}`)), h("small", {}, t(`set.sens.${x}.help`)))))));

    const dets = h("fieldset", { class: "switches" }, h("legend", {}, t("set.detectors")),
      h("p", { class: "help" }, t("set.detectors.help")),
      DETECTORS.map((k) => h("label", { class: "switch-row" },
        h("input", { type: "checkbox", role: "switch", class: "toggle", checked: !d.disabledDetectors.includes(k),
          onchange: (e) => {
            const set = new Set(state.draft.disabledDetectors);
            if (e.target.checked) set.delete(k); else set.add(k);
            state.draft.disabledDetectors = DETECTORS.filter((x) => set.has(x));
            updateDirtyMarks();
          } }),
        h("span", {}, h("b", {}, alertKind(k)), h("small", {}, t(`det.${k}.help`))))));

    const save = h("button", { class: "btn primary", type: "submit" }, t("common.save"));
    return h("form", {
      class: "set-section", "aria-labelledby": "set-detect-h", novalidate: true,
      onsubmit: (e) => { e.preventDefault(); saveSection(DETECT_FIELDS, errEl, save); },
    },
    ...sectionHead("detect", t("set.detect")),
    field("set-learn", t("set.learnPeriodDays"), num("learnPeriodDays", "1"), t("set.learn.help")),
    learnInfo(),
    sens,
    dets,
    h("div", { class: "grid2" },
      field("set-dedup", t("set.dedupWindowHours"), num("dedupWindowHours", "any"), t("set.dedup.help")),
      field("set-retention", t("set.retentionDays"), num("retentionDays", "1"), t("set.retention.help"))),
    errEl,
    h("div", { class: "actions start" }, save));
  }

  async function doReset(all) {
    const word = t("reset.word");
    const ok = await confirmDialog(all ? t("reset.allTitle") : t("reset.learnedTitle"),
      all ? t("set.resetAll.help") : t("set.resetLearned.help"), t("common.delete"), true, word);
    if (!ok) return;
    try {
      await api("POST", "reset", { scope: all ? "all" : "learned" });
      toast(t("reset.done"));
      if (all) { state.expanded.clear(); state.collapsed.clear(); state.selected.clear(); }
    } catch (err) {
      toast(t("reset.failed", { err: err.message }), true);
    }
    await refresh();
    try {
      state.settings = await api("GET", "settings");
      for (const [f, v] of Object.entries(draftFrom(state.settings))) if (!fieldChanged(f)) state.draft[f] = v;
      if ($("#settings").open) renderSettings();
    } catch { /* keep the old values */ }
  }

  function dataSection() {
    const item = (title, help, all) => h("div", { class: "danger-item" },
      h("div", {}, h("b", {}, title), h("p", { class: "help" }, help)),
      h("button", { class: "btn danger", type: "button", onclick: () => doReset(all) }, title));
    return h("section", { class: "set-section danger-zone", "aria-labelledby": "set-danger-h" },
      h("div", { class: "set-head" }, h("h3", { id: "set-danger-h" }, t("set.danger"))),
      item(t("set.resetLearned"), t("set.resetLearned.help"), false),
      item(t("set.resetAll"), t("set.resetAll.help"), true));
  }

  function renderSettings() {
    const body = $("#settings-body");
    if (!state.settings || !state.draft) {
      body.replaceChildren(h("p", { class: "banner" }, t("set.unavailable", { err: state.settingsErr || "?" })));
      return;
    }
    // keep the scroll position when re-rendering (language switch, save)
    const dlg = $("#settings");
    const scroll = dlg.scrollTop;
    body.replaceChildren(notifySection(), detectSection(), dataSection());
    dlg.scrollTop = scroll;
    updateDirtyMarks();
  }

  // ------------------------------------------------------------------ refresh loop
  let refreshing = null;
  async function refresh() {
    if (refreshing) return refreshing;
    refreshing = (async () => {
      const q = state.alertFilter === "open" ? "alerts?open=1&limit=500" : "alerts?limit=500";
      const [st, devs, alerts] = await Promise.allSettled([api("GET", "status"), api("GET", "devices"), api("GET", q)]);
      if (st.status === "fulfilled") state.status = st.value;
      if (devs.status === "fulfilled") state.devices = devs.value || [];
      if (alerts.status === "fulfilled") state.alerts = alerts.value || [];
      const failed = [st, devs, alerts].find((r) => r.status === "rejected");
      renderStatus();
      const banner = $("#error-banner");
      if (failed) {
        banner.textContent = t("st.loadFailed", { err: failed.reason.message });
        banner.classList.remove("hidden");
      }
      renderAlerts();
      renderDevices();
      if (state.settings && state.status && $("#settings").open) {
        state.settings.learningUntil = state.status.learningUntil;
        updateLearnInfo();
      }
    })().finally(() => { refreshing = null; });
    return refreshing;
  }

  function tick() {
    if (document.hidden) return;
    refresh();
    loadDetail(false);
  }

  /** UI language: stored choice → server setting → browser → English */
  async function initLang() {
    const stored = storedLang();
    setLang(stored || browserLang() || "en");
    applyStatic();
    if (stored) return;
    try {
      const st = await Promise.race([api("GET", "settings"), new Promise((_, rej) => setTimeout(() => rej(new Error("timeout")), 2000))]);
      if (st && LANGS.includes(st.language) && st.language !== lang && !storedLang()) {
        setLang(st.language);
        applyStatic();
      }
    } catch { /* settings unavailable: keep the browser language */ }
  }

  // ------------------------------------------------------------------ init
  function init() {
    const langSel = $("#lang-select");
    langSel.replaceChildren(...LANGS.map((l) => h("option", { value: l, lang: l }, LANG_NAMES[l])));
    const langReady = initLang(); // sets the language synchronously, may switch it once settings arrive
    langSel.addEventListener("change", () => switchLang(langSel.value));
    $("#theme-btn").addEventListener("click", () => setTheme(THEME_NEXT[theme]));
    $("#settings-btn").addEventListener("click", openSettings);

    document.querySelectorAll(".seg button").forEach((b) => b.addEventListener("click", () => {
      document.querySelectorAll(".seg button").forEach((x) => x.classList.toggle("active", x === b));
      state.alertFilter = b.dataset.filter;
      state.alertsShown = 30;
      refresh();
    }));
    $("#device-filter").addEventListener("input", (e) => { state.deviceQuery = e.target.value; renderDevices(); });
    document.querySelectorAll("table.devices th[data-sort] .th-sort").forEach((b) =>
      b.addEventListener("click", () => setSort(b.closest("th").dataset.sort)));
    $("#sort-select").addEventListener("change", (e) => setSort(e.target.value, SORT_FIRST_DIR[e.target.value] || "asc"));
    $("#sort-dir").addEventListener("click", () => setSort(state.sort.key, state.sort.dir === "asc" ? "desc" : "asc"));
    $("#merge-btn").addEventListener("click", () => setMergeMode(!state.merge));
    $("#expand-btn").addEventListener("click", toggleExpandAll);
    $("#merge-cancel").addEventListener("click", () => setMergeMode(false));
    $("#merge-do").addEventListener("click", mergeSelected);
    $("#confirm-cancel").addEventListener("click", () => $("#confirm").close("cancel"));

    const detail = $("#detail");
    detail.querySelector("[data-close]").addEventListener("click", () => detail.close());
    detail.addEventListener("close", () => { state.detailMac = null; state.detailData = null; state.detailDirty = false; });
    detail.addEventListener("click", (e) => { if (e.target === detail) detail.close(); });

    const settings = $("#settings");
    settings.querySelector("[data-close]").addEventListener("click", closeSettings);
    settings.addEventListener("cancel", (e) => { e.preventDefault(); closeSettings(); }); // Esc
    settings.addEventListener("click", (e) => { if (e.target === settings) closeSettings(); });
    settings.addEventListener("close", () => { state.draft = null; state.settings = null; });

    document.addEventListener("visibilitychange", () => { if (!document.hidden) tick(); });
    renderSortUI();
    renderFoot();
    langReady.finally(() => {
      refresh();
      setInterval(tick, REFRESH_MS);
    });
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();

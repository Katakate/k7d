/* k7d-view — demo-grade observer.
   One EventSource; vanilla JS; no build step. Pure observer: reads SSE +
   ingest, operator verbs only via the explicit drawer buttons. */
(() => {
  "use strict";
  const $ = (id) => document.getElementById(id);
  const SVGNS = "http://www.w3.org/2000/svg";

  let state = {
    connected: false, error: null, run: {}, trees: {},
    events: [], meta: [], beats: [], totals: {},
  };
  let selectedTree = null;
  let selected = null;
  let selectedCid = null;
  let lastFlash = {};        // node_id -> ts of last topology event
  let baseTs = {};           // tree_id -> first event ts (T+ clock base)
  let history = {};          // tree_id -> [{t, vms, ram, vmMax, ramMax}]
  let toastQ = [];
  let toastBusy = false;
  let pressureLatch = {};    // tree_id -> bool (already warned)
  let armSeen = "";
  let serialTimer = null;

  // One SVG per tree. Node ids collide ("root"), so the maps live
  // on the pane, not on the page. Metrics patches never rebuild them.
  const panes = new Map();
  // One tree fills the hero. Side-by-side is opt-in.
  let splitMode = false;
  let acting = false;
  // A preset/policy round trip polls every cluster and can outlive the
  // next slider gesture. Dropping that gesture left the drawer on ×1.
  // Keep the latest dilation action and the factor the operator asked
  // for until the snapshot echoes them.
  let pendingAct = null;
  let pendingFactor = null;
  let pendingFactorUntil = 0;
  let pendingAdaptive = null;
  let pendingAdaptiveUntil = 0;
  let drawerSig = "";
  let tileSigCache = "";
  let treeTabSig = "";
  let gaugeSig = "";
  let timelineSig = "";
  let eventSig = "";
  let metaSig = "";
  let ladderSig = "";
  let flashHot = 0;
  let raf = 0;
  const pending = [];
  const TITLES = {
    tetragon: "Tetragon — fork the cluster and watch the tree",
    miner: "MCP agent — remove the miner",
  };

  /* ---------- formatting ---------- */

  const fmtBytes = (n) => {
    if (n == null) return "—";
    if (n < 1024) return `${n} B`;
    if (n < 1024 ** 2) return `${(n / 1024).toFixed(0)} KiB`;
    if (n < 1024 ** 3) return `${(n / 1024 ** 2).toFixed(1)} MiB`;
    return `${(n / 1024 ** 3).toFixed(2)} GiB`;
  };
  const fmtMs = (ms) => {
    if (ms == null) return "";
    const v = Number(ms);
    // Keep the measured number visible — 1998ms, not a rounded "2.00s"
    // that looks like a placeholder.
    if (v >= 10_000) return `${(v / 1000).toFixed(2)}s`;
    return `${v >= 10 ? v.toFixed(0) : v.toFixed(1)}ms`;
  };
  const fmtT = (ms) => {
    if (ms == null || ms < 0) return "";
    const s = Math.floor(ms / 1000);
    return `T+${String(Math.floor(s / 60)).padStart(2, "0")}:${String(s % 60).padStart(2, "0")}`;
  };
  const nodeFactor = (tree, nodeId) => {
    const raw = (tree && tree.live_dilation && tree.live_dilation[nodeId]) || 1;
    const n = Number(raw);
    return Number.isFinite(n) && n >= 1 ? n : 1;
  };
  const treeFactor = (tree) => {
    if (!tree) return 1;
    const nodes = Object.values(tree.nodes || {});
    const root = nodes.find((n) => !n.parent);
    if (root) return nodeFactor(tree, root.id);
    const vals = Object.values(tree.live_dilation || {});
    return vals.length ? nodeFactor(tree, Object.keys(tree.live_dilation)[0]) : 1;
  };
  const guestClockText = (tree) => {
    const n = treeFactor(tree);
    const gc = tree && tree.guest_clock;
    if (!gc || gc.uptime_s == null || gc.base_uptime_s == null) {
      return `guest T+00:00 ×${n}`;
    }
    const deltaMs = Math.max(0, (Number(gc.uptime_s) - Number(gc.base_uptime_s)) * 1000);
    return `guest ${fmtT(deltaMs) || "T+00:00"} ×${n}`;
  };
  const esc = (s) =>
    String(s == null ? "" : s).replace(/[&<>"]/g, (c) =>
      ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c]));

  /* ---------- state helpers ---------- */

  function currentTree() {
    const ids = Object.keys(state.trees || {});
    if (selectedTree && state.trees[selectedTree]) return state.trees[selectedTree];
    const prefer = state.run && state.run.tree_id;
    if (prefer && state.trees[prefer]) return state.trees[prefer];
    return ids.length ? state.trees[ids[0]] : null;
  }

  function treeBase(tid) {
    return baseTs[tid] != null ? baseTs[tid] : null;
  }

  function noteBase(ev) {
    const tid = ev.tree_id;
    const ts = ev.ts_unix_ms;
    if (!tid || !ts) return;
    if (baseTs[tid] == null || ts < baseTs[tid]) baseTs[tid] = ts;
  }

  function relT(tid, ts) {
    const b = treeBase(tid);
    return b == null || ts == null ? "" : fmtT(ts - b);
  }

  /* ---------- layout ---------- */

  function depthOf(n, byId) {
    let d = 0;
    let cur = n;
    const seen = new Set();
    while (cur && cur.parent && byId[cur.parent] && !seen.has(cur.id)) {
      seen.add(cur.id);
      cur = byId[cur.parent];
      d += 1;
    }
    return d;
  }

  function layout(nodes) {
    const byId = Object.fromEntries(nodes.map((n) => [n.id, n]));
    const sorted = [...nodes].sort((a, b) => {
      const da = depthOf(a, byId) - depthOf(b, byId);
      if (da !== 0) return da;
      return (a.created_at_unix || 0) - (b.created_at_unix || 0) ||
        String(a.id).localeCompare(String(b.id));
    });
    const laneOf = {};
    const used = new Set();
    const alloc = (pref) => {
      if (pref != null && !used.has(pref)) { used.add(pref); return pref; }
      let i = 0;
      while (used.has(i)) i += 1;
      used.add(i);
      return i;
    };
    for (const n of sorted) {
      const parent = n.parent && byId[n.parent];
      if (!parent) { laneOf[n.id] = alloc(0); continue; }
      // Middle sibling (by id, not creation order) continues the parent
      // lane so child-0 is not visually the trunk.
      const kids = [...(parent.children || [])].sort((a, b) =>
        String(a).localeCompare(String(b)));
      const idx = kids.indexOf(n.id);
      const mid = Math.floor((kids.length - 1) / 2);
      laneOf[n.id] = idx === mid ? alloc(laneOf[parent.id]) : alloc(null);
    }
    const depth = {};
    let maxD = 0;
    for (const n of sorted) {
      depth[n.id] = depthOf(n, byId);
      if (depth[n.id] > maxD) maxD = depth[n.id];
    }
    return { byId, laneOf, depth, maxD, sorted };
  }

  function metrics(count) {
    if (count <= 8) return { colW: 216, rowH: 66, boxW: 178, boxH: 46, f: 1 };
    if (count <= 18) return { colW: 172, rowH: 54, boxW: 142, boxH: 40, f: 0.9 };
    return { colW: 138, rowH: 44, boxW: 114, boxH: 34, f: 0.8 };
  }

  /* ---------- graph reconciler ---------- */

  function cpuRows(tree, nodeId) {
    return ((tree && tree.live_cpu) || {})[nodeId] || [];
  }

  // Mean of per-VM host-vCPU percents, weighted by vCPU count.
  // Each VM's percent is already (utime+stime) / (wall × vCPUs).
  function cpuAvg(tree, nodeId) {
    let acc = 0;
    let cpus = 0;
    for (const r of cpuRows(tree, nodeId)) {
      const pct = Number(r.cpu_percent);
      const n = Number(r.vcpus) || 0;
      if (!Number.isFinite(pct) || n <= 0) continue;
      acc += pct * n;
      cpus += n;
    }
    if (!cpus) return null;
    return acc / cpus;
  }

  function cpuText(tree, nodeId) {
    const avg = cpuAvg(tree, nodeId);
    if (avg == null) return "";
    const n = cpuRows(tree, nodeId).filter((r) => r.cpu_percent != null).length;
    return n > 1 ? `CPU avg ${avg.toFixed(0)}%` : `CPU ${avg.toFixed(0)}%`;
  }

  function cpuTip(tree, nodeId) {
    const parts = cpuRows(tree, nodeId).map((r) => {
      const pct = r.cpu_percent == null ? "…" : `${Number(r.cpu_percent).toFixed(0)}%`;
      const n = Number(r.vcpus) || 0;
      return `vm${r.member} ${pct} of ${n} vCPU${n === 1 ? "" : "s"}`;
    });
    const avg = cpuAvg(tree, nodeId);
    const head = avg == null ? "no sample yet" : `avg ${avg.toFixed(0)}% across vCPUs`;
    return `${head}. ${parts.join(" · ")}. ` +
      "Host utime+stime of each vCPU thread over wall time, divided by that VM's vCPU count. " +
      "Not guest /proc/stat, and not a share of the host.";
  }

  function labelRoom(m, cpuLabel) {
    const reserve = cpuLabel ? Math.ceil(cpuLabel.length * 5.6 + 16) : 24;
    return Math.max(4, Math.floor((m.boxW - reserve) / (6.6 * m.f + 0.4)));
  }

  function nodeBits(tree, n, maxChars) {
    // Dilation stays on the status line. CPU is its own top-right label
    // so a bare percent is not read as the rate.
    const f = nodeFactor(tree, n.id);
    const tail = [];
    if (f !== 1) tail.push(`×${f}`);
    const state = n.state || "live";
    const vmc = n.vm_count || 1;
    const vm = vmc === 1 ? "" : `${vmc} vm`;
    const dirtyN = (n.dirty_page_count || 0) * 4096;
    const dirty = dirtyN ? fmtBytes(dirtyN) : "";
    const limit = (maxChars || 24) + 8;
    const candidates = [
      [state, vm, dirty, ...tail],
      [state, vm, ...tail],
      [state, ...tail],
      tail.length ? tail : [state],
    ];
    for (const parts of candidates) {
      const text = parts.filter(Boolean).join(" · ");
      if (text.length <= limit) return text;
    }
    return (tail.length ? tail : [state]).join(" · ");
  }

  function topoKey(tree) {
    const nodes = Object.values(tree.nodes || {});
    return nodes.map((n) => [
      n.id, n.parent || "", n.state || "", n.protected ? 1 : 0,
      (n.children || []).join(","),
      ((tree.latencies || {})[n.id] || {}).latency_ms,
    ].join(":")).join("|");
  }

  function ensurePane(tree) {
    let pane = panes.get(tree.tree_id);
    if (pane) return pane;
    const wrap = document.createElement("div");
    wrap.className = "pane";
    wrap.dataset.tree = tree.tree_id;
    const bar = document.createElement("div");
    bar.className = "pane-tools";
    const head = document.createElement("button");
    head.type = "button";
    head.className = "pane-title";
    const max = document.createElement("button");
    max.type = "button";
    max.className = "pane-max";
    max.textContent = "fill view";
    max.title = "show only this tree";
    max.hidden = true;
    const hint = document.createElement("div");
    hint.className = "pane-hint";
    hint.textContent = "waiting for nodes";
    const svg = document.createElementNS(SVGNS, "svg");
    const layers = {};
    for (const name of ["edges", "chips", "ghosts", "nodes"]) {
      const g = document.createElementNS(SVGNS, "g");
      layers[name] = g;
      svg.appendChild(g);
    }
    bar.append(head, max);
    wrap.append(bar, svg, hint);
    wrap.addEventListener("click", () => {
      if (selectedTree === tree.tree_id) return;
      focusTree(tree.tree_id, { clear: true });
    });
    $("panes").appendChild(wrap);
    pane = {
      treeId: tree.tree_id, wrap, svg, hint, head, max, layers,
      nodeEls: new Map(), edgeEls: new Map(), chipEls: new Map(),
      positions: new Map(), topo: "", nodeCount: 0,
    };
    panes.set(tree.tree_id, pane);
    head.addEventListener("click", (ev) => {
      ev.stopPropagation();
      if (selectedTree === tree.tree_id) return;
      focusTree(tree.tree_id, { clear: false });
    });
    max.addEventListener("click", (ev) => {
      ev.stopPropagation();
      focusTree(tree.tree_id, { fill: true, clear: false });
    });
    return pane;
  }

  function multiTree() {
    return Object.keys(state.trees || {}).length >= 2;
  }

  function focusTree(id, opts) {
    opts = opts || {};
    if (opts.fill) {
      splitMode = false;
      for (const pane of panes.values()) pane.topo = "";
    }
    if (selectedTree !== id) {
      selectedTree = id;
      if (opts.clear) {
        selected = null;
        selectedCid = null;
      }
      drawerSig = "";
      ladderSig = "";
    }
    showFocused();
    const tree = (state.trees || {})[id];
    if (tree) reconcileGraph(tree);
  }

  function markFocus() {
    const focus = (currentTree() || {}).tree_id;
    const split = splitMode && multiTree();
    const box = $("panes");
    if (box) box.classList.toggle("split", split);
    const toggle = $("layout-split");
    if (toggle) {
      toggle.hidden = !multiTree();
      toggle.classList.toggle("on", split);
      toggle.title = split ? "show one tree" : "show both trees at once";
    }
    for (const [id, pane] of panes) {
      const show = split || id === focus;
      const wasOff = pane.wrap.classList.contains("off");
      pane.wrap.classList.toggle("off", !show);
      pane.wrap.classList.toggle("focus", split && id === focus);
      if (pane.max) pane.max.hidden = !split;
      if (wasOff && show) pane.topo = "";
    }
    for (const btn of document.querySelectorAll("#trees button")) {
      btn.classList.toggle("on", btn.dataset.id === focus);
    }
  }

  function flashKey(treeId, nodeId) {
    return `${treeId}\n${nodeId}`;
  }

  function patchNodeTexts(pane, tree) {
    // Metrics-only path. Do not touch transform, class, or layout —
    // twenty-plus VMs repaint this several times a second.
    const nodes = Object.values(tree.nodes || {});
    const m = metrics(nodes.length);
    for (const n of nodes) {
      const g = pane.nodeEls.get(n.id);
      if (!g) return false;
      const cpu = cpuText(tree, n.id);
      const meta = g._meta || (g._meta = g.querySelector(".meta"));
      const text = nodeBits(tree, n, labelRoom(m, cpu));
      if (meta.textContent !== text) meta.textContent = text;
      placeCpu(g, m, cpu, cpuTip(tree, n.id), n.protected && n.state !== "pruned");
    }
    return true;
  }

  function setSvgLabel(el, text, tip) {
    const shown = `${tip || ""}\n${text || ""}`;
    if (el.dataset.shown === shown) return;
    el.dataset.shown = shown;
    el.replaceChildren();
    if (tip) {
      const title = document.createElementNS(SVGNS, "title");
      title.textContent = tip;
      el.appendChild(title);
    }
    if (text) el.appendChild(document.createTextNode(text));
  }

  function placeCpu(g, m, text, tip, shielded) {
    const el = g._cpu || (g._cpu = g.querySelector(".cpu"));
    const bg = g._cpuBg || (g._cpuBg = g.querySelector(".cpu-bg"));
    if (!el || !bg) return;
    setSvgLabel(el, text, tip);
    if (!text) {
      bg.setAttribute("width", "0");
      return;
    }
    const w = Math.ceil(text.length * 5.4 + 8);
    const x = m.boxW - w - (shielded ? 18 : 5);
    bg.setAttribute("x", x);
    bg.setAttribute("y", 3);
    bg.setAttribute("width", w);
    bg.setAttribute("height", 13);
    bg.setAttribute("rx", 3);
    el.setAttribute("x", x + w - 4);
    el.setAttribute("y", 12.5);
  }

  function shieldPath(x, y, s) {
    // small shield glyph, s ≈ height
    const w = s * 0.82;
    return `M${x},${y} h${w} v${s * 0.45} q0,${s * 0.4} -${w / 2},${s * 0.55} q-${w / 2},-${s * 0.15} -${w / 2},-${s * 0.55} z`;
  }

  function makeNodeEl(n, m, treeId) {
    const g = document.createElementNS(SVGNS, "g");
    g.dataset.id = n.id;
    const box = document.createElementNS(SVGNS, "rect");
    box.setAttribute("class", "box");
    box.setAttribute("width", m.boxW);
    box.setAttribute("height", m.boxH);
    box.setAttribute("rx", 7);
    const ring = document.createElementNS(SVGNS, "rect");
    ring.setAttribute("class", "glowring");
    ring.setAttribute("x", -2); ring.setAttribute("y", -2);
    ring.setAttribute("width", m.boxW + 4);
    ring.setAttribute("height", m.boxH + 4);
    ring.setAttribute("rx", 9);
    ring.setAttribute("fill", "none");
    const bar = document.createElementNS(SVGNS, "rect");
    bar.setAttribute("class", "bar");
    bar.setAttribute("x", 0); bar.setAttribute("y", 0);
    bar.setAttribute("width", 3.5); bar.setAttribute("height", m.boxH);
    const lbl = document.createElementNS(SVGNS, "text");
    lbl.setAttribute("class", "lbl");
    lbl.setAttribute("x", 11); lbl.setAttribute("y", m.boxH * 0.42);
    const meta = document.createElementNS(SVGNS, "text");
    meta.setAttribute("class", "meta");
    meta.setAttribute("x", 11); meta.setAttribute("y", m.boxH * 0.78);
    const cpuBg = document.createElementNS(SVGNS, "rect");
    cpuBg.setAttribute("class", "cpu-bg");
    cpuBg.setAttribute("width", 0);
    cpuBg.setAttribute("height", 13);
    cpuBg.setAttribute("rx", 3);
    const cpu = document.createElementNS(SVGNS, "text");
    cpu.setAttribute("class", "cpu");
    cpu.setAttribute("text-anchor", "end");
    cpu.setAttribute("x", m.boxW - 8);
    cpu.setAttribute("y", 12);
    const shield = document.createElementNS(SVGNS, "path");
    shield.setAttribute("class", "shield");
    shield.setAttribute("d", shieldPath(m.boxW - 17, 6, 12));
    shield.setAttribute("fill", "var(--prot)");
    shield.setAttribute("visibility", "hidden");
    g.append(box, ring, bar, lbl, meta, cpuBg, cpu, shield);
    g._meta = meta;
    g._cpu = cpu;
    g._cpuBg = cpuBg;
    g.addEventListener("click", (ev) => {
      ev.stopPropagation();
      selectedTree = treeId;
      selectNode(n.id);
    });
    return g;
  }

  function reconcileGraph(tree) {
    if (!tree) return;
    const pane = ensurePane(tree);
    if (pane.wrap.classList.contains("off")) {
      if (pane.nodeEls.size && pane.topo === topoKey(tree)) patchNodeTexts(pane, tree);
      return;
    }
    const key = topoKey(tree);
    if (pane.topo === key && patchNodeTexts(pane, tree)) {
      pane.head.textContent = `${tree.tree_id}  ×${treeFactor(tree)}`;
      return;
    }
    const nodeEls = pane.nodeEls;
    const edgeEls = pane.edgeEls;
    const chipEls = pane.chipEls;
    const positions = pane.positions;
    const svg = pane.svg;
    const nodes = Object.values(tree.nodes || {});
    const grew = nodes.length > pane.nodeCount;
    const hint = pane.hint;
    hint.style.display = nodes.length ? "none" : "flex";
    const { byId, laneOf, depth, maxD } = layout(nodes);
    const m = metrics(nodes.length);
    const lanes = Math.max(0, ...Object.values(laneOf)) + 1;
    const wrap = svg.parentElement;
    const contentW = 60 + (maxD + 1) * m.colW;
    const contentH = 54 + lanes * m.rowH;
    const availW = wrap.clientWidth - 4;
    const availH = wrap.clientHeight - 4;
    // zoom-to-fit: small trees fill the hero (capped so 2 nodes don't
    // become billboards); big trees zoom out to a floor, then scroll
    const scale = Math.max(
      0.62, Math.min(1.75, availW / contentW, availH / contentH));
    if (scale > 1) {
      const vbW = availW / scale;
      const vbH = availH / scale;
      svg.setAttribute("width", availW);
      svg.setAttribute("height", availH);
      svg.setAttribute(
        "viewBox",
        `${-(vbW - contentW) / 2} ${-(vbH - contentH) / 2} ${vbW} ${vbH}`);
    } else if (scale < 1 && contentW <= availW / scale && contentH <= availH / scale) {
      const vbW = availW / scale;
      const vbH = availH / scale;
      svg.setAttribute("width", availW);
      svg.setAttribute("height", availH);
      svg.setAttribute(
        "viewBox",
        `${-(vbW - contentW) / 2} ${-(vbH - contentH) / 2} ${vbW} ${vbH}`);
    } else {
      const W = Math.max(availW, contentW);
      const H = Math.max(availH, contentH);
      svg.setAttribute("width", W);
      svg.setAttribute("height", H);
      svg.setAttribute("viewBox", `0 0 ${W} ${H}`);
    }
    const xOf = (id) => 34 + (depth[id] || 0) * m.colW;
    const yOf = (id) => 30 + (laneOf[id] || 0) * m.rowH;

    const cur = new Set(nodes.map((n) => n.id));

    // exits → ghosts
    for (const [id, g] of [...nodeEls]) {
      if (cur.has(id)) continue;
      const pos = positions.get(id);
      spawnGhost(pane, id, pos, g.dataset.label || id);
      g.remove();
      nodeEls.delete(id);
      positions.delete(id);
      const e = edgeEls.get(id);
      if (e) { e.classList.add("exit"); setTimeout(() => e.remove(), 800); edgeEls.delete(id); }
      const c = chipEls.get(id);
      if (c) { c.remove(); chipEls.delete(id); }
    }

    // nodes
    for (const n of nodes) {
      const x = xOf(n.id);
      const y = yOf(n.id);
      let g = nodeEls.get(n.id);
      const isNew = !g;
      if (isNew) {
        g = makeNodeEl(n, m, tree.tree_id);
        nodeEls.set(n.id, g);
        pane.layers.nodes.appendChild(g);
        const p = n.parent && positions.get(n.parent);
        g.style.transform = p
          ? `translate(${p.x + 14}px, ${p.y}px) scale(0.55)`
          : `translate(${x}px, ${y}px) scale(0.75)`;
        g.style.opacity = "0";
        // force layout so the transition below animates from the parent
        g.getBoundingClientRect();
      }
      // size refresh (metric tier can change as the tree grows)
      const box = g.querySelector(".box");
      if (Number(box.getAttribute("width")) !== m.boxW) {
        box.setAttribute("width", m.boxW); box.setAttribute("height", m.boxH);
        const ring = g.querySelector(".glowring");
        ring.setAttribute("width", m.boxW + 4); ring.setAttribute("height", m.boxH + 4);
        g.querySelector(".bar").setAttribute("height", m.boxH);
        g.querySelector(".lbl").setAttribute("y", m.boxH * 0.42);
        g.querySelector(".meta").setAttribute("y", m.boxH * 0.78);
        g.querySelector(".shield").setAttribute("d", shieldPath(m.boxW - 17, 6, 12));
      }
      g.style.transform = `translate(${x}px, ${y}px) scale(1)`;
      g.style.opacity = "1";
      positions.set(n.id, { x, y, w: m.boxW, h: m.boxH });
      const err = (tree.errors || {})[n.id];
      const stateName = n.state === "pruned"
        ? "pruned" : n.protected ? "protected" : (n.state || "live");
      g.setAttribute("class", [
        "node", stateName,
        err ? "err" : "",
        pane.treeId === selectedTree && selected === n.id ? "sel" : "",
        Date.now() - (lastFlash[flashKey(tree.tree_id, n.id)] || 0) < 900 ? "flash" : "",
      ].join(" "));
      g.dataset.label = n.label || n.id;
      const cpuShown = cpuText(tree, n.id);
      const lbl = g.querySelector(".lbl");
      const maxChars = labelRoom(m, cpuShown);
      lbl.textContent = (n.state === "pruned" ? "✕ " : "")
        + (n.label || n.id).slice(0, maxChars);
      const meta = g.querySelector(".meta");
      meta.textContent = nodeBits(tree, n, maxChars);
      placeCpu(g, m, cpuShown, cpuTip(tree, n.id), n.protected && n.state !== "pruned");
      g.querySelector(".shield").setAttribute(
        "visibility",
        n.protected && n.state !== "pruned" ? "visible" : "hidden");
    }

    // edges + latency chips
    for (const n of nodes) {
      const p = n.parent && byId[n.parent];
      if (!p) continue;
      const a = positions.get(p.id);
      const b = positions.get(n.id);
      if (!a || !b) continue;
      const x1 = a.x + a.w, y1 = a.y + a.h / 2, x2 = b.x, y2 = b.y + b.h / 2;
      const mid = (x1 + x2) / 2;
      const d = `M${x1},${y1} C${mid},${y1} ${mid},${y2} ${x2},${y2}`;
      let e = edgeEls.get(n.id);
      if (!e) {
        e = document.createElementNS(SVGNS, "path");
        edgeEls.set(n.id, e);
        pane.layers.edges.appendChild(e);
        const len = Math.hypot(x2 - x1, y2 - y1) + 60;
        e.setAttribute("stroke-dasharray", len);
        e.style.setProperty("--len", len);
        e.setAttribute("class", "edge enter");
        setTimeout(() => { e.classList.remove("enter"); e.removeAttribute("stroke-dasharray"); }, 600);
      }
      e.setAttribute("d", d);
      e.classList.toggle("to-protected", !!n.protected && n.state !== "pruned");
      e.classList.toggle("to-pruned", n.state === "pruned");

      const lat = (tree.latencies || {})[n.id];
      if (lat && lat.latency_ms != null) {
        let c = chipEls.get(n.id);
        if (!c) {
          c = document.createElementNS(SVGNS, "g");
          const r = document.createElementNS(SVGNS, "rect");
          r.setAttribute("height", 14); r.setAttribute("rx", 4);
          const t = document.createElementNS(SVGNS, "text");
          t.setAttribute("text-anchor", "middle");
          c.append(r, t);
          chipEls.set(n.id, c);
          pane.layers.chips.appendChild(c);
        }
        const text = fmtMs(lat.latency_ms);
        const w = text.length * 6.4 + 10;
        // point at t on the cubic — near the child so fan-out chips spread
        const tt = 0.74;
        const bez = (p0, p1, p2, p3) => {
          const u = 1 - tt;
          return u * u * u * p0 + 3 * u * u * tt * p1 + 3 * u * tt * tt * p2 + tt * tt * tt * p3;
        };
        const cx = bez(x1, mid, mid, x2);
        const cy = bez(y1, y1, y2, y2) - 11;
        c.setAttribute("class", [
          "chip",
          Number(lat.latency_ms) >= 1500 ? "slow" : "",
          n.state === "pruned" ? "dim" : "",
        ].filter(Boolean).join(" "));
        const r = c.querySelector("rect");
        r.setAttribute("x", cx - w / 2); r.setAttribute("y", cy - 8);
        r.setAttribute("width", w);
        const t = c.querySelector("text");
        t.setAttribute("x", cx); t.setAttribute("y", cy + 3);
        t.textContent = text;
      }
    }

    pane.topo = key;
    pane.nodeCount = nodes.length;
    pane.head.textContent = `${tree.tree_id}  ×${treeFactor(tree)}`;
    // Instant jump when the tree grows. Smooth scroll on every metrics
    // tick is what makes 20 VMs feel late.
    if (grew && wrap.scrollWidth > wrap.clientWidth + 24) {
      wrap.scrollLeft = wrap.scrollWidth;
    }
  }

  function spawnGhost(pane, id, pos, label) {
    if (!pos) return;
    const g = document.createElementNS(SVGNS, "g");
    g.setAttribute("class", "ghost prune");
    g.style.transformOrigin = `${pos.x + pos.w / 2}px ${pos.y + pos.h / 2}px`;
    const r = document.createElementNS(SVGNS, "rect");
    r.setAttribute("x", pos.x); r.setAttribute("y", pos.y);
    r.setAttribute("width", pos.w); r.setAttribute("height", pos.h);
    r.setAttribute("rx", 7);
    const t = document.createElementNS(SVGNS, "text");
    t.setAttribute("x", pos.x + 10); t.setAttribute("y", pos.y + pos.h / 2 + 4);
    t.textContent = `${label} ✕`;
    g.append(r, t);
    pane.layers.ghosts.appendChild(g);
    setTimeout(() => g.remove(), 1150);
  }

  /* ---------- toast ---------- */

  function toast(text, klass) {
    toastQ.push({ text, klass });
    if (toastQ.length > 4) toastQ.shift();
    pumpToast();
  }

  function pumpToast() {
    if (toastBusy || !toastQ.length) return;
    toastBusy = true;
    const { text, klass } = toastQ.shift();
    const el = $("toast");
    el.textContent = text;
    el.className = `toast ${klass}`;
    el.hidden = false;
    setTimeout(() => {
      el.hidden = true;
      toastBusy = false;
      pumpToast();
    }, 1900);
  }

  /* ---------- gauges + chart ---------- */

  function setGauge(fillId, numId, num, den, numText) {
    const pct = den > 0 ? Math.min(100, (num / den) * 100) : 0;
    const fill = $(fillId);
    fill.style.width = `${pct}%`;
    fill.className = pct >= 97 ? "hot" : pct >= 85 ? "warn" : "";
    $(numId).innerHTML = numText;
    return pct;
  }

  function renderGauges(tree) {
    if (!tree) return;
    const u = tree.usage || {};
    const b = tree.budget || {};
    const sig = [
      tree.tree_id, u.live_vm_count, u.live_ram_bytes, u.disk_bytes,
      b.max_live_vms, b.max_live_ram_bytes, b.max_disk_bytes,
    ].join("|");
    if (sig === gaugeSig) return;
    gaugeSig = sig;
    const vms = u.live_vm_count || 0;
    const ram = u.live_ram_bytes || 0;
    const disk = u.disk_bytes || 0;
    const vmMax = b.max_live_vms || 0;
    const ramMax = b.max_live_ram_bytes || 0;
    const diskMax = b.max_disk_bytes || 0;
    const p1 = setGauge("vms-fill", "vms-num", vms, vmMax,
      `${vms}<span class="cap"> / ${vmMax || "∞"}</span>`);
    const p2 = setGauge("ram-fill", "ram-num", ram, ramMax,
      `${fmtBytes(ram)}<span class="cap"> / ${ramMax ? fmtBytes(ramMax) : "∞"}</span>`);
    setGauge("disk-fill", "disk-num", disk, diskMax,
      `${fmtBytes(disk)}<span class="cap"> / ${diskMax ? fmtBytes(diskMax) : "∞"}</span>`);
    const hottest = Math.max(p1, p2);
    $("g-vms").classList.toggle("pressure", p1 >= 97);
    $("g-ram").classList.toggle("pressure", p2 >= 97);
    const hr = $("headroom");
    if (vmMax || ramMax) {
      hr.innerHTML =
        `headroom <b>${Math.max(0, vmMax - vms)} vms</b> · ` +
        `<b>${fmtBytes(Math.max(0, ramMax - ram))}</b> ram — ` +
        `evictions fire past the budget line`;
    } else {
      hr.textContent = "no TreeBudget reported";
    }
    const tid = tree.tree_id;
    if (hottest >= 85 && !pressureLatch[tid]) {
      pressureLatch[tid] = true;
      toast(`budget pressure — ${hottest.toFixed(0)}% of ${p1 >= p2 ? "vm" : "ram"} budget`, "evict");
    } else if (hottest < 70) {
      pressureLatch[tid] = false;
    }
  }

  function sampleHistory() {
    const tree = currentTree();
    if (!tree) return;
    const u = tree.usage || {};
    const b = tree.budget || {};
    const h = (history[tree.tree_id] ||= []);
    h.push({
      t: Date.now(),
      vms: u.live_vm_count || 0,
      ram: u.live_ram_bytes || 0,
      vmMax: b.max_live_vms || 0,
      ramMax: b.max_live_ram_bytes || 0,
    });
    if (h.length > 480) h.splice(0, h.length - 480);
  }

  function drawChart() {
    const c = $("chart");
    const tree = currentTree();
    if (!c || !c.getContext) return;
    const dpr = window.devicePixelRatio || 1;
    const cssW = c.clientWidth || 300;
    const cssH = 132;
    if (c.width !== cssW * dpr) { c.width = cssW * dpr; c.height = cssH * dpr; }
    const ctx = c.getContext("2d");
    ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
    ctx.clearRect(0, 0, cssW, cssH);
    const h = tree ? history[tree.tree_id] || [] : [];
    if (h.length < 2) return;
    const pad = 6;
    const w = cssW - pad * 2;
    const hh = cssH - pad * 2;
    const x = (i) => pad + (i / (h.length - 1)) * w;
    // normalise to budget when known, else to max seen
    const vmDen = Math.max(1, ...h.map((s) => s.vmMax || 0), ...h.map((s) => s.vms));
    const ramDen = Math.max(1, ...h.map((s) => s.ramMax || 0), ...h.map((s) => s.ram));
    const y = (frac) => pad + hh - Math.min(1.02, frac) * hh;
    // budget line (100 %) + soft line (85 %)
    ctx.strokeStyle = "rgba(244,101,95,0.75)";
    ctx.setLineDash([5, 4]);
    ctx.lineWidth = 1;
    ctx.beginPath(); ctx.moveTo(pad, y(1)); ctx.lineTo(pad + w, y(1)); ctx.stroke();
    ctx.strokeStyle = "rgba(245,192,74,0.28)";
    ctx.beginPath(); ctx.moveTo(pad, y(0.85)); ctx.lineTo(pad + w, y(0.85)); ctx.stroke();
    ctx.setLineDash([]);
    const series = [
      { get: (s) => s.vms / vmDen, color: "#b7f04d", fill: "rgba(183,240,77,0.10)" },
      { get: (s) => s.ram / ramDen, color: "#53d8e8", fill: "rgba(83,216,232,0.07)" },
    ];
    for (const sr of series) {
      ctx.beginPath();
      h.forEach((s, i) => {
        const yy = y(sr.get(s));
        if (i === 0) ctx.moveTo(x(i), yy);
        else { ctx.lineTo(x(i), y(sr.get(h[i - 1]))); ctx.lineTo(x(i), yy); }
      });
      ctx.strokeStyle = sr.color;
      ctx.lineWidth = 1.6;
      ctx.stroke();
      ctx.lineTo(x(h.length - 1), y(0));
      ctx.lineTo(x(0), y(0));
      ctx.closePath();
      ctx.fillStyle = sr.fill;
      ctx.fill();
    }
  }

  /* ---------- incident timeline ---------- */

  const BEAT_CLASS = {
    inject: "alarm", incident: "alarm", evict: "alarm", prune: "alarm",
    protect: "gold", remediate: "gold", verified: "gold", verify: "gold",
  };

  function derivedBeats(tree) {
    // fallback when no explicit beat ingest exists (run_scenario runs)
    const out = [];
    const seen = new Set();
    const add = (name, ts) => {
      if (!name || seen.has(name)) return;
      seen.add(name);
      out.push({ name, ts_unix_ms: ts, tree_id: tree.tree_id });
    };
    for (const e of state.events || []) {
      if (e.tree_id !== tree.tree_id) continue;
      const ts = e.ts_unix_ms;
      switch (e.op) {
        case "appear":
          add(e.parent_id ? "fork" : "boot", ts);
          break;
        case "note":
          if (/incident injected/i.test(e.text || "")) add("inject", ts);
          break;
        case "protect": add("protect", ts); break;
        case "suspend": add("park", ts); break;
        case "evict": add("evict", ts); break;
        case "prune": add("prune", ts); break;
        case "run":
          if (e.label === "scoring") add("score", ts);
          if (e.label === "evicting") add("evict-pass", ts);
          break;
        default: break;
      }
    }
    return out;
  }

  function renderTimeline(tree) {
    const box = $("timeline");
    if (!tree) {
      if (timelineSig !== "|none") {
        timelineSig = "|none";
        box.innerHTML = `<span class="timeline-empty">incident timeline — waiting for a run</span>`;
      }
      return;
    }
    const explicit = (state.beats || []).filter((b) => b.tree_id === tree.tree_id);
    const names = new Set(explicit.map((b) => b.name));
    // merge: explicit bridge beats + derived firsts (e.g. "inject" from the
    // harness note) — dedupe by name, chronological
    let beats = [...explicit];
    for (const d of derivedBeats(tree)) {
      if (!names.has(d.name)) { names.add(d.name); beats.push(d); }
    }
    beats.sort((a, b) => (a.ts_unix_ms || 0) - (b.ts_unix_ms || 0));
    if (!beats.length) {
      const empty = `${tree.tree_id}|empty`;
      if (timelineSig !== empty) {
        timelineSig = empty;
        box.innerHTML = `<span class="timeline-empty">incident timeline — waiting for a run</span>`;
      }
      return;
    }
    beats = beats.slice(-12);
    const running = (state.run || {}).phase && state.run.phase !== "idle";
    const sig = tree.tree_id + "|" + (running ? 1 : 0) + "|" +
      beats.map((b) => `${b.name}:${b.ts_unix_ms}`).join(",");
    if (sig === timelineSig) return;
    timelineSig = sig;
    box.replaceChildren();
    beats.forEach((b, i) => {
      const el = document.createElement("div");
      const last = i === beats.length - 1;
      const extra = BEAT_CLASS[b.name] || "";
      el.className = `beat ${last && running ? "active" : "done"} ${extra}`;
      el.innerHTML =
        `<span class="dot"></span>` +
        `<span class="tag"><b>${esc(b.name)}</b><span>${relT(b.tree_id, b.ts_unix_ms)}</span></span>` +
        (last ? "" : `<span class="link"></span>`);
      box.appendChild(el);
    });
    box.scrollLeft = box.scrollWidth;
  }

  /* ---------- branch tiles ---------- */

  function tilesKey(tree) {
    if (!tree) return "";
    return tree.tree_id + "|" + Object.values(tree.nodes || {}).map((n) => {
      const v = (tree.verdicts || {})[n.id];
      return [
        n.id, n.state, n.protected ? 1 : 0, n.label,
        ((tree.latencies || {})[n.id] || {}).latency_ms,
        (tree.notes || {})[n.id] || "",
        (tree.errors || {})[n.id] || "",
        v ? `${v.clean}:${v.branch_only}:${v.source_only}` : "",
        ((tree.traces || {})[n.id] || []).length,
      ].join(":");
    }).join("|");
  }

  function syncTileBadges(el, tree, n) {
    const header = el.querySelector("header");
    if (!header) return;
    const f = nodeFactor(tree, n.id);
    let rate = el.querySelector(".xn.rate");
    if (f === 1) {
      if (rate) rate.remove();
    } else if (rate) {
      const text = `×${f}`;
      if (rate.textContent !== text) rate.textContent = text;
    } else {
      rate = document.createElement("span");
      rate.className = "xn rate";
      rate.textContent = `×${f}`;
      header.appendChild(rate);
    }
    const cpu = cpuText(tree, n.id);
    const tip = cpuTip(tree, n.id);
    let badge = el.querySelector(".xn.cpu");
    if (!cpu) {
      if (badge) badge.remove();
    } else if (badge) {
      if (badge.textContent !== cpu) badge.textContent = cpu;
      if (badge.title !== tip) badge.title = tip;
    } else {
      badge = document.createElement("span");
      badge.className = "xn cpu";
      badge.textContent = cpu;
      badge.title = tip;
      header.appendChild(badge);
    }
  }

  function renderTiles(tree) {
    const box = $("tiles");
    if (!tree) { box.replaceChildren(); tileSigCache = ""; return; }
    const key = tilesKey(tree);
    if (key === tileSigCache) {
      box.querySelectorAll(".tile").forEach((el) => {
        const n = (tree.nodes || {})[el.dataset.id];
        if (!n) return;
        syncTileBadges(el, tree, n);
      });
      return;
    }
    tileSigCache = key;
    const nodes = Object.values(tree.nodes || {});
    const root = nodes.filter((n) => !n.parent);
    // stable camera order: creation order, root pinned first; newest kept
    // when over the cap
    let rest = nodes.filter((n) => n.parent).sort((a, b) =>
      (a.created_at_unix || 0) - (b.created_at_unix || 0) ||
      String(a.id).localeCompare(String(b.id)));
    // over the cap: shed oldest pruned tombstones before live branches
    if (rest.length > 13) {
      let drop = rest.length - 13;
      rest = rest.filter((n) => {
        if (drop > 0 && n.state === "pruned") { drop--; return false; }
        return true;
      });
    }
    const show = [...root, ...rest.slice(-13)].slice(0, 14);
    box.replaceChildren();
    for (const n of show) {
      const el = document.createElement("div");
      const err = (tree.errors || {})[n.id];
      const pruned = n.state === "pruned";
      const stateName = pruned
        ? "pruned" : n.protected ? "protected" : (n.state || "live");
      el.dataset.id = n.id;
      el.className = [
        "tile",
        pruned ? "pruned" : "",
        n.protected && !pruned ? "prot" : "",
        err ? "errored" : "",
        Date.now() - (lastFlash[flashKey(tree.tree_id, n.id)] || 0) < 900 ? "flash" : "",
      ].join(" ");
      const lat = (tree.latencies || {})[n.id];
      const note = (tree.notes || {})[n.id] || "";
      const cmd = (tree.cmds || {})[n.id];
      const verdict = (tree.verdicts || {})[n.id];
      const traces = (tree.traces || {})[n.id] || [];
      const lastTrace = traces[traces.length - 1];
      // Tetragon diff vs the fork source. Ingest posts it; an unscored
      // branch has nothing to show, so the card stays a node summary.
      let vHtml = "";
      if (verdict) {
        if (verdict.clean) {
          vHtml = `<span class="verdict clean">✓ tetragon clean vs source</span>`;
        } else if (verdict.branch_only > 0) {
          vHtml = `<span class="verdict suspicious">▲ ${verdict.branch_only} new event${verdict.branch_only === 1 ? "" : "s"} on branch</span>`;
        } else {
          vHtml = `<span class="verdict clean">✓ ${verdict.source_only} suspicious event${verdict.source_only === 1 ? "" : "s"} gone</span>`;
        }
      }
      const rate = nodeFactor(tree, n.id);
      const cpu = cpuText(tree, n.id);
      el.innerHTML =
        `<header><span class="dot ${stateName}"></span>` +
        `<h3>${pruned ? "✕ " : ""}${esc(n.label || n.id)}</h3>` +
        (rate !== 1 ? `<span class="xn rate">×${rate}</span>` : "") +
        (cpu ? `<span class="xn cpu" title="${esc(cpuTip(tree, n.id))}">${esc(cpu)}</span>` : "") +
        (lat && lat.latency_ms != null ? `<span class="ms">⑂ ${fmtMs(lat.latency_ms)}</span>` : "") +
        `</header>` +
        vHtml +
        (note ? `<div class="note" title="${esc(note)}">${esc(note)}</div>` : "") +
        (cmd ? `<div class="cmd${cmd.destructive ? " boom" : ""}" title="${esc(cmd.cmd)}">${esc(cmd.cmd)}</div>` : "") +
        (err ? `<div class="cmd boom">${esc(err)}</div>` : "") +
        (lastTrace
          ? `<div class="trace${n.state === "live" ? " stream" : ""}">${esc(lastTrace.role)}: ${esc(lastTrace.text)}</div>`
          : "");
      el.addEventListener("click", () => selectNode(n.id));
      box.appendChild(el);
    }
  }

  /* ---------- feeds ---------- */

  function renderMeta() {
    const box = $("meta-feed");
    const rows = (state.meta || []).slice(-14).reverse();
    const sig = rows.map((r) => `${r.ts_unix_ms}:${r.action}:${r.text}`).join("|");
    if (sig === metaSig && box.childElementCount) return;
    metaSig = sig;
    if (!rows.length) {
      box.innerHTML = `<span class="empty">waiting for decisions</span>`;
      return;
    }
    box.innerHTML = rows.map((r) =>
      `<div class="row${r.action === "think" ? " think" : ""} op-${esc(r.action)}">` +
      `<span class="t">${relT(r.tree_id, r.ts_unix_ms)}</span>` +
      `<span class="txt"><b>${esc(r.action || "decide")}</b> ${esc(r.text || r.node_id || "")}</span></div>`
    ).join("");
  }

  const FEED_SKIP = new Set(["tick", "trace", "members", "budget", "state", "guest_clock"]);

  function renderEvents() {
    const box = $("events");
    const evs = (state.events || []).filter((e) => !FEED_SKIP.has(e.op)).slice(-34).reverse();
    const sig = evs.map((e) => e.seq).join(",");
    if (sig === eventSig && box.childElementCount) return;
    eventSig = sig;
    if (!evs.length) {
      box.innerHTML = `<span class="empty">waiting for events</span>`;
      return;
    }
    box.innerHTML = evs.map((e) => {
      const what = e.text || e.reason || e.label || e.node_id || e.tree_id || "";
      return `<div class="row op-${esc(e.op)}">` +
        `<span class="t">${relT(e.tree_id, e.ts_unix_ms)}</span>` +
        `<span class="txt"><b>${esc(e.op)}</b> ${esc(String(what).slice(0, 90))}</span></div>`;
    }).join("");
  }

  /* ---------- header ---------- */

  function renderHeader(tree) {
    const titled = tree && (TITLES[tree.tree_id] || (state.run && state.run.tree_id === tree.tree_id && state.run.goal));
    $("goal").textContent = titled || (tree ? tree.tree_id : "waiting for a tree");
    const phase = (state.run && state.run.phase) || "idle";
    const ph = $("phase");
    ph.textContent = phase;
    ph.className = "pill " + (
      phase === "idle" ? "" :
      /evict/.test(phase) ? "bad" :
      /prepar|boot/.test(phase) ? "warn" : "ok");
    if (/^agent-/.test(phase)) armSeen = phase.slice(6);
    const arm = $("arm");
    if (armSeen) {
      arm.hidden = false;
      arm.textContent = `arm: ${armSeen}`;
      arm.className = "pill " + (armSeen === "fork" ? "ok" : "warn");
    }
    const conn = $("conn");
    if (state.connected) {
      conn.textContent = "k7d live · sse";
      conn.className = "pill ok";
    } else {
      conn.textContent = state.error ? "k7d down" : "connecting";
      conn.className = "pill bad";
    }
  }

  function renderTrees() {
    const box = $("trees");
    const ids = Object.keys(state.trees || {});
    const active = currentTree();
    const sig = ids.map((id) => {
      const t = state.trees[id];
      const nodes = Object.keys(t.nodes || {}).length;
      const vms = (t.usage && t.usage.live_vm_count) || 0;
      return `${id}:${nodes}:${vms}:${active && active.tree_id === id ? 1 : 0}`;
    }).join("|");
    if (sig === treeTabSig) return;
    treeTabSig = sig;
    box.replaceChildren();
    for (const id of ids) {
      const t = state.trees[id];
      const nodes = Object.keys(t.nodes || {}).length;
      const vms = (t.usage && t.usage.live_vm_count) || 0;
      const btn = document.createElement("button");
      btn.dataset.id = id;
      btn.className = active && active.tree_id === id ? "on" : "";
      btn.title = `show ${id}`;
      btn.innerHTML =
        `${esc(id)}<span class="n">${nodes} nodes · ${vms} vms</span>`;
      btn.addEventListener("click", () => focusTree(id, { clear: true }));
      box.appendChild(btn);
    }
  }

  function renderClock() {
    const tree = currentTree();
    const el = $("clock");
    const guest = $("guest-clock");
    if (!tree || treeBase(tree.tree_id) == null) {
      el.textContent = "T+00:00";
    } else {
      el.textContent = fmtT(Date.now() - treeBase(tree.tree_id)) || "T+00:00";
    }
    if (guest) guest.textContent = guestClockText(tree);
  }

  /* ---------- drawer ---------- */

  function showFocused() {
    const tree = currentTree();
    markFocus();
    renderHeader(tree);
    renderGauges(tree);
    renderTimeline(tree);
    renderTiles(tree);
    renderClock();
    if (selected) renderDrawer();
    else $("drawer").hidden = true;
  }

  function selectNode(id) {
    selected = selected === id ? null : id;
    selectedCid = null;
    drawerSig = "";
    ladderSig = "";
    for (const pane of panes.values()) {
      for (const [nid, g] of pane.nodeEls) {
        const on = pane.treeId === selectedTree && nid === selected;
        if (g.classList.contains("sel") !== on) g.classList.toggle("sel", on);
      }
    }
    showFocused();
  }

  function closeDrawer() {
    selected = null;
    selectedCid = null;
    drawerSig = "";
    $("drawer").hidden = true;
    for (const pane of panes.values()) {
      for (const g of pane.nodeEls.values()) g.classList.remove("sel");
    }
  }

  function setAct(name, disabled, why) {
    const btn = document.querySelector(`#actions button[data-act="${name}"]`);
    if (!btn) return;
    btn.disabled = disabled;
    btn.title = disabled ? why : "";
  }

  function syncActions(node) {
    if (!node) return;
    const live = node.state === "live";
    const sus = node.state === "suspended";
    const dead = node.state === "pruned" || node.state === "evicted";
    setAct("suspend", !live, "suspend needs a live node");
    setAct("resume", !sus, "resume needs a suspended node");
    setAct("fork", !live || dead, "fork needs a live node");
    setAct("prune", dead, "already gone");
    setAct("protect", !!node.protected || dead, node.protected ? "already protected" : "gone");
    setAct("unprotect", !node.protected || dead, "not protected");
    setAct("auto_evict", false, "");
    const rate = $("rate");
    const adaptive = $("adaptive");
    if (rate && adaptive) rate.disabled = adaptive.checked || !live;
  }

  function ladderOf(tree, node) {
    const stored = ((tree && tree.dilation_ladder) || {})[node.id];
    if (stored && stored.length) return stored.map(Number);
    return [8, 4, 2, 1];
  }

  function paintLadder(tree, node) {
    const box = $("ladder");
    if (!box || !node) return;
    const ladder = ladderOf(tree, node);
    const factor = nodeFactor(tree, node.id);
    const onLadder = ladder.includes(factor);
    const sig = `${tree.tree_id}|${node.id}|${ladder.join(",")}|${factor}|${onLadder ? 1 : 0}`;
    if (sig === ladderSig) return;
    ladderSig = sig;
    box.replaceChildren();
    for (const rung of ladder) {
      const el = document.createElement("i");
      el.textContent = `×${rung}`;
      el.className = onLadder && rung === factor ? "on" : "";
      box.appendChild(el);
    }
    const hint = $("ladder-hint");
    if (hint) {
      hint.textContent = onLadder ? "" : `live ×${factor} is off this ladder`;
    }
  }

  function paintCpu(tree, node) {
    const box = $("cpus");
    if (!box || !node) return;
    const avg = cpuAvg(tree, node.id);
    const rows = cpuRows(tree, node);
    const text = !rows.length
      ? "CPU —"
      : (avg == null ? "CPU —" : `avg ${avg.toFixed(0)}% of vCPUs`) + "  ·  " + rows.map((r) => {
        const pct = r.cpu_percent == null ? "…" : `${Number(r.cpu_percent).toFixed(0)}%`;
        const n = Number(r.vcpus) || 0;
        return `vm${r.member} ${pct} / ${n} vCPU`;
      }).join("  ·  ");
    if (box.textContent !== text) box.textContent = text;
    const tip = cpuTip(tree, node.id);
    if (box.title !== tip) box.title = tip;
  }

  // Manual ×N does not back off. Adaptive does, from KVM awake-vCPU
  // samples, not from this host-CPU number. Warn when the two disagree.
  function paintHot(tree, node, factor) {
    const el = $("rate-warn");
    if (!el || !node) return;
    const avg = cpuAvg(tree, node.id);
    const hot = factor > 1 && avg != null && avg >= 80;
    el.hidden = !hot;
    if (!hot) return;
    const share = Math.max(1, Math.round(100 / factor));
    el.textContent =
      `×${factor} while host vCPUs are ${avg.toFixed(0)}% busy. ` +
      `Guest time runs ${factor}× wall time, so a saturated guest gets about ${share}% of a CPU per guest-second. ` +
      "Timers and timeouts fire late. Adaptive steps down; a manual rate does not.";
  }

  function paintRate(tree, node) {
    const factor = nodeFactor(tree, node.id);
    if (pendingFactor != null && (factor === pendingFactor || Date.now() > pendingFactorUntil)) {
      pendingFactor = null;
    }
    const shown = pendingFactor != null ? pendingFactor : factor;
    const read = $("rate-read");
    const rate = $("rate");
    if (read) read.textContent = `×${shown}`;
    if (rate && document.activeElement !== rate) rate.value = String(shown);
    const mode = ((tree.dilation_policy || {})[node.id]) || "";
    const adaptive = $("adaptive");
    if (adaptive && document.activeElement !== adaptive) {
      const tracked = mode === "track" || mode === "down";
      if (pendingAdaptive != null && Date.now() > pendingAdaptiveUntil) pendingAdaptive = null;
      if (pendingAdaptive == null) {
        adaptive.checked = tracked;
      } else if (pendingAdaptive === tracked || (pendingAdaptive && mode === "down")) {
        pendingAdaptive = null;
        adaptive.checked = tracked;
      } else {
        adaptive.checked = pendingAdaptive;
      }
    }
    const preset = $("preset");
    const ladder = ((tree.dilation_ladder || {})[node.id]) || [];
    if (preset && document.activeElement !== preset && ladder.length && pendingAdaptive == null) {
      const key = ladder.join(",");
      if (key === "8,4,1") preset.value = "aggressive";
      else if (key === "8,4,2,1") preset.value = "gentle";
    }
  }

  function renderDrawer() {
    const drawer = $("drawer");
    const tree = currentTree();
    const node = tree && selected && (tree.nodes || {})[selected];
    if (!node) { drawer.hidden = true; return; }
    drawer.hidden = false;
    paintLadder(tree, node);
    paintCpu(tree, node);
    paintRate(tree, node);
    paintHot(tree, node, pendingFactor != null ? pendingFactor : nodeFactor(tree, node.id));
    syncActions(node);
    const sig = [
      tree.tree_id,
      node.id, node.state, node.protected ? 1 : 0, node.parent || "",
      ((tree.members || {})[node.id] || []).join(","),
      ((tree.latencies || {})[node.id] || {}).latency_ms,
      (tree.notes || {})[node.id] || "",
      (tree.errors || {})[node.id] || "",
      ((tree.traces || {})[node.id] || []).length,
      ((tree.execs || {})[node.id] || []).length,
    ].join("|");
    const dil = $("kv-dil");
    if (dil) dil.textContent = `×${nodeFactor(tree, node.id)}`;
    if (sig === drawerSig) return;
    drawerSig = sig;
    $("drawer-title").textContent = node.label || node.id;
    const lat = (tree.latencies || {})[node.id] || {};
    const cow = (lat.cow || []).length
      ? (lat.cow.every(Boolean) ? "CoW" : "full-copy") : "—";
    const cids = (tree.members || {})[node.id] || [];
    $("drawer-kv").innerHTML = `
      <b>id</b><span>${esc(node.id)}</span>
      <b>kind</b><span>${esc(node.kind || tree.kind || "cluster")} · ${node.vm_count || 1} vm</span>
      <b>state</b><span>${esc(node.state)}${node.protected ? " · protected" : ""}</span>
      <b>parent</b><span>${esc(node.parent || "—")}</span>
      <b>dirty</b><span>${node.dirty_page_count || 0} pages (${fmtBytes((node.dirty_page_count || 0) * 4096)})</span>
      <b>fork</b><span>${lat.latency_ms != null ? fmtMs(lat.latency_ms) : "—"} · ${cow}</span>
      <b>dilation</b><span id="kv-dil">×${nodeFactor(tree, node.id)}</span>
      <b>cids</b><span>${cids.join(", ") || "—"}</span>`;
    const note = (tree.notes || {})[node.id] || "";
    const err = (tree.errors || {})[node.id] || "";
    $("drawer-note").textContent = note;
    $("drawer-note").hidden = !note;
    $("drawer-err").textContent = err;
    $("drawer-err").hidden = !err;
    const traces = (tree.traces || {})[node.id] || [];
    $("drawer-trace").innerHTML = traces.slice(-10).map((s) =>
      `<div class="row"><span class="txt"><b>${esc(s.role)}</b> ${esc(s.text)}</span></div>`
    ).join("") || `<span class="empty">no spans</span>`;
    const vbox = $("drawer-vms");
    vbox.replaceChildren();
    if (!cids.length) {
      vbox.innerHTML = `<span class="empty">no live cids (suspended or evicted)</span>`;
    }
    cids.forEach((c, i) => {
      const el = document.createElement("div");
      el.className = `vm${String(c) === String(selectedCid) ? " on" : ""}`;
      el.innerHTML = `<b>vm${i}</b> cid ${esc(String(c))}`;
      el.addEventListener("click", () => {
        selectedCid = String(c) === String(selectedCid) ? null : c;
        $("serial-cid").textContent = selectedCid != null ? `cid ${c}` : "";
        if (selectedCid != null) loadSerial(c);
        renderDrawer();
      });
      vbox.appendChild(el);
    });

    // member activity: everything the agent ran on this node's VMs, with
    // output — kubectl get pods / logs land here when the agent ran them.
    // Selecting a vm chip filters to that member. Pure observation: this
    // is replayed from the MCP log, the viewer never execs anything.
    const selIdx = selectedCid != null
      ? cids.findIndex((c) => String(c) === String(selectedCid)) : -1;
    const execs = ((tree.execs || {})[node.id] || [])
      .filter((x) => selIdx < 0 || Number(x.member) === selIdx);
    $("execs-hint").textContent = selIdx >= 0 ? `vm${selIdx} only` : "all members";
    $("drawer-execs").innerHTML = execs.slice(-12).reverse().map((x) => {
      const out = [x.stdout, x.stderr ? `[stderr] ${x.stderr}` : ""]
        .filter(Boolean).join("\n");
      const bad = x.exit_code != null && Number(x.exit_code) !== 0;
      return `<details class="exec${x.destructive ? " boom" : ""}">` +
        `<summary><b>vm${x.member ?? "?"}</b> $ ${esc(x.cmd)}` +
        `<span class="rc${bad ? " bad" : ""}">exit ${x.exit_code ?? "?"}</span>` +
        `</summary><pre>${esc(out || "(no output)")}</pre></details>`;
    }).join("") || `<span class="empty">nothing ran here yet</span>`;
  }

  async function loadSerial(cid) {
    const el = $("serial");
    try {
      const r = await fetch(`/api/serial?cid=${encodeURIComponent(cid)}`);
      const j = await r.json();
      if (j.error) throw new Error(j.error);
      el.textContent = j.console || "(empty console)";
      el.scrollTop = el.scrollHeight;
    } catch (e) {
      el.textContent = String(e);
    }
  }

  function showErr(text) {
    const el = $("drawer-err");
    el.hidden = !text;
    el.textContent = text || "";
    if (text) toast(String(text).slice(0, 140), "evict");
  }

  async function act(op, extra) {
    const tree = currentTree();
    if (!tree) return;
    if (acting) {
      if (op === "set_dilation" || op === "set_dilation_policy") {
        pendingAct = { op, extra };
        if (op === "set_dilation" && extra && extra.factor != null) {
          pendingFactor = Number(extra.factor);
          pendingFactorUntil = Date.now() + 4000;
        }
      }
      return;
    }
    acting = true;
    document.querySelectorAll("#actions button, #fork-btn, #dilate button, #dilate select, #dilate input").forEach((el) => {
      el.dataset.was = el.disabled ? "1" : "0";
      el.disabled = true;
    });
    try {
      const body = Object.assign({
        op,
        tree_id: tree.tree_id,
        node_id: selected || "",
      }, extra || {});
      if (op === "fork") body.n = Number(($("fork-n") || {}).value) || 1;
      const r = await fetch("/api/action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(body),
      });
      const j = await r.json();
      if (j.error) throw new Error(j.error);
      showErr("");
      drawerSig = "";
      tileSigCache = "";
      treeTabSig = "";
    } catch (e) {
      showErr(String(e.message || e));
      if (op === "set_dilation") pendingFactor = null;
      if (op === "set_dilation_policy") pendingAdaptive = null;
    } finally {
      acting = false;
      document.querySelectorAll("#actions button, #fork-btn, #dilate button, #dilate select, #dilate input").forEach((el) => {
        el.disabled = false;
      });
      const node = (currentTree() && currentTree().nodes || {})[selected];
      if (node) syncActions(node);
      const next = pendingAct;
      pendingAct = null;
      if (next) void act(next.op, next.extra);
    }
  }

  /* ---------- event reactions (toasts, flashes) ---------- */

  const TOPO_OPS = new Set(["appear", "prune", "evict", "suspend", "resume", "protect", "unprotect"]);

  function reactToEvents(events) {
    const now = Date.now();
    for (const e of events || []) {
      noteBase(e);
      if (e.node_id && e.tree_id && TOPO_OPS.has(e.op)) {
        lastFlash[flashKey(e.tree_id, e.node_id)] = now;
        flashHot = now + 900;
      }
      if (e.op === "evict") toast(`evicted ${e.label || e.node_id} — over budget`, "evict");
      if (e.op === "protect") toast(`protected ${e.label || e.node_id}`, "protect");
      if (e.op === "prune") toast(`pruned ${e.label || e.node_id}`, "evict");
      if (e.op === "verdict" && e.clean) toast(`tetragon clean — ${e.node_id}`, "info");
      if (e.op === "verdict" && !e.clean && !e.branch_only && e.source_only) {
        toast(`${e.node_id}: ${e.source_only} suspicious events gone`, "info");
      }
      if (e.op === "beat" && e.label === "inject") toast("incident injected", "evict");
    }
  }

  /* ---------- render root ---------- */

  function renderPanes() {
    const ids = new Set(Object.keys(state.trees || {}));
    for (const id of ids) ensurePane(state.trees[id]);
    for (const [id, pane] of [...panes]) {
      if (!ids.has(id)) {
        pane.wrap.remove();
        panes.delete(id);
      }
    }
    markFocus();
    for (const id of ids) reconcileGraph(state.trees[id]);
  }

  function render() {
    const tree = currentTree();
    renderHeader(tree);
    renderTrees();
    renderTimeline(tree);
    renderMeta();
    renderEvents();
    renderGauges(tree);
    renderPanes();
    renderTiles(tree);
    if (selected) renderDrawer();
    renderClock();
  }

  function applyMetrics(msg) {
    state.connected = msg.connected !== false;
    if (msg.error) state.error = msg.error;
    for (const [tid, patch] of Object.entries(msg.trees || {})) {
      const slot = (state.trees || {})[tid];
      if (!slot) continue;
      if (patch.usage) slot.usage = patch.usage;
      if (patch.live_dilation) slot.live_dilation = patch.live_dilation;
      if (patch.live_cpu) slot.live_cpu = patch.live_cpu;
      if (patch.dilation_ladder) slot.dilation_ladder = patch.dilation_ladder;
      if (patch.dilation_policy) slot.dilation_policy = patch.dilation_policy;
      if (patch.dilation_trajectory) slot.dilation_trajectory = patch.dilation_trajectory;
      if (patch.guest_clock) slot.guest_clock = patch.guest_clock;
      const nodes = slot.nodes || {};
      for (const [nid, dirty] of Object.entries(patch.dirty || {})) {
        if (nodes[nid]) nodes[nid].dirty_page_count = dirty;
      }
    }
    markFocus();
    for (const id of Object.keys(state.trees || {})) reconcileGraph(state.trees[id]);
    const tree = currentTree();
    renderTrees();
    renderGauges(tree);
    renderTiles(tree);
    renderClock();
    renderHeader(tree);
    if (selected) renderDrawer();
  }

  function applyState(msg) {
    const evs = msg.events || [];
    if (msg.state) {
      state = msg.state;
      for (const e of state.events || []) noteBase(e);
    }
    reactToEvents(evs);
    if (evs.some((e) => TOPO_OPS.has(e.op) || e.op === "appear" || e.op === "drop" || e.op === "latency")) {
      tileSigCache = "";
      treeTabSig = "";
      drawerSig = "";
    }
    render();
  }

  function apply(msg) {
    pending.push(msg);
    if (!raf) raf = requestAnimationFrame(flushPending);
  }

  function flushPending() {
    raf = 0;
    const batch = pending.splice(0, pending.length);
    let full = null;
    let metric = null;
    for (const msg of batch) {
      if (msg.kind === "metrics") metric = msg;
      else full = msg;
    }
    if (full) applyState(full);
    else if (metric) applyMetrics(metric);
  }

  /* ---------- wiring ---------- */

  document.querySelectorAll("#actions button[data-act]").forEach((btn) => {
    btn.addEventListener("click", () => act(btn.dataset.act));
  });
  const forkBtn = $("fork-btn");
  if (forkBtn) forkBtn.addEventListener("click", () => act("fork"));
  const preset = $("preset");
  const adaptive = $("adaptive");
  const sendPolicy = () => {
    pendingAdaptive = !!(adaptive && adaptive.checked);
    pendingAdaptiveUntil = Date.now() + 4000;
    act("set_dilation_policy", {
      preset: preset ? preset.value : "gentle",
      adaptive: pendingAdaptive,
    });
  };
  if (preset) preset.addEventListener("change", sendPolicy);
  if (adaptive) adaptive.addEventListener("change", sendPolicy);
  const rate = $("rate");
  if (rate) {
    rate.addEventListener("input", () => {
      if (adaptive && adaptive.checked) return;
      pendingFactor = Number(rate.value);
      pendingFactorUntil = Date.now() + 4000;
      const read = $("rate-read");
      if (read) read.textContent = `×${rate.value}`;
    });
    rate.addEventListener("change", () => {
      if (adaptive && adaptive.checked) return;
      pendingFactor = Number(rate.value);
      pendingFactorUntil = Date.now() + 4000;
      act("set_dilation", { factor: pendingFactor });
    });
  }
  const layoutSplit = $("layout-split");
  if (layoutSplit) {
    layoutSplit.addEventListener("click", () => {
      splitMode = !splitMode;
      for (const pane of panes.values()) pane.topo = "";
      renderPanes();
    });
  }
  $("drawer-close").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDrawer();
  });

  fetch("/api/state")
    .then((r) => r.json())
    .then((s) => {
      state = s;
      for (const e of state.events || []) noteBase(e);
      sampleHistory();
      render();
      drawChart();
    })
    .catch(() => {});

  const es = new EventSource("/api/events");
  es.onmessage = (ev) => {
    try {
      apply(JSON.parse(ev.data));
    } catch (_) { /* keepalive */ }
  };
  es.onerror = () => {
    $("conn").textContent = "sse drop";
    $("conn").className = "pill bad";
  };

  setInterval(() => {
    renderClock();
    const now = Date.now();
    if (now > flashHot) return;
    const tree = currentTree();
    for (const [treeId, pane] of panes) {
      for (const [id, g] of pane.nodeEls) {
        const on = now - (lastFlash[flashKey(treeId, id)] || 0) < 900;
        if (g.classList.contains("flash") !== on) g.classList.toggle("flash", on);
      }
    }
    if (!tree) return;
    document.querySelectorAll("#tiles .tile").forEach((el) => {
      const on = now - (lastFlash[flashKey(tree.tree_id, el.dataset.id)] || 0) < 900;
      if (el.classList.contains("flash") !== on) el.classList.toggle("flash", on);
    });
  }, 250);

  setInterval(() => {
    sampleHistory();
    drawChart();
  }, 500);

  serialTimer = setInterval(() => {
    if (selectedCid != null && !$("drawer").hidden) loadSerial(selectedCid);
  }, 400);
  void serialTimer;
})();

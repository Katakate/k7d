/* k7d-view — demo-grade observer .
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

  // keyed svg elements
  const nodeEls = new Map();
  const edgeEls = new Map();
  const chipEls = new Map();
  const positions = new Map(); // node_id -> {x, y, w, h}
  let graphTree = null;        // tree_id the keyed maps belong to

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

  function clearGraph() {
    for (const layer of ["layer-edges", "layer-chips", "layer-ghosts", "layer-nodes"]) {
      $(layer).replaceChildren();
    }
    nodeEls.clear(); edgeEls.clear(); chipEls.clear(); positions.clear();
  }

  function shieldPath(x, y, s) {
    // small shield glyph, s ≈ height
    const w = s * 0.82;
    return `M${x},${y} h${w} v${s * 0.45} q0,${s * 0.4} -${w / 2},${s * 0.55} q-${w / 2},-${s * 0.15} -${w / 2},-${s * 0.55} z`;
  }

  function makeNodeEl(n, m) {
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
    const shield = document.createElementNS(SVGNS, "path");
    shield.setAttribute("class", "shield");
    shield.setAttribute("d", shieldPath(m.boxW - 17, 6, 12));
    shield.setAttribute("fill", "var(--prot)");
    shield.setAttribute("visibility", "hidden");
    g.append(box, ring, bar, lbl, meta, shield);
    g.addEventListener("click", () => { selectNode(n.id); });
    return g;
  }

  function reconcileGraph(tree) {
    const svg = $("graph");
    if (!tree) { clearGraph(); graphTree = null; return; }
    if (graphTree !== tree.tree_id) { clearGraph(); graphTree = tree.tree_id; }
    const nodes = Object.values(tree.nodes || {});
    const hint = $("hero-hint");
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
      spawnGhost(id, pos, g.dataset.label || id);
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
        g = makeNodeEl(n, m);
        nodeEls.set(n.id, g);
        $("layer-nodes").appendChild(g);
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
        selected === n.id ? "sel" : "",
        Date.now() - (lastFlash[n.id] || 0) < 900 ? "flash" : "",
      ].join(" "));
      g.dataset.label = n.label || n.id;
      const lbl = g.querySelector(".lbl");
      const maxChars = Math.floor((m.boxW - 24) / (6.6 * m.f + 0.4));
      lbl.textContent = (n.state === "pruned" ? "✕ " : "")
        + (n.label || n.id).slice(0, maxChars);
      const bits = [n.state || "live"];
      const vmc = n.vm_count || 1;
      bits.push(`${vmc} vm${vmc === 1 ? "" : "s"}`);
      const dirty = (n.dirty_page_count || 0) * 4096;
      if (dirty) bits.push(fmtBytes(dirty));
      const meta = g.querySelector(".meta");
      meta.textContent = bits.join(" · ").slice(0, maxChars + 4);
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
        $("layer-edges").appendChild(e);
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
          $("layer-chips").appendChild(c);
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

    // keep the newest column in view
    if (wrap.scrollWidth > wrap.clientWidth + 24) {
      wrap.scrollTo({ left: wrap.scrollWidth, behavior: "smooth" });
    }
  }

  function spawnGhost(id, pos, label) {
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
    $("layer-ghosts").appendChild(g);
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
      box.innerHTML = `<span class="timeline-empty">incident timeline — waiting for a run</span>`;
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
      box.innerHTML = `<span class="timeline-empty">incident timeline — waiting for a run</span>`;
      return;
    }
    beats = beats.slice(-12);
    const running = (state.run || {}).phase && state.run.phase !== "idle";
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

  function renderTiles(tree) {
    const box = $("tiles");
    if (!tree) { box.replaceChildren(); return; }
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
        Date.now() - (lastFlash[n.id] || 0) < 900 ? "flash" : "",
      ].join(" ");
      const lat = (tree.latencies || {})[n.id];
      const note = (tree.notes || {})[n.id] || "";
      const cmd = (tree.cmds || {})[n.id];
      const verdict = (tree.verdicts || {})[n.id];
      const traces = (tree.traces || {})[n.id] || [];
      const lastTrace = traces[traces.length - 1];
      let vHtml = `<span class="verdict none">tetragon — not scored</span>`;
      if (verdict) {
        if (verdict.clean) {
          vHtml = `<span class="verdict clean">✓ tetragon clean vs source</span>`;
        } else if (verdict.branch_only > 0) {
          vHtml = `<span class="verdict suspicious">▲ ${verdict.branch_only} new event${verdict.branch_only === 1 ? "" : "s"} on branch</span>`;
        } else {
          vHtml = `<span class="verdict clean">✓ ${verdict.source_only} suspicious event${verdict.source_only === 1 ? "" : "s"} gone</span>`;
        }
      }
      el.innerHTML =
        `<header><span class="dot ${stateName}"></span>` +
        `<h3>${pruned ? "✕ " : ""}${esc(n.label || n.id)}</h3>` +
        (nodeFactor(tree, n.id) !== 1 ? `<span class="xn">×${nodeFactor(tree, n.id)}</span>` : "") +
        (lat && lat.latency_ms != null ? `<span class="ms">⑂ ${fmtMs(lat.latency_ms)}</span>` : "") +
        `</header>` +
        vHtml +
        (note ? `<div class="note" title="${esc(note)}">${esc(note)}</div>` : "") +
        (cmd ? `<div class="cmd${cmd.destructive ? " boom" : ""}" title="${esc(cmd.cmd)}">${esc(cmd.cmd)}</div>` : "") +
        (err ? `<div class="cmd boom">${esc(err)}</div>` : "") +
        (lastTrace
          ? `<div class="trace${n.state === "live" ? " stream" : ""}">${esc(lastTrace.role)}: ${esc(lastTrace.text)}</div>`
          : `<div class="trace">no trace yet</div>`);
      el.addEventListener("click", () => selectNode(n.id));
      box.appendChild(el);
    }
  }

  /* ---------- feeds ---------- */

  function renderMeta() {
    const box = $("meta-feed");
    const rows = (state.meta || []).slice(-14).reverse();
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
    $("goal").textContent =
      (state.run && state.run.goal) || (tree ? tree.tree_id : "waiting for a tree");
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
    box.replaceChildren();
    const ids = Object.keys(state.trees || {});
    const active = currentTree();
    if (ids.length < 2 && !ids.length) return;
    for (const id of ids) {
      const t = state.trees[id];
      const nodes = Object.values(t.nodes || {});
      const vms = (t.usage && t.usage.live_vm_count) || 0;
      const btn = document.createElement("button");
      btn.className = active && active.tree_id === id ? "on" : "";
      btn.innerHTML =
        `${esc(id)}<span class="n">${nodes.length} nodes · ${vms} vms</span>`;
      btn.addEventListener("click", () => {
        selectedTree = id; selected = null; selectedCid = null;
        render();
      });
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

  function selectNode(id) {
    selected = selected === id ? null : id;
    selectedCid = null;
    renderDrawer();
    const tree = currentTree();
    if (tree) { reconcileGraph(tree); renderTiles(tree); }
  }

  function closeDrawer() {
    selected = null;
    selectedCid = null;
    $("drawer").hidden = true;
    const tree = currentTree();
    if (tree) reconcileGraph(tree);
  }

  function renderDrawer() {
    const drawer = $("drawer");
    const tree = currentTree();
    const node = tree && selected && (tree.nodes || {})[selected];
    if (!node) { drawer.hidden = true; return; }
    drawer.hidden = false;
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
      <b>dilation</b><span>×${nodeFactor(tree, node.id)}</span>
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

  async function act(op) {
    const tree = currentTree();
    if (!tree) return;
    try {
      const r = await fetch("/api/action", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ op, tree_id: tree.tree_id, node_id: selected || "" }),
      });
      const j = await r.json();
      if (j.error) throw new Error(j.error);
    } catch (e) {
      $("serial").textContent = String(e);
    }
  }

  /* ---------- event reactions (toasts, flashes) ---------- */

  const TOPO_OPS = new Set(["appear", "prune", "evict", "suspend", "resume", "protect", "unprotect"]);

  function reactToEvents(events) {
    const now = Date.now();
    for (const e of events || []) {
      noteBase(e);
      if (e.node_id && TOPO_OPS.has(e.op)) lastFlash[e.node_id] = now;
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

  function render() {
    const tree = currentTree();
    renderHeader(tree);
    renderTrees();
    renderTimeline(tree);
    renderMeta();
    renderEvents();
    renderGauges(tree);
    reconcileGraph(tree);
    renderTiles(tree);
    if (selected) renderDrawer();
    renderClock();
  }

  function apply(msg) {
    const evs = msg.events || [];
    if (msg.state) {
      state = msg.state;
      for (const e of state.events || []) noteBase(e);
    }
    reactToEvents(evs);
    sampleHistory();
    render();
    drawChart();
  }

  /* ---------- wiring ---------- */

  document.querySelectorAll("#actions button[data-act]").forEach((btn) => {
    btn.addEventListener("click", () => act(btn.dataset.act));
  });
  $("drawer-close").addEventListener("click", closeDrawer);
  document.addEventListener("keydown", (e) => {
    if (e.key === "Escape") closeDrawer();
  });
  $("graph").addEventListener("click", (e) => {
    if (e.target === $("graph")) closeDrawer();
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
    // flash decay + caret upkeep without a full re-render
    const tree = currentTree();
    if (tree) {
      const now = Date.now();
      for (const [id, g] of nodeEls) {
        g.classList.toggle("flash", now - (lastFlash[id] || 0) < 900);
      }
      document.querySelectorAll("#tiles .tile").forEach((el) => {
        el.classList.toggle("flash", now - (lastFlash[el.dataset.id] || 0) < 900);
      });
    }
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

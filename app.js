/* R26-CS-019 website: send one URL to every connected component API and show
 * each answer separately. API text is only ever inserted with textContent. */
(() => {
  "use strict";
  const cfg = window.R26_CONFIG;
  const root = document.documentElement;
  const $ = (sel, scope = document) => scope.querySelector(sel);

  /* ---------- theme ---------- */
  function setTheme(theme) {
    root.dataset.theme = theme;
    try { localStorage.setItem("r26-theme", theme); } catch (e) { /* storage blocked */ }
  }
  let saved = null;
  try { saved = localStorage.getItem("r26-theme"); } catch (e) { /* storage blocked */ }
  setTheme(saved || (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark"));
  $("#theme").addEventListener("click", () => setTheme(root.dataset.theme === "dark" ? "light" : "dark"));

  /* ---------- cards ---------- */
  const cards = {};
  const tpl = $("#card-tpl");
  for (const c of cfg.components) {
    const node = tpl.content.firstElementChild.cloneNode(true);
    $(".tag", node).textContent = `${c.id} · ${c.layer}`;
    $(".card-title", node).textContent = c.name;
    $(".owner", node).textContent = c.owner;
    $("#cards").appendChild(node);
    cards[c.id] = node;
    if (c.url) setState(c.id, "idle", "Waiting for a URL");
    else setState(c.id, "off", "Not connected yet");
  }

  function setDot(id, cls, text) {
    const dot = $(".dot", cards[id]);
    dot.className = "dot " + cls;
    $("em", dot).textContent = text;
  }

  function setState(id, state, verdict) {
    const card = cards[id];
    card.dataset.state = state;
    $(".verdict", card).textContent = verdict;
    if (state === "off") setDot(id, "", "Offline");
  }

  function clearResult(id) {
    const card = cards[id];
    $(".meter", card).hidden = true;
    $(".message", card).textContent = "";
    $(".evidence", card).replaceChildren();
    $(".elapsed", card).textContent = "";
  }

  /* ---------- network ---------- */
  async function fetchJSON(url, options, ms) {
    const ctl = new AbortController();
    const timer = setTimeout(() => ctl.abort(), ms);
    try {
      const res = await fetch(url, { ...options, signal: ctl.signal, referrerPolicy: "no-referrer" });
      let body = null;
      try { body = await res.json(); } catch (e) { /* not JSON */ }
      return { ok: res.ok, status: res.status, body };
    } finally {
      clearTimeout(timer);
    }
  }

  // Wake sleeping free servers as soon as the page opens.
  for (const c of cfg.components) {
    if (!c.url) continue;
    setDot(c.id, "wait", "Waking");
    fetchJSON(c.url + "/health", {}, c.timeoutMs || cfg.requestTimeoutMs)
      .then(r => r.ok ? setDot(c.id, "on", "Online") : setDot(c.id, "err", "Error"))
      .catch(() => setDot(c.id, "err", "No reply"));
  }

  /* ---------- adapters: map each API's own format to one shape ---------- */
  const pretty = s => String(s ?? "").replace(/_/g, " ").toLowerCase();
  const short = v => (typeof v === "string" ? v : JSON.stringify(v ?? "")).slice(0, 240);

  function httpProblem(http) {
    const detail = http.body && (http.body.detail ?? http.body.message);
    if (http.status === 429) return { status: "busy", message: "This component is busy with another analysis. Try again shortly." };
    if (http.status >= 400 && http.status < 500) return { status: "invalid", message: short(detail) || `Request rejected (HTTP ${http.status}).` };
    return { status: "error", message: short(detail) || `Server error (HTTP ${http.status}).` };
  }

  function contractEvidence(e = {}) {
    const out = [];
    if (e.decision_source) out.push(`Decision source: ${pretty(e.decision_source)}`);
    if (e.model_prediction) out.push(`Model alone: ${pretty(e.model_prediction)}`);
    if (e.reputation && e.reputation.status) out.push(`Reputation feed: ${pretty(e.reputation.status)}`);
    if (e.data_quality) out.push(`Data quality: ${pretty(e.data_quality)}`);
    if (Number.isFinite(e.observed_features)) out.push(`Live features observed: ${e.observed_features} of ${e.total_features}`);
    if (e.data_availability_note) out.push(e.data_availability_note);
    if (e.capture && e.capture.final_url) out.push(`Final page: ${e.capture.final_url}`);
    for (const flag of (e.active_quality_flags || []).slice(0, 3)) out.push(`Quality flag: ${pretty(flag)}`);
    if (e.needs_review) out.push("Marked for human review");
    return out;
  }

  const adapters = {
    contract(http) {
      if (!http.ok) return httpProblem(http);
      const b = http.body || {};
      const e = b.evidence || {};
      let status = b.status === "ok" ? "ok" : b.status === "invalid_input" ? "invalid" : b.status === "error" ? "error" : "inconclusive";
      let message = b.message;
      const source = String(e.decision_source || "");
      // C4: a verdict built from zero live data is missing evidence, not a legitimate vote.
      if (status === "ok" && e.data_quality === "INSUFFICIENT DATA" && source === "TUNED_80") {
        status = "inconclusive";
        message = "No live infrastructure data could be collected – not counted as a vote.";
      }
      const listed = status === "ok" && source.startsWith("OPENPHISH");
      return {
        status, label: b.label, score: b.score, threshold: b.threshold, message,
        strong: listed ? "listed in the OpenPhish phishing feed (exact match)" : null,
        policyScore: listed ? 1 : undefined,
        evidence: contractEvidence(e)
      };
    },
    c1(http) {
      if (!http.ok) return httpProblem(http);
      const b = http.body || {};
      // Allowlist/rule decisions override the model, so its raw score is evidence, not the result.
      const byModel = b.decision_source === "frozen_ml_hybrid";
      const evidence = (b.evidence || []).slice(0, 4);
      if (!byModel && Number.isFinite(b.phishing_probability)) {
        evidence.push(`Raw ML score ${b.phishing_probability.toFixed(3)} – overridden by ${pretty(b.decision_source)}`);
      }
      const allowlisted = b.decision_source === "trusted_allowlist";
      const rule = b.decision_source === "deterministic_typosquatting_evidence";
      return {
        status: "ok",
        label: b.prediction === "PHISHING" ? "phishing" : "legitimate",
        score: byModel ? b.phishing_probability : null, threshold: b.frozen_threshold,
        // C1's own policy values: 0 for a trusted-domain match, 1 for a typosquatting rule
        policyScore: allowlisted ? 0 : rule ? 1 : undefined,
        allowlisted,
        strong: rule ? `typosquatting rule (${(b.applied_rules || []).map(pretty).join(", ") || "imitation pattern"})` : null,
        message: `${pretty(b.detailed_prediction)} · decided by ${pretty(b.decision_source)}`,
        evidence
      };
    },
    c3(http) {
      if (!http.ok) return httpProblem(http);
      const b = http.body || {};
      return {
        status: "ok",
        label: b.prediction === "PHISHING" ? "phishing" : "legitimate",
        score: b.phishing_probability, threshold: b.threshold,
        message: `Page type ${pretty(b.page_type)} → ${b.model_used || "model"}`,
        evidence: [b.model_name && `Model: ${b.model_name}`, b.router_confidence != null && `Router confidence: ${b.router_confidence}`].filter(Boolean)
      };
    }
  };

  /* ---------- rendering ---------- */
  function showResult(id, r, seconds) {
    const card = cards[id];
    const view = {
      ok: r.label === "phishing" ? ["phishing", "Phishing"] : ["legitimate", "Legitimate"],
      inconclusive: ["inconclusive", "Inconclusive"],
      invalid: ["invalid", "Not accepted"],
      busy: ["inconclusive", "Busy"],
      error: ["error", "Unavailable"]
    }[r.status] || ["error", "Unavailable"];
    setState(id, view[0], view[1]);

    if (r.status === "ok" && Number.isFinite(r.score)) {
      const pct = Math.max(0, Math.min(1, r.score)) * 100;
      $(".meter", card).hidden = false;
      $(".meter-fill", card).style.width = pct.toFixed(1) + "%";
      $(".score", card).textContent = `score ${r.score.toFixed(3)}`;
      if (Number.isFinite(r.threshold)) {
        $(".meter-thr", card).style.left = (r.threshold * 100).toFixed(1) + "%";
        $(".thr", card).textContent = `threshold ${r.threshold.toFixed(2)} · not a probability`;
      }
    }
    $(".message", card).textContent = r.message || "";
    const list = $(".evidence", card);
    for (const item of (r.evidence || []).slice(0, 6)) {
      const li = document.createElement("li");
      li.textContent = item;
      list.appendChild(li);
    }
    $(".elapsed", card).textContent = `answered in ${seconds.toFixed(1)} s`;
  }

  function renderSummary(target, results) {
    const summary = $("#summary");
    summary.hidden = false;
    $("#target").textContent = target;
    const entries = cfg.components.map((c, i) => ({ id: c.id, result: results[i] })).filter((e, i) => cfg.components[i].url);
    const f = window.R26Fusion.fuse(entries);
    summary.dataset.verdict = f.verdict;
    $("#fused-verdict").textContent = { phishing: "Phishing", legitimate: "Legitimate", review: "Needs review" }[f.verdict];
    $("#fused-reason").textContent = f.reason;
    summary.dataset.band = f.band;
    $("#risk-value").textContent = f.risk === null ? "–" : `${f.risk} / 100 · ${f.band}`;
    $("#risk-fill").style.width = (f.risk || 0) + "%";
    $("#summary-line").textContent =
      `Layers answering: ${f.answered} of ${f.connected} · Triggered by: ${f.triggered.join(", ") || "none"} · Rule ${f.rule}`;
    const tally = $("#tally");
    tally.replaceChildren();
    cfg.components.forEach((c, i) => {
      const s = document.createElement("span");
      const r = results[i];
      s.dataset.id = c.id;
      if (r && r.status === "ok") s.className = r.label;
      else if (r && (r.status === "inconclusive" || r.status === "busy")) s.className = "inconclusive";
      tally.appendChild(s);
    });
  }

  /* ---------- scan ---------- */
  function normaliseUrl(raw) {
    let text = raw.trim();
    if (!text) throw new Error("Enter a website address.");
    if (!/^[a-z][a-z0-9+.-]*:\/\//i.test(text)) text = "https://" + text;
    const u = new URL(text);
    if (u.protocol !== "http:" && u.protocol !== "https:") throw new Error("Only http:// and https:// addresses can be analysed.");
    if (u.username || u.password) throw new Error("Remove the username or password from the address.");
    return u.href;
  }

  async function runComponent(c, target) {
    const card = cards[c.id];
    clearResult(c.id);
    setState(c.id, "loading", "Analysing…");
    const started = performance.now();
    const ticker = setInterval(() => {
      const s = (performance.now() - started) / 1000;
      $(".elapsed", card).textContent = `${s.toFixed(0)} s`;
      if (s > 10) $(".verdict", card).textContent = "Waking the server – free hosting can take up to a minute…";
    }, 1000);
    try {
      const http = await fetchJSON(c.url + c.endpoint, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ url: target })
      }, c.timeoutMs || cfg.requestTimeoutMs);
      const result = adapters[c.adapter](http);
      showResult(c.id, result, (performance.now() - started) / 1000);
      setDot(c.id, "on", "Online");
      return result;
    } catch (err) {
      const result = { status: "error", message: err.name === "AbortError" ? "No answer within the time limit." : "Could not reach this component." };
      showResult(c.id, result, (performance.now() - started) / 1000);
      setDot(c.id, "err", "No reply");
      return result;
    } finally {
      clearInterval(ticker);
    }
  }

  $("#scan-form").addEventListener("submit", async ev => {
    ev.preventDefault();
    const msg = $("#form-msg");
    let target;
    try { target = normaliseUrl($("#url").value); }
    catch (err) { msg.textContent = err instanceof TypeError ? "That does not look like a valid web address." : err.message; return; }
    msg.textContent = "";
    $("#url").value = target;

    const live = cfg.components.filter(c => c.url);
    if (!live.length) { msg.textContent = "No component is connected yet."; return; }
    const button = $("#go");
    button.disabled = true;
    button.textContent = "Scanning";
    $("#summary").hidden = true;

    const results = await Promise.all(cfg.components.map(c => c.url ? runComponent(c, target) : Promise.resolve(null)));
    renderSummary(target, results);
    button.disabled = false;
    button.textContent = "Analyse";
    $("#summary").scrollIntoView({ behavior: "smooth", block: "nearest" });
  });
})();

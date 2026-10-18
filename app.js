/* R26-CS-019 website: send one URL to every connected component API, show each
 * answer separately with a "View analysis" explanation, then fuse the answers.
 * API text is only ever inserted with textContent. */
(() => {
  "use strict";
  const cfg = window.R26_CONFIG;
  const $ = (sel, scope = document) => scope.querySelector(sel);

  /* ---------- cards ---------- */
  const cards = {};
  const tpl = $("#card-tpl");
  for (const c of cfg.components) {
    const node = tpl.content.firstElementChild.cloneNode(true);
    $(".dnum", node).textContent = c.id;
    $(".tag", node).textContent = `${c.id} · ${c.layer}`;
    $(".card-title", node).textContent = c.name;
    $(".owner", node).textContent = c.owner;
    $("#cards").appendChild(node);
    cards[c.id] = node;
    const button = $(".view", node);
    const panel = $(".analysis", node);
    button.addEventListener("click", () => {
      const open = panel.hidden;
      panel.hidden = !open;
      button.setAttribute("aria-expanded", String(open));
      button.textContent = open ? "Hide analysis" : "View analysis";
    });
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
    $(".elapsed", card).textContent = "";
    const button = $(".view", card);
    button.hidden = true;
    button.setAttribute("aria-expanded", "false");
    button.textContent = "View analysis";
    const panel = $(".analysis", card);
    panel.hidden = true;
    panel.replaceChildren();
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

  /* ---------- plain-language analysis builders ---------- */
  const pretty = s => String(s ?? "").replace(/_/g, " ").toLowerCase();
  const short = v => (typeof v === "string" ? v : JSON.stringify(v ?? "")).slice(0, 240);
  const num = (v, d = 3) => (Number.isFinite(v) ? v.toFixed(d) : "–");
  const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

  function analysis(headline, sections, details, limits, images = []) {
    return {
      headline,
      sections: sections.filter(s => s.items.length),
      details: details.filter(d => d[1] !== null && d[1] !== undefined && d[1] !== "" && d[1] !== "–"),
      limits,
      images
    };
  }

  // Only plain base64 of an expected image type is turned into a data: URI (CSP allows data: images).
  function dataImage(mime, b64) {
    if (typeof b64 !== "string" || b64.length < 50 || b64.length > 3000000 || !/^[A-Za-z0-9+/]+={0,2}$/.test(b64)) return null;
    return `data:${mime};base64,${b64}`;
  }

  function visualFigures(ve) {
    const figs = [];
    const shot = dataImage("image/jpeg", ve.screenshot_jpeg_base64);
    if (shot) figs.push({ src: shot, alt: "Screenshot of the page captured by C3's browser", caption: "Screenshot captured by C3's hidden browser" });
    return figs;
  }

  const LIMITS = {
    C1: "C1 only reads the domain name as text (offline). It never fetches the page, so it cannot see the page's content, its appearance or the hosting behind it.",
    C2: "C2 reads the page's source code and does not run its scripts. Pages built mainly by JavaScript, or sites that block cloud servers, can look different from what a visitor sees. The cues above are the easiest-to-read signs; the model weighs 106 features together.",
    C3: "C3 judges a screenshot taken by a hidden browser. A cookie banner, a different language or region, or a page that has not finished loading can change the picture. Its test data also had a screenshot-size shortcut, so treat the score with caution.",
    C4: "C4 looks only at infrastructure (DNS, registration, certificate, hosting), not at the name or the page. Missing live data pushes it towards “legitimate”, and its training data contained almost only phishing “www.” hosts, so “www.” addresses can be over-flagged."
  };

  function fallbackAnalysis(id, r) {
    return analysis(
      "This layer gave no verdict, so it did not vote in the fused result.",
      [{ title: "What happened", items: [r.message || "No usable answer was returned."] },
       { title: "Details", items: r.evidence || [] }],
      [], LIMITS[id]);
  }

  function analysisC1(b) {
    const src = b.decision_source;
    const p = b.phishing_probability, t = b.frozen_threshold;
    const phish = b.prediction === "PHISHING";
    let headline;
    const why = [];
    if (src === "trusted_allowlist") {
      headline = `Legitimate – ${b.registered_domain || "this domain"} is on the trusted-domain list.`;
      why.push("The registered domain exactly matches one of 68 well-known trusted domains, so no imitation is possible.");
      if (Number.isFinite(p)) why.push(`The learned model alone scored ${num(p)} (threshold ${num(t)}); the allowlist overrides it, so that number is shown for transparency only.`);
    } else if (src === "deterministic_typosquatting_evidence") {
      headline = `Phishing – the domain imitates ${b.nearest_trusted_domain || "a trusted brand"}.`;
      why.push("A rule written for typosquatting fired. Rules override the model because they name a specific imitation trick.");
      for (const r of (b.applied_rules || [])) why.push(`Rule: ${pretty(r)}`);
    } else {
      headline = `${phish ? "Phishing" : "Legitimate"} – the learned model scored ${num(p)} against a threshold of ${num(t)}.`;
      why.push(phish ? "The score is at or above the threshold, so the domain name looks like phishing domains the model has seen."
                     : "The score is below the threshold, so the domain name does not look like a typical phishing domain.");
      why.push("No allowlist match and no typosquatting rule fired, so the model decided.");
    }
    return analysis(headline,
      [{ title: "Why", items: why }, { title: "Evidence from the domain name", items: b.evidence || [] }],
      [["Registered domain", b.registered_domain], ["Decision made by", pretty(src)], ["Confidence", pretty(b.confidence)],
       ["Nearest trusted domain", b.nearest_trusted_domain],
       ["Edit distance to it", Number.isFinite(b.damerau_distance) ? String(b.damerau_distance) : null],
       ["Similarity (Jaro–Winkler)", num(b.jaro_winkler_similarity, 3)],
       ["Model parts", Number.isFinite(b.tabular_probability) ? `features ${num(b.tabular_probability)} · characters ${num(b.character_probability)}` : null]],
      LIMITS.C1);
  }

  function analysisC2(body) {
    const d = body.details || {};
    const f = d.features || {};
    const n = k => Number(f[k]) || 0;
    const score = body.score, thr = body.threshold;
    const suspicious = [], calm = [];
    if (n("password_form_cross_site_action_count")) suspicious.push(`${plural(n("password_form_cross_site_action_count"), "login form sends", "login forms send")} the password to a different website`);
    if (n("form_cross_site_action_count") && !n("password_form_cross_site_action_count")) suspicious.push(`${plural(n("form_cross_site_action_count"), "form sends", "forms send")} data to a different website`);
    if (n("form_https_to_http_action_count")) suspicious.push(`${plural(n("form_https_to_http_action_count"), "form submits", "forms submit")} from a secure page to an unencrypted address`);
    if (n("context_plaintext_passwordlike_control_count")) suspicious.push(`${plural(n("context_plaintext_passwordlike_control_count"), "field looks", "fields look")} like a password box but shows the text in plain view`);
    if (n("context_identity_password_pair_form_count")) suspicious.push(`${plural(n("context_identity_password_pair_form_count"), "form asks", "forms ask")} for a username and a password together`);
    else if (n("password_input_count")) suspicious.push(`${plural(n("password_input_count"), "password box", "password boxes")} on the page`);
    if (n("iframe_hidden_hint_count")) suspicious.push(`${plural(n("iframe_hidden_hint_count"), "hidden frame", "hidden frames")} embedded in the page`);
    if (n("meta_refresh_cross_site_count")) suspicious.push("the page can redirect the visitor to another website automatically");
    if (n("js_eval_call_count") + n("js_atob_call_count") + n("js_decode_call_count") + n("js_char_code_call_count")) suspicious.push("scripts decode or hide their own code (eval, atob or character codes)");
    if (n("js_location_assignment_count")) suspicious.push("a script redirects the page");
    if (n("js_fetch_call_count") + n("js_xhr_constructor_count") + n("js_sendbeacon_call_count")) suspicious.push("scripts send data in the background");
    if (n("script_cross_site_count") > 3) suspicious.push(`${n("script_cross_site_count")} scripts are loaded from other websites`);
    if (!n("form_count") && !n("password_input_count")) calm.push("no forms or password boxes were found, so there is nothing to steal credentials with");
    else if (!n("password_form_cross_site_action_count") && !n("form_cross_site_action_count")) calm.push("forms on the page send their data back to the same website");
    if (!n("js_eval_call_count") && !n("js_atob_call_count") && !n("js_decode_call_count")) calm.push("no hidden or encoded script tricks were found");
    if (!n("iframe_hidden_hint_count") && !n("meta_refresh_cross_site_count")) calm.push("no hidden frames or automatic redirects to other websites");
    const phish = body.label === "phishing";
    const headline = body.status !== "ok"
      ? "No verdict – the page could not be read, so this layer did not vote."
      : `${phish ? "Phishing" : "Legitimate"} – the page-code model scored ${num(score)} against a threshold of ${num(thr)}.`;
    const flags = ((body.evidence || {}).active_quality_flags || []).map(pretty);
    const cap = (body.evidence || {}).capture || {};
    return analysis(headline,
      [{ title: body.status === "ok" ? "Signs that raise suspicion" : "What happened", items: body.status === "ok" ? suspicious : [body.message || "The page could not be fetched."] },
       { title: "Calm signs", items: body.status === "ok" ? calm : [] },
       { title: "Capture quality", items: flags.map(x => `Flag: ${x}`) }],
      [["Final page", cap.final_url], ["Page size", Number.isFinite(d.html_characters) ? `${d.html_characters.toLocaleString()} characters` : null],
       ["Forms · password boxes", f.form_count !== undefined ? `${n("form_count")} · ${n("password_input_count")}` : null],
       ["Scripts (external)", f.script_count !== undefined ? `${n("script_count")} (${n("script_external_count")})` : null],
       ["Capture method", pretty(d.capture_basis)]],
      LIMITS.C2);
  }

  function analysisC3(b) {
    const phish = b.prediction === "PHISHING";
    const modelLabel = b.model_used === "MODEL_1" ? "login-page model" : "general-page model";
    const why = [
      `The page was classed as ${pretty(b.page_type)} (router confidence ${b.router_confidence ?? "–"}), so the ${modelLabel} judged the screenshot.`,
      phish ? `The model scored ${num(b.phishing_probability)}, at or above its threshold of ${num(b.threshold)}: the screenshot resembles phishing pages it learned from.`
            : `The model scored ${num(b.phishing_probability)}, below its threshold of ${num(b.threshold)}: the screenshot does not resemble the phishing pages it learned from.`
    ];
    const cap = ((b.diagnostics || {}).capture) || {};
    const ve = b.visual_evidence || {};
    const figures = visualFigures(ve);
    const input = dataImage("image/png", ve.model_input_png_base64);
    if (input) figures.push({ src: input, alt: "The image the CNN received after resizing and cropping", caption: "What the CNN actually received (resized and cropped)" });
    const gc = ve.gradcam || {};
    const gcItems = [];
    if (gc.status === "ok") {
      const pm = dataImage("image/png", gc.phishing_overlay_png_base64), lm = dataImage("image/png", gc.legitimate_overlay_png_base64);
      if (pm) figures.push({ src: pm, alt: "Grad-CAM heat-map for the phishing class", caption: "Grad-CAM – where the network pushed the score towards PHISHING" });
      if (lm) figures.push({ src: lm, alt: "Grad-CAM heat-map for the legitimate class", caption: "Grad-CAM – where the network pushed the score towards LEGITIMATE" });
      gcItems.push("Warm colours (yellow to red) show the areas that influenced the score most; dark blue means little influence.");
      gcItems.push(`Read the map that matches the verdict: the ${phish ? "PHISHING" : "LEGITIMATE"} map shows what supported this result.`);
      gcItems.push("The maps are coarse (the last feature grid is only 5×12 for the login model and 7×12 for the general model) and are scaled per image, so colours cannot be compared between pages.");
      gcItems.push("A highlighted area shows where the model looked, not proof of why a page is phishing.");
    } else if (gc.status === "failed") {
      gcItems.push("Grad-CAM could not be computed for this page. The prediction itself is not affected.");
    } else if (!b.visual_evidence) {
      gcItems.push("This C3 server version does not send the screenshot or Grad-CAM heat-maps yet.");
    }
    return analysis(
      `${phish ? "Phishing" : "Legitimate"} – the visual model scored ${num(b.phishing_probability)} against a threshold of ${num(b.threshold)}.`,
      [{ title: "Why", items: why }, { title: "How to read the heat-maps", items: gcItems }],
      [["Page type", pretty(b.page_type)], ["Router confidence", b.router_confidence], ["Model", b.model_name],
       ["Final page", cap.final_url], ["Page returned", Number.isFinite(cap.http_status) ? `HTTP ${cap.http_status}` : null],
       ["Run ID", b.run_id]],
      LIMITS.C3, figures);
  }

  function analysisC3Capture(status, d, evidence) {
    const review = status === 422;
    return analysis(
      review ? "No verdict – the captured page may not show the real website, so no visual prediction was made."
             : "No verdict – the browser could not load the page, so no visual prediction was made.",
      [{ title: "What the browser saw", items: evidence },
       { title: "Why this matters", items: ["A screenshot of an error, block or blank page says nothing about the real site, so C3 refuses to guess. It did not vote in the fused result."] }],
      [["Run ID", d.run_id]], LIMITS.C3, visualFigures(d.visual_evidence || {}));
  }

  function analysisC4(body) {
    const e = body.evidence || {};
    const phish = body.label === "phishing";
    const groups = e.available_groups || {};
    const names = { DNS: "DNS records", RDAP: "registration (RDAP/WHOIS)", TLS: "TLS certificate", IP: "IP and hosting" };
    const have = Object.keys(groups).filter(k => groups[k]).map(k => names[k] || k);
    const miss = Object.keys(groups).filter(k => !groups[k]).map(k => names[k] || k);
    const listed = String(e.decision_source || "").startsWith("OPENPHISH");
    const why = [];
    if (listed) why.push("This exact address is listed in the OpenPhish feed of reported phishing sites, which decides the result on its own.");
    why.push(`The infrastructure model scored ${num(body.score)} against a threshold of ${num(body.threshold)}${e.model_prediction ? ` (${pretty(e.model_prediction)})` : ""}.`);
    if (e.reputation && e.reputation.reason) why.push(e.reputation.reason);
    if (phish && String(e.host || "").startsWith("www.")) why.push("Note: this address starts with “www.”. In C4's training data almost every “www.” host was phishing, so such addresses can be over-flagged.");
    const headline = body.status === "ok"
      ? `${phish ? "Phishing" : "Legitimate"} – ${listed ? "listed in the OpenPhish feed." : `the infrastructure model scored ${num(body.score)} against a threshold of ${num(body.threshold)}.`}`
      : "No verdict – not enough live infrastructure data, so this layer did not vote.";
    return analysis(headline,
      [{ title: "Why", items: why },
       { title: "Data collected", items: [have.length ? `Collected: ${have.join(", ")}` : "", miss.length ? `Not available: ${miss.join(", ")}` : "", e.data_availability_note || ""].filter(Boolean) }],
      [["Host analysed", e.host], ["Live features observed", Number.isFinite(e.observed_features) ? `${e.observed_features} of ${e.total_features}` : null],
       ["Data quality", pretty(e.data_quality)], ["Decision made by", pretty(e.decision_source)],
       ["Reputation feed", e.reputation && pretty(e.reputation.status)]],
      LIMITS.C4);
  }

  /* ---------- adapters: map each API's own format to one shape ---------- */
  function httpProblem(http) {
    const detail = http.body && (http.body.detail ?? http.body.message);
    if (http.status === 429) return { status: "busy", message: "This component is busy with another analysis. Try again shortly." };
    if (http.status >= 400 && http.status < 500) return { status: "invalid", message: short(detail) || `Request rejected (HTTP ${http.status}).` };
    return { status: "error", message: short(detail) || `Server error (HTTP ${http.status}).` };
  }

  function captureWarning(w) {
    const code = String(w);
    if (code.startsWith("http_error_")) return `Page returned HTTP ${code.slice(11)}`;
    return {
      possible_access_block_or_verification: "Page looks like an access block or human-verification page",
      near_blank_capture: "Screenshot is almost blank"
    }[code] || pretty(code);
  }

  const adapters = {
    contract(http, id) {
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
      const view = { ...b, status: status === "ok" ? "ok" : "failed", message };
      return {
        status, label: b.label, score: b.score, threshold: b.threshold, message,
        strong: listed ? "listed in the OpenPhish phishing feed (exact match)" : null,
        policyScore: listed ? 1 : undefined,
        analysis: id === "C4" ? analysisC4(view) : analysisC2(view)
      };
    },
    c1(http) {
      if (!http.ok) return httpProblem(http);
      const b = http.body || {};
      // Allowlist/rule decisions override the model, so its raw score is evidence, not the result.
      const byModel = b.decision_source === "frozen_ml_hybrid";
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
        analysis: analysisC1(b)
      };
    },
    c3(http) {
      // 422 = capture needs review, 502 = capture failed: C3 made no prediction, so it never votes.
      if (http.status === 422 || http.status === 502) {
        const d = (http.body && typeof http.body.detail === "object" && http.body.detail) || {};
        const cap = d.capture || {};
        const evidence = (cap.warnings || []).map(captureWarning);
        if (Number.isFinite(cap.http_status)) evidence.push(`Page returned HTTP ${cap.http_status}`);
        if (cap.final_url) evidence.push(`Final page: ${cap.final_url}`);
        if (cap.error_type) evidence.push(`Browser error: ${cap.error_type}`);
        const review = http.status === 422;
        return {
          status: review ? "inconclusive" : "error",
          verdict: review ? "Unable to assess – capture needs review" : "Unable to assess – capture failed",
          message: review ? "The captured page may not show the real website, so no visual prediction was made."
                          : "The browser could not load the page, so no visual prediction was made.",
          analysis: analysisC3Capture(http.status, d, [...new Set(evidence)])
        };
      }
      if (!http.ok) return httpProblem(http);
      const b = http.body || {};
      return {
        status: "ok",
        label: b.prediction === "PHISHING" ? "phishing" : "legitimate",
        score: b.phishing_probability, threshold: b.threshold,
        message: `Page type ${pretty(b.page_type)} → ${b.model_used || "model"}`,
        analysis: analysisC3(b)
      };
    }
  };

  /* ---------- rendering ---------- */
  function renderAnalysis(card, a) {
    const panel = $(".analysis", card);
    panel.replaceChildren();
    const h = document.createElement("h4");
    h.textContent = a.headline;
    panel.appendChild(h);
    if (a.images && a.images.length) {
      const t = document.createElement("h5");
      t.textContent = "What C3 saw";
      const wrap = document.createElement("div");
      wrap.className = "figures";
      for (const f of a.images) {
        const fig = document.createElement("figure");
        const img = document.createElement("img");
        img.src = f.src;
        img.alt = f.alt;
        img.loading = "lazy";
        const cap = document.createElement("figcaption");
        cap.textContent = f.caption;
        fig.append(img, cap);
        wrap.appendChild(fig);
      }
      panel.append(t, wrap);
    }
    for (const s of a.sections) {
      const t = document.createElement("h5");
      t.textContent = s.title;
      const ul = document.createElement("ul");
      for (const item of s.items) {
        const li = document.createElement("li");
        li.textContent = item;
        ul.appendChild(li);
      }
      panel.append(t, ul);
    }
    if (a.details.length) {
      const t = document.createElement("h5");
      t.textContent = "Key numbers";
      const dl = document.createElement("dl");
      for (const [k, v] of a.details) {
        const dt = document.createElement("dt"), dd = document.createElement("dd");
        dt.textContent = k;
        dd.textContent = String(v);
        dl.append(dt, dd);
      }
      panel.append(t, dl);
    }
    if (a.limits) {
      const p = document.createElement("p");
      p.className = "limits";
      p.textContent = "What this layer cannot see: " + a.limits;
      panel.appendChild(p);
    }
  }

  function showResult(id, r, seconds) {
    const card = cards[id];
    const view = {
      ok: r.label === "phishing" ? ["phishing", "Phishing"] : ["legitimate", "Legitimate"],
      inconclusive: ["inconclusive", "Inconclusive"],
      invalid: ["invalid", "Not accepted"],
      busy: ["inconclusive", "Busy"],
      error: ["error", "Unavailable"]
    }[r.status] || ["error", "Unavailable"];
    setState(id, view[0], r.verdict || view[1]);

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
    renderAnalysis(card, r.analysis || fallbackAnalysis(id, r));
    $(".view", card).hidden = false;
    $(".elapsed", card).textContent = `answered in ${seconds.toFixed(1)} s`;
  }

  function renderSummary(target, results) {
    const summary = $(".summary-card");
    $("#summary").hidden = false;
    $("#target").textContent = target;
    const entries = cfg.components.map((c, i) => ({ id: c.id, result: results[i] })).filter((e, i) => cfg.components[i].url);
    const f = window.R26Fusion.fuse(entries);
    summary.dataset.verdict = f.verdict;
    $("#fused-verdict").textContent = { phishing: "Phishing", legitimate: "Legitimate", unknown: "Unable to assess" }[f.verdict];
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
      const result = adapters[c.adapter](http, c.id);
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
    $("#summary").scrollIntoView({ behavior: "smooth", block: "start" });
  });
})();

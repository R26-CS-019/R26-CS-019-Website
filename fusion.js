/* R26-CS-019 decision fusion, version 1.2 (binary)
 *
 * Final classification is Phishing or Legitimate, with a 0-100 risk score, as in
 * the TAF output layer. The rule was chosen with the joint evaluation (100 live
 * URLs: majority rule 91% accuracy, 96% recall, 14% FPR – better than any single
 * layer or any risk-score threshold) and must be confirmed on a new run.
 *
 *   T1  C1 matched a trusted domain and the flags include page-content layers
 *       (C2/C3) -> Legitimate (content warnings alone do not override it)
 *   S1  any strong-evidence flag (C1 typosquatting rule, C4 OpenPhish match) -> Phishing
 *   M2  two or more answering layers flag phishing                           -> Phishing
 *   M1  exactly one layer flags                                               -> Legitimate
 *   M0  no layer flags                                                        -> Legitimate
 *   U0  no layer could analyse the URL                                        -> Unable to assess
 *
 * Input: one normalised result per connected component:
 *   { status: "ok"|"inconclusive"|"invalid"|"busy"|"error",
 *     label: "phishing"|"legitimate", score, threshold,
 *     policyScore (0..1, when a rule rather than a model decided),
 *     strong (text, when the flag is strong evidence), allowlisted (C1 only) }
 * Failed, inconclusive or unconnected layers are never counted as votes.
 */
(function (root) {
  "use strict";

  // Map a score onto 0..1 so that every component's own threshold sits at 0.5.
  function moduleRisk(r) {
    if (Number.isFinite(r.policyScore)) return r.policyScore;
    const t = r.threshold;
    if (!Number.isFinite(r.score) || !Number.isFinite(t) || t <= 0 || t >= 1) {
      return r.label === "phishing" ? 1 : 0;
    }
    const s = Math.min(1, Math.max(0, r.score));
    return s < t ? 0.5 * s / t : 0.5 + 0.5 * (s - t) / (1 - t);
  }

  // Risk 0..100: half from the strongest warning, half from the average layer.
  function riskScore(okResults) {
    if (!okResults.length) return null;
    const risks = okResults.map(moduleRisk);
    const mean = risks.reduce((a, b) => a + b, 0) / risks.length;
    return Math.round(100 * (0.5 * Math.max(...risks) + 0.5 * mean));
  }

  function riskBand(risk) {
    if (risk === null) return "unknown";
    return risk >= 70 ? "high" : risk >= 40 ? "medium" : "low";
  }

  // entries: [{ id: "C1", result }, ...] for every connected component
  function fuse(entries) {
    const ok = entries.filter(e => e.result && e.result.status === "ok");
    const flags = ok.filter(e => e.result.label === "phishing");
    const names = list => list.map(e => e.id).join(", ");
    const strong = flags.filter(e => e.result.strong);
    const c1 = ok.find(e => e.id === "C1");
    const contentFlags = flags.filter(e => e.id === "C2" || e.id === "C3");
    let verdict, rule, reason;

    if (!ok.length) {
      verdict = "unknown"; rule = "U0";
      reason = "No layer could analyse this URL, so no classification is possible.";
    } else if (c1 && c1.result.allowlisted && contentFlags.length) {
      verdict = "legitimate"; rule = "T1";
      reason = `C1 matched a trusted domain. Warnings from ${names(flags)} are shown in the risk score ` +
               "but do not override it.";
    } else if (strong.length) {
      verdict = "phishing"; rule = "S1";
      reason = "Strong evidence: " + strong.map(e => `${e.id} – ${e.result.strong}`).join("; ") + ".";
    } else if (flags.length >= 2) {
      verdict = "phishing"; rule = "M2";
      reason = `${flags.length} of ${ok.length} answering layers flag this URL (${names(flags)}).`;
    } else if (flags.length === 1) {
      verdict = "legitimate"; rule = "M1";
      reason = `Only ${flags[0].id} flagged this URL (1 of ${ok.length} answering layers) – not enough ` +
               `agreement for a phishing verdict. See the risk score and ${flags[0].id}'s evidence.`;
    } else {
      verdict = "legitimate"; rule = "M0";
      reason = `None of the ${ok.length} answering layers found phishing evidence.`;
    }
    if (verdict === "legitimate") {
      reason += " This is a model result, not a guarantee of safety.";
      if (ok.length < entries.length) reason += ` Based on ${ok.length} of ${entries.length} layers.`;
    }

    const risk = riskScore(ok.map(e => e.result));
    return { verdict, rule, reason, risk, band: riskBand(risk),
             triggered: flags.map(e => e.id), answered: ok.length, connected: entries.length };
  }

  const api = { moduleRisk, riskScore, riskBand, fuse, version: "1.2" };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.R26Fusion = api;
})(this);

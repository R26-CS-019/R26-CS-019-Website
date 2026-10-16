/* R26-CS-019 decision fusion, version 1.1
 *
 * Fusion v1 follows the group report (Section 4.4, Appendix A.3). v1.1 adds one
 * agreed refinement: a single flag that is "strong evidence" decides Phishing.
 *
 * Input: one normalised result per component (null = not connected):
 *   { status: "ok"|"inconclusive"|"invalid"|"busy"|"error",
 *     label: "phishing"|"legitimate", score, threshold,
 *     policyScore (0..1, when a rule rather than a model decided),
 *     strong (text, when the flag is strong evidence), allowlisted (C1 only) }
 * Missing, failed or inconclusive layers are never counted as legitimate votes.
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
    const c1 = ok.find(e => e.id === "C1");
    const contentFlags = flags.filter(e => e.id === "C2" || e.id === "C3");
    const strong = flags.filter(e => e.result.strong);
    let verdict, rule, reason;

    if (c1 && c1.result.allowlisted && contentFlags.length) {
      verdict = "review"; rule = "R1";
      reason = `C1 matched a trusted domain, but ${names(contentFlags)} flagged the page. A trusted name does not prove the page is safe.`;
    } else if (strong.length) {
      verdict = "phishing"; rule = "S1";
      reason = "Strong evidence: " + strong.map(e => `${e.id} – ${e.result.strong}`).join("; ") + ".";
    } else if (flags.length >= 2) {
      verdict = "phishing"; rule = "R2";
      reason = `${flags.length} independent layers flag this URL (${names(flags)}).`;
    } else if (flags.length === 1) {
      verdict = "review"; rule = "R3";
      reason = `Only ${flags[0].id} flags this URL. A single warning is never ignored – check its evidence first.`;
    } else if (ok.length >= 3) {
      verdict = "legitimate"; rule = "R4";
      reason = `None of the ${ok.length} answering layers found phishing evidence. This is not a guarantee of safety.`;
    } else {
      verdict = "review"; rule = "R5";
      reason = `Only ${ok.length} of ${entries.length} layers gave a usable answer – not enough to call this URL legitimate.`;
    }

    const risk = riskScore(ok.map(e => e.result));
    return { verdict, rule, reason, risk, band: riskBand(risk),
             triggered: flags.map(e => e.id), answered: ok.length, connected: entries.length };
  }

  const api = { moduleRisk, riskScore, riskBand, fuse, version: "1.1" };
  if (typeof module === "object" && module.exports) module.exports = api;
  else root.R26Fusion = api;
})(this);

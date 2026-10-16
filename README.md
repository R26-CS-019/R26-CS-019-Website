# R26-CS-019 – Group website

Static website (HTML, CSS, JavaScript – no build step) for the R26-CS-019
adaptive multi-layer phishing detection framework. It sends one URL to every
connected component API at the same time and shows each result on its own card,
plus a simple count of how many answering layers flag the URL.

## Decision fusion (v1.2, binary)

`fusion.js` gives a final **Phishing** or **Legitimate** classification plus a risk score, as in
the TAF output layer:

| Rule | Condition | Verdict |
|---|---|---|
| T1 | C1 matched a trusted domain and the flags include C2 or C3 (page content) | Legitimate (warnings shown in the risk score) |
| S1 | Any flag that is strong evidence (C1 typosquatting rule, C4 OpenPhish exact match) | Phishing |
| M2 | Two or more answering layers flag phishing | Phishing |
| M1 | Exactly one layer flags phishing | Legitimate (risk score and that layer's evidence shown) |
| M0 | No layer flags phishing | Legitimate |
| U0 | No layer could analyse the URL | Unable to assess |

Why binary majority: on the joint evaluation (100 live URLs, 50/50) it reached 91% accuracy,
96% recall and 14% FPR – better than the best single layer (C1: 89% / 90% / 12%) and than any
risk-score threshold (e.g. risk ≥ 50: 80% accuracy, 38% FPR). The rule was chosen on those same
URLs, so it must be confirmed on a new run. It replaces the group report's three-way design
(v1/v1.1 with "Needs review", Appendix A.3), where 18 single-flag cases contained only 2 phishing sites.

Failed, inconclusive or unconnected layers are never counted as votes (C4 results built
from zero live data are treated as inconclusive). **Risk score (0–100):** each layer's score is
scaled so its own threshold sits at 50 (rule decisions use C1's policy values 0/100, a feed match
uses 100); risk = 50% strongest layer + 50% average layer. Bands: low < 40 ≤ medium < 70 ≤ high.
Not a calibrated probability; to be validated by the joint evaluation.

## Connect a component

Edit **`config.js`** only: paste the component's Render address into its `url`
(no slash at the end), save, commit and push. Leave `url` empty for components
that are not online yet.

| Component | Endpoint | Response format (`adapter`) |
|---|---|---|
| C1 Domain & Typosquatting | `POST /predict` | `c1` – C1's own `predict_url` output |
| C2 HTML & JavaScript | `POST /analyze` | `contract` – group result contract |
| C3 Micro Visual Cues | `POST /predict` | `c3` – C3's visual API output |
| C4 Domain Intelligence | `POST /analyze` | `contract` – group result contract |

Every API receives `{"url": "https://..."}`.

## Run locally

```
python -m http.server 8080 --bind 127.0.0.1
```
Then open http://127.0.0.1:8080

## Host

Render → **New → Static Site** → this repository → Publish directory `.` (no build command).

## Notes

- API text is inserted with `textContent` only, and a Content-Security-Policy
  limits scripts to this site.
- The vote count is not a combined verdict; the group has not adopted a fusion rule.
- Free component servers sleep when idle; the page pings each `/health` on load to wake them.

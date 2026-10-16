# R26-CS-019 – Group website

Static website (HTML, CSS, JavaScript – no build step) for the R26-CS-019
adaptive multi-layer phishing detection framework. It sends one URL to every
connected component API at the same time and shows each result on its own card,
plus a simple count of how many answering layers flag the URL.

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

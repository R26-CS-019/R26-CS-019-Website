/*
 * R26-CS-019 website settings – the ONLY file you need to edit to connect a component.
 *
 * When a teammate's API is online, paste its Render address into "url"
 * (no slash at the end), save, and upload the change to GitHub.
 * Leave "url" empty ("") for components that are not online yet.
 */
window.R26_CONFIG = {
  requestTimeoutMs: 120000,   // free servers can take ~1 minute to wake up
  components: [
    {
      id: "C1",
      layer: "Domain name",
      name: "Domain & Typosquatting Detection",
      owner: "I. A. Niunhella · IT22131010",
      url: "https://c1-domain-typosquatting-detector.onrender.com",
      endpoint: "/predict",
      adapter: "c1"
    },
    {
      id: "C2",
      layer: "Page code",
      name: "HTML & JavaScript Behaviour Analysis",
      owner: "W. M. U. G. Jayawardana · IT22281050",
      url: "https://c2-html-js-phishing-detector.onrender.com",
      endpoint: "/analyze",
      adapter: "contract"
    },
    {
      id: "C3",
      layer: "Visual appearance",
      name: "Micro Visual Cue Detection (CNN)",
      owner: "M. A. O. Rashmika · IT22546234",
      url: "",
      endpoint: "/predict",
      adapter: "c3"
    },
    {
      id: "C4",
      layer: "Infrastructure",
      name: "Domain Intelligence (DNS · RDAP · TLS · IP)",
      owner: "C. I. Vitharana · IT22911308",
      url: "https://c4-domain-intelligence-detector.onrender.com",
      endpoint: "/analyze",
      adapter: "contract"
    }
  ]
};

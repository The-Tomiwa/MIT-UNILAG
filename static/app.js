// GPON Malware Framework Generator - front end (vanilla JS, renders backend JSON)
(() => {
  const $ = (s, el = document) => el.querySelector(s);
  const esc = (v) => String(v ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const form = $("#gen-form");
  const out = $("#output");
  const status = $("#status");
  let current = null;       // last generated framework JSON
  let activeSample = null;
  let hasSamples = false;

  const LEVEL = { Critical: "b-crit", High: "b-high", Medium: "b-med", Low: "b-low" };
  const CONF = { high: "b-low", moderate: "b-med", medium: "b-med", low: "b-high" };
  const REL_LABEL = { direct: "Direct GPON exploit", indirect: "Indirect / same device class", none: "Not ISP CPE" };

  // ---------------------------------------------------------------- samples
  async function loadSampleList() {
    const res = await fetch("/api/samples");
    const list = res.ok ? await res.json() : [];
    // no bundled samples: hide the list and the campaign view (it correlates bundled samples)
    $("#samples-heading").hidden = $("#btn-campaign").hidden = list.length === 0;
    hasSamples = list.length > 0;
    $("#sample-list").innerHTML = list.map((s) => `
      <li><button data-id="${esc(s.id)}"><strong>${esc(s.name)}</strong>
      <span class="hash">${esc((s.sha256 || "").slice(0, 16))}…</span></button></li>`).join("");
  }

  $("#sample-list").addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-id]");
    if (!btn) return;
    const s = await (await fetch(`/api/samples/${btn.dataset.id}`)).json();
    activeSample = s.id;
    setActive(btn);
    form.reset();
    form.name.value = s.meta.name || "";
    form.sha256.value = s.meta.sha256 || "";
    form.static.value = s.static;
    form.dynamic.value = s.dynamic;
    $("#input-title").textContent = `Analysis input — ${s.meta.name}`;
    await runGenerate(s.meta.source_report);
  });

  $("#btn-new").addEventListener("click", () => {
    activeSample = null;
    setActive($("#btn-new"));
    form.reset();
    $("#input-title").textContent = "Analysis input — new sample";
    showInput(true);
    out.innerHTML = `<div class="card empty">Paste your static and dynamic analysis results (or upload files), then generate.</div>`;
    current = null; toggleExports(false); $("#toc").hidden = true;
  });

  $("#btn-campaign").addEventListener("click", async () => {
    setActive($("#btn-campaign"));
    showInput(false);
    status.textContent = "";
    out.innerHTML = `<div class="card empty">Correlating samples…</div>`;
    const c = await (await fetch("/api/campaign")).json();
    renderCampaign(c);
    current = null; toggleExports(false); $("#toc").hidden = true;
  });

  function setActive(el) {
    document.querySelectorAll("#sample-list button, .side-btn").forEach((b) => b.classList.remove("active"));
    el.classList.add("active");
  }

  // ---------------------------------------------------------------- generate
  form.addEventListener("submit", (e) => { e.preventDefault(); runGenerate(); });

  async function runGenerate(sourceReport) {
    status.textContent = "Generating…";
    $("#btn-generate").disabled = true;
    try {
      const res = await fetch("/api/generate", { method: "POST", body: new FormData(form) });
      const data = await res.json();
      $("#warnings").innerHTML = (data.warnings || []).map((w) => `<div class="warn">${esc(w)}</div>`).join("");
      if (!res.ok) { status.textContent = data.error || "Failed"; return; }
      if (sourceReport) data.meta.source_report = sourceReport;
      current = data;
      render(data);
      toggleExports(true);
      status.textContent = `Framework generated · ${data.iocs.length} IOCs · ${data.attack.length} techniques`;
      if (activeSample) showInput(false);
    } catch (err) {
      status.textContent = "Error: " + err.message;
    } finally {
      $("#btn-generate").disabled = false;
    }
  }

  // ---------------------------------------------------------------- helpers
  const badge = (text, cls = "b-neutral") => `<span class="badge ${cls}">${esc(text)}</span>`;
  const evList = (ev) => ev && ev.length ? `<ul class="ev">${ev.map((l) => `<li>${esc(l)}</li>`).join("")}</ul>` : "";
  const section = (n, id, title, body) =>
    `<section class="fw" id="${id}"><h3><span class="num">${n}</span>${esc(title)}</h3>${body}</section>`;
  const code = (text, lang) => `<div class="code-block"><button class="copy" data-copy>Copy</button><pre class="${lang || ""}">${esc(text)}</pre></div>`;

  // ---------------------------------------------------------------- render framework
  function render(fw) {
    const i = fw.identity, v = fw.vector, r = fw.risk;
    const riskColor = { Critical: "var(--crit)", High: "var(--high)", Medium: "var(--med)", Low: "var(--low)" }[r.level];
    const maxScore = Math.max(1, ...i.family_scores.map((s) => s.score));

    const header = `
      <div class="report-title"><h2>${esc(i.name)} — GPON malware framework</h2>
        <span class="gen">Generated ${esc(fw.meta.generated_at)}${fw.meta.source_report ? " · source: " + esc(fw.meta.source_report) : ""}</span></div>
      <div class="summary">
        <div class="stat"><div class="k">Family</div><div class="v">${esc(i.family)}</div><div class="s">${esc(i.family_confidence)} confidence</div></div>
        <div class="stat"><div class="k">Platform</div><div class="v">${esc(i.arch || "?")}</div><div class="s">${esc(i.platform)}</div></div>
        <div class="stat"><div class="k">GPON relevance</div><div class="v">${badge(REL_LABEL[v.gpon_relevance], "b-" + v.gpon_relevance)}</div><div class="s">${v.vectors.length} vector(s)</div></div>
        <div class="stat"><div class="k">Risk</div><div class="v" style="color:${riskColor}">${r.score}<span class="s">/100 · ${esc(r.level)}</span></div>
          <div class="risk-bar"><div style="width:${r.score}%;background:${riskColor}"></div></div></div>
        <div class="stat"><div class="k">Operator priority</div><div class="v" style="font-size:15px">${esc(fw.operator.priority.split(" - ")[0])}</div><div class="s">${esc(fw.operator.priority.split(" - ")[1] || "")}</div></div>
      </div>`;

    // 1 identity
    const s1 = section(1, "s1", "Sample identity", `
      <table class="kv"><tbody>
        <tr><td>SHA256</td><td class="mono">${esc(i.sha256 || "—")}</td></tr>
        <tr><td>Other hashes</td><td class="mono">${esc([...i.hashes.sha256.filter((h) => h !== i.sha256), ...i.hashes.sha1, ...i.hashes.md5].join("  ") || "—")}</td></tr>
        <tr><td>Platform</td><td>${esc(i.platform)}</td></tr>
        <tr><td>Architecture</td><td>${esc([i.arch, i.bits && i.bits + "-bit", i.endian && i.endian + "-endian"].filter(Boolean).join(" · ") || "unknown")}</td></tr>
        <tr><td>Linking / symbols</td><td>${esc(i.linking || "unknown")} · ${i.stripped === true ? "stripped" : i.stripped === false ? "not stripped" : "unknown"}</td></tr>
        <tr><td>File size</td><td>${i.file_size ? i.file_size.toLocaleString() + " bytes" : "—"}</td></tr>
        <tr><td>Role</td><td>${i.roles.map((x) => badge(x, "b-src")).join(" ")}</td></tr>
        <tr><td>Family (engine)</td><td>${badge(i.family)} ${badge(i.family_confidence + " confidence", CONF[i.family_confidence])}
          <div class="muted" style="margin-top:4px">${esc(i.family_note)}</div></td></tr>
        ${i.family_analyst ? `<tr><td>Family (analyst)</td><td>${esc(i.family_analyst)}</td></tr>` : ""}
      </tbody></table>
      ${i.family_scores.length ? `<details><summary>Why this family? (weighted signature scores)</summary>
        <div class="family-bars">${i.family_scores.map((s) => `
          <div class="fbar"><span>${esc(s.family)}</span><div class="track"><div class="fill" style="width:${(s.score / maxScore) * 100}%"></div></div><strong>${s.score}</strong></div>
          <ul class="ev" style="margin:0 0 6px 138px">${s.evidence.map((e) => `<li>+${e.weight} ${esc(e.signal)}</li>`).join("")}</ul>`).join("")}
        </div></details>` : ""}`);

    // 2 vector
    const s2 = section(2, "s2", "Infection vector", `
      <div class="callout ${esc(v.gpon_relevance)}"><strong>${esc(REL_LABEL[v.gpon_relevance])}.</strong> ${esc(v.gpon_summary)}</div>
      ${v.vectors.length ? `<div class="table-wrap"><table><thead><tr><th>Vector</th><th>Target</th><th>CVE</th><th>Evidence</th></tr></thead><tbody>
        ${v.vectors.map((x) => `<tr${x.gpon ? ' style="background:var(--crit-soft)"' : ""}>
          <td><strong>${esc(x.name)}</strong>${x.note ? `<div class="muted" style="font-size:12px">${esc(x.note)}</div>` : ""}</td>
          <td>${esc(x.target)}</td><td class="mono">${esc(x.cves.join(", ") || "—")}</td>
          <td>${badge(x.source, "b-src")}${evList(x.evidence)}</td></tr>`).join("")}
      </tbody></table></div>` : `<p class="muted">No infection vector recovered from the supplied analysis.</p>`}`);

    // 3 static
    const s3 = section(3, "s3", "Static findings", `
      <table class="kv"><tbody>${fw.static.findings.map((f) => `<tr><td>${esc(f.label)}</td><td class="${f.label === "File type" ? "mono" : ""}">${esc(f.value)}</td></tr>`).join("")}</tbody></table>
      ${fw.static.http_requests.length ? `<details><summary>${fw.static.http_requests.length} embedded HTTP request template(s)</summary>
        <ul class="ev">${fw.static.http_requests.map((h) => `<li>${esc(h)}</li>`).join("")}</ul></details>` : ""}`);

    // 4 dynamic
    const d = fw.dynamic;
    const s4 = section(4, "s4", "Dynamic findings", `
      <p>${badge(d.level === "observed" ? "behaviour observed" : d.level === "none" ? "no dynamic data" : "partially observed", "b-" + (d.level === "none" ? "high" : d.level))} ${esc(d.verdict)}</p>
      ${d.environments.length ? `<table><thead><tr><th>Environment</th><th>Note</th></tr></thead><tbody>
        ${d.environments.map((e) => `<tr><td><strong>${esc(e.environment)}</strong></td><td>${esc(e.note || "—")}</td></tr>`).join("")}</tbody></table>` : ""}
      ${d.signals.length ? `<h4>Signals detected in dynamic notes</h4><table><tbody>
        ${d.signals.map((s) => `<tr><td style="width:40%">${esc(s.label)}</td><td>${evList(s.evidence)}</td></tr>`).join("")}</tbody></table>` : ""}`);

    // 5 IOCs
    const s5 = section(5, "s5", "IOC pack", `
      <div class="table-wrap"><table><thead><tr><th>Type</th><th>Indicator</th><th>Context</th><th>Confidence</th></tr></thead><tbody>
        ${fw.iocs.map((x) => `<tr><td>${esc(x.type)}</td><td class="mono">${esc(x.value)}</td><td>${esc(x.context)}</td>
          <td>${badge(x.confidence, CONF[x.confidence])}</td></tr>`).join("")}
      </tbody></table></div>
      ${fw.excluded.length ? `<details><summary>${fw.excluded.length} value(s) excluded as sandbox / lab noise</summary>
        <table><tbody>${fw.excluded.map((e) => `<tr><td class="mono">${esc(e.value)}</td><td class="muted">${esc(e.reason)}</td></tr>`).join("")}</tbody></table></details>` : ""}`);

    // 6 ATT&CK
    const s6 = section(6, "s6", "ATT&CK mapping" + (i.platform.startsWith("Android") ? " (Mobile matrix)" : " (Enterprise, Linux/IoT)"), `
      <div class="table-wrap"><table><thead><tr><th>Tactic</th><th>Technique</th><th>ID</th><th>Evidence</th></tr></thead><tbody>
        ${fw.attack.map((a) => `<tr><td>${esc(a.tactic)}</td><td>${esc(a.technique)}</td><td class="mono">${esc(a.tid)}</td>
          <td>${badge(a.source, a.source === "inferred" ? "b-med" : "b-src")}${evList(a.evidence)}</td></tr>`).join("")}
      </tbody></table></div>`);

    // 7 detections
    const det = fw.detections;
    const s7 = section(7, "s7", "Detection package", `
      <h4>YARA</h4>${code(det.yara)}
      <h4>Suricata (${det.suricata.length} rules)</h4>${det.suricata.length ? code(det.suricata.join("\n")) : `<p class="muted">No network indicators to build Suricata rules from (e.g. encrypted C2 config).</p>`}
      <h4>Host hunting commands</h4>${code(det.hunt.join("\n"))}`);

    // 8 operator
    const s8 = section(8, "s8", "Operator framework (FTTH / ISP)", `
      <p><strong>Priority:</strong> ${esc(fw.operator.priority)}</p>
      <div class="phases">${fw.operator.phases.map((p) => `<div class="phase"><h4>${esc(p.phase)}</h4>
        <ul>${p.actions.map((a) => `<li>${esc(a)}</li>`).join("")}</ul></div>`).join("")}</div>
      <details><summary>Risk score breakdown</summary><table><tbody>
        ${r.factors.map((f) => `<tr><td>${esc(f.factor)}</td><td style="width:60px">+${f.points}</td></tr>`).join("")}
        <tr><td><strong>Total (capped at 100)</strong></td><td><strong>${r.score}</strong></td></tr></tbody></table>
        <p class="muted">${esc(r.note)}</p></details>`);

    out.innerHTML = header + s1 + s2 + s3 + s4 + s5 + s6 + s7 + s8;
    $("#toc").hidden = false;
  }

  // ---------------------------------------------------------------- campaign view
  function renderCampaign(c) {
    const ids = c.samples.map((s) => s.id);
    const name = (id) => (c.samples.find((s) => s.id === id) || {}).name || id;
    const strong = c.links.filter((l) => l.strength === "strong");
    const weak = c.links.filter((l) => l.strength !== "strong");
    const clusters = c.clusters.filter((cl) => cl.length > 1);

    out.innerHTML = `
      <div class="report-title"><h2>Campaign view — cross-sample correlation</h2>
        <span class="gen">${c.samples.length} samples · ${strong.length} infrastructure link(s)</span></div>
      <section class="fw"><h3>Sample overview</h3><div class="table-wrap"><table>
        <thead><tr><th>Sample</th><th>Family</th><th>Arch / platform</th><th>Role</th><th>GPON</th><th>Risk</th></tr></thead><tbody>
        ${c.samples.map((s) => `<tr><td><strong>${esc(s.name)}</strong></td><td>${esc(s.family)}</td>
          <td>${esc(s.arch)} <span class="muted">· ${esc(s.platform)}</span></td><td>${esc(s.roles.join(", "))}</td>
          <td>${badge(REL_LABEL[s.gpon], "b-" + s.gpon)}</td><td>${badge(s.risk + " " + s.score, LEVEL[s.risk])}</td></tr>`).join("")}
      </tbody></table></div></section>

      <section class="fw"><h3>Shared infrastructure (campaign clusters)</h3>
        ${clusters.length ? clusters.map((cl) => `<p>${badge("Cluster", "b-crit")} ${cl.map(name).map(esc).join(" ↔ ")}</p>`).join("") : `<p class="muted">No shared C2/payload infrastructure between samples.</p>`}
        <div class="links">${strong.map((l) => `<div class="link-card"><strong>${esc(name(l.a))} ↔ ${esc(name(l.b))}</strong>
          ${Object.entries(l.shared).map(([t, vals]) => `<div><span class="muted">${esc(t)}:</span> <span class="mono">${vals.map(esc).join(", ")}</span></div>`).join("")}</div>`).join("")}</div>
        ${weak.length ? `<details><summary>${weak.length} weak link(s) — same family or architecture only (not proof of shared operator)</summary>
          <table><tbody>${weak.map((l) => `<tr><td>${esc(name(l.a))} ↔ ${esc(name(l.b))}</td><td>${Object.entries(l.shared).map(([t, v]) => esc(t + ": " + v.join(", "))).join("<br>")}</td></tr>`).join("")}</tbody></table></details>` : ""}
      </section>

      <section class="fw"><h3>Exploit coverage matrix</h3><div class="table-wrap"><table class="matrix">
        <thead><tr><th>Vector</th>${ids.map((id) => `<th>${esc(name(id))}</th>`).join("")}</tr></thead><tbody>
        ${c.vector_matrix.map((row) => `<tr${/GPON/.test(row.vector) ? ' style="background:var(--crit-soft)"' : ""}><td>${esc(row.vector)}</td>
          ${ids.map((id) => row.samples[id] ? `<td class="hit">●</td>` : `<td class="miss">·</td>`).join("")}</tr>`).join("")}
      </tbody></table></div></section>`;
  }

  // ---------------------------------------------------------------- misc UI
  out.addEventListener("click", (e) => {
    const b = e.target.closest("[data-copy]");
    if (!b) return;
    navigator.clipboard.writeText(b.nextElementSibling.textContent).then(() => {
      b.textContent = "Copied"; setTimeout(() => (b.textContent = "Copy"), 1200);
    });
  });

  function showInput(show) {
    $("#input-panel").classList.toggle("collapsed", !show);
    $("#btn-toggle-input").textContent = show ? "Hide input" : "Show input";
  }
  $("#btn-toggle-input").addEventListener("click", () => showInput($("#input-panel").classList.contains("collapsed")));

  function toggleExports(on) { ["#btn-md", "#btn-json", "#btn-print"].forEach((s) => ($(s).disabled = !on)); }

  function download(name, blob) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob); a.download = name; a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  }
  const fileBase = () => (current.identity.name || "framework").replace(/[^a-z0-9]+/gi, "_");
  $("#btn-json").addEventListener("click", () =>
    download(fileBase() + "_framework.json", new Blob([JSON.stringify(current, null, 2)], { type: "application/json" })));
  $("#btn-md").addEventListener("click", async () => {
    const res = await fetch("/api/export/markdown", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(current) });
    download(fileBase() + "_framework.md", await res.blob());
  });
  $("#btn-print").addEventListener("click", () => {
    document.querySelectorAll("#output details").forEach((d) => (d.open = true));
    window.print();
  });

  loadSampleList().then(() => {
    out.innerHTML = hasSamples
      ? `<div class="card empty">Pick an analysed sample on the left, open the <strong>Campaign view</strong>, or paste a new analysis above.</div>`
      : `<div class="card empty">Paste your static and dynamic analysis results above (or upload files), then click <strong>Generate framework</strong>.</div>`;
  });
})();

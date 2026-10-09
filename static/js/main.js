const PLAIN = {
  Malicious: {title: "Dangerous — stay away", action: "Do NOT open this link, and never type passwords or card details into it. Delete the message it came in. If you already opened it, tell your IT/security person now."},
  Uncertain: {title: "Not sure — ask for help", action: "We could not give a clear answer. Do not log in through this link. If it claims to be your bank or school, type their address yourself instead, or ask someone technical to check it."},
  Legitimate: {title: "Looks safe", action: "No warning signs found. Still: if this arrived unexpectedly asking for money or passwords, stay cautious — no checker is perfect."}
};
const esc = s => String(s).replace(/[&<>"']/g, c => ({"&":"&amp;","<":"&lt;",">":"&gt;",'"':"&quot;","'":"&#39;"}[c]));

document.getElementById("f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = document.getElementById("url").value.trim();
  const out = document.getElementById("out");
  const btn = e.target.querySelector("button");
  btn.disabled = true; btn.textContent = "Checking…";
  out.hidden = false;
  out.innerHTML = '<div class="card"><p>Examining the address safely (we never open it)…</p></div>';
  try {
    const r = await fetch("/predict", {method: "POST",
      headers: {"Content-Type": "application/json"}, body: JSON.stringify({url})});
    const d = await r.json();
    if (!r.ok) { out.innerHTML = `<div class="error">${esc(d.error || "Something went wrong.")}</div>`; return; }
    const ui = PLAIN[d.verdict] || PLAIN.Uncertain;
    const pct = Math.round(d.confidence);
    const factors = (d.explanation.factors || []).map(f => {
      const warn = f.direction === "malicious";
      return `<li class="${warn ? "malicious" : "legitimate"}"><span class="tag">${warn ? "Warning sign" : "Reassuring"}</span>${esc(f.reason)}</li>`;
    }).join("");
    const host = d.tier2 && d.tier2.signals && d.tier2.signals.source !== "unavailable"
      ? `<p class="host">Extra background check on <strong>${esc(d.tier2.host)}</strong>: ${d.tier2.escalated_to !== "Uncertain" ? "this decided the result." : "no clear answer from it."}</p>` : "";
    out.innerHTML = `
      <div class="card">
        <p class="badge ${d.verdict}">${ui.title}</p>
        <p class="conf">Checked: <strong>${esc(d.url)}</strong> · certainty ${pct}%</p>
        <div class="meter ${d.verdict}"><div style="width:${pct}%"></div></div>
        <p class="why">${esc(d.explanation.summary)}</p>
        ${factors ? `<h3>What we noticed</h3><ul class="factors">${factors}</ul>` : ""}
        ${host}
        <div class="action ${d.verdict}"><strong>What should you do?</strong> ${ui.action}</div>
        <details class="tech"><summary>Technical details (for IT staff)</summary><pre>${esc(JSON.stringify(d, null, 2))}</pre></details>
      </div>`;
  } catch {
    out.innerHTML = '<div class="error">Could not reach the checker. It may be waking up — wait 30 seconds and try again.</div>';
  } finally {
    btn.disabled = false; btn.textContent = "Check link";
  }
});

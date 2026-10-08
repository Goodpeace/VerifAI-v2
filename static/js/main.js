document.getElementById("f").addEventListener("submit", async (e) => {
  e.preventDefault();
  const url = document.getElementById("url").value;
  const out = document.getElementById("out");
  out.textContent = "Analyzing…";
  const r = await fetch("/predict", {method: "POST",
    headers: {"Content-Type": "application/json"}, body: JSON.stringify({url})});
  out.textContent = JSON.stringify(await r.json(), null, 2);
});

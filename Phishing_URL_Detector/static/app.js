const urlInput = document.getElementById("url");
const analyzeBtn = document.getElementById("analyze");
const results = document.getElementById("results");
const errorBox = document.getElementById("error");

function labelize(name) {
  return name.replaceAll("_", " ");
}

function render(data) {
  results.classList.remove("hidden");
  document.getElementById("score").textContent = data.risk_score;
  document.getElementById("prediction").textContent = data.prediction;
  document.getElementById("confidence").textContent = `${data.confidence}%`;
  document.getElementById("meterFill").style.width = `${data.risk_score}%`;

  const reasons = document.getElementById("reasons");
  reasons.innerHTML = data.explanation.map(x => `<li>${x}</li>`).join("");

  const featureBox = document.getElementById("features");
  featureBox.innerHTML = data.feature_names.map(name => `
    <div class="feature">
      <span>${labelize(name)}</span>
      <strong>${data.features[name]}</strong>
    </div>
  `).join("");
}

async function analyze() {
  errorBox.classList.add("hidden");
  const url = urlInput.value.trim();
  if (!url) {
    errorBox.textContent = "Enter a URL first.";
    errorBox.classList.remove("hidden");
    return;
  }

  analyzeBtn.disabled = true;
  analyzeBtn.textContent = "Analyzing...";

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: {"Content-Type": "application/json"},
      body: JSON.stringify({url})
    });
    const data = await response.json();
    if (!response.ok) throw new Error(data.error || "Analysis failed.");
    render(data);
  } catch (err) {
    errorBox.textContent = err.message;
    errorBox.classList.remove("hidden");
  } finally {
    analyzeBtn.disabled = false;
    analyzeBtn.textContent = "Analyze";
  }
}

analyzeBtn.addEventListener("click", analyze);
urlInput.addEventListener("keydown", e => {
  if (e.key === "Enter") analyze();
});

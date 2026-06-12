const app = {
  history: [],
  filteredHistory: [],
  latestScan: null,
  featureDocs: [],
  performanceRows: [],
  charts: {},
  page: 1,
  pageSize: 8,
  sortKey: "time",
  sortDirection: "desc",
};

const $ = (selector) => document.querySelector(selector);
const $$ = (selector) => Array.from(document.querySelectorAll(selector));

document.addEventListener("DOMContentLoaded", () => {
  bindEvents();
  loadPerformanceMetadata();
  renderEmptyFeatureCharts();
  loadHistory();
});

function bindEvents() {
  $("#scan-form").addEventListener("submit", handleScan);
  $("#feedback-form").addEventListener("submit", handleFeedback);
  $("#export-history").addEventListener("click", exportHistoryCsv);
  $("#delete-history").addEventListener("click", deleteHistory);
  $("#history-search").addEventListener("input", () => { app.page = 1; renderHistory(); });
  $("#history-filter").addEventListener("change", () => { app.page = 1; renderHistory(); });
  $("#feature-search").addEventListener("input", handleFeatureSearch);
  $("#prev-page").addEventListener("click", () => changePage(-1));
  $("#next-page").addEventListener("click", () => changePage(1));
  $("#theme-toggle").addEventListener("click", toggleTheme);
  $$(".cyber-table th[data-sort]").forEach((th) => th.addEventListener("click", () => sortHistory(th.dataset.sort)));
}

async function api(path, options = {}) {
  const response = await fetch(path, {
    headers: { "Content-Type": "application/json" },
    ...options,
  });
  const payload = await response.json().catch(() => ({}));
  if (!response.ok || payload.success === false) {
    throw new Error(payload.message || "Request failed.");
  }
  return payload.data ?? payload;
}

function validateUrl(value) {
  const url = normalizeUrl(value);
  if (!url) return { valid: false, message: "Enter a URL to analyze." };
  if (/\s/.test(url)) {
    return { valid: false, message: "Enter a domain or URL (example: facebook.com or https://facebook.com)." };
  }
  try {
    const parsed = new URL(url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      return { valid: false, message: "Only public http(s) URLs can be scanned." };
    }
    if (parsed.username || parsed.password) {
      return { valid: false, message: "URLs with embedded credentials are blocked." };
    }
    if (!parsed.hostname.includes(".") && !/^\[[0-9a-fA-F:.]+\]$|^[0-9.]+$/.test(parsed.hostname)) {
      return { valid: false, message: "Enter a domain or URL (example: facebook.com or https://facebook.com)." };
    }
    return { valid: true, url };
  } catch {
    return { valid: false, message: "Enter a domain or URL (example: facebook.com or https://facebook.com)." };
  }
}

function normalizeUrl(value) {
  let url = value.trim();
  const markdownLink = url.match(/^\[([^\]]+)\]\(([^)]+)\)$/);
  if (markdownLink) {
    url = markdownLink[1].trim() || markdownLink[2].trim();
  }

  if (!url.startsWith("http://") && !url.startsWith("https://") && !/^[a-zA-Z][a-zA-Z0-9+.-]*:/.test(url)) {
    url = "https://" + url;
  }

  return url;
}

async function handleScan(event) {
  event.preventDefault();
  const check = validateUrl($("#url-input").value);
  if (!check.valid) {
    setStatus(check.message, true);
    showToast(check.message, "danger");
    return;
  }

  setLoading(true);
  setStatus("Analyzing URL with feature extraction and model inference...");
  $("#result-section").classList.add("d-none");

  try {
    const data = await api("/api/scan", {
      method: "POST",
      body: JSON.stringify({ url: $("#url-input").value.trim() }),
    });
    app.latestScan = data;
    renderResult(data);
    renderFeatureCharts(data);
    setStatus("Analysis complete.");
    showToast("Scan completed successfully.", "success");
    await loadHistory(false);
  } catch (error) {
    setStatus(error.message, true);
    showToast(error.message, "danger");
  } finally {
    setLoading(false);
  }
}

function setLoading(isLoading) {
  const button = $("#scan-button");
  button.disabled = isLoading;
  button.querySelector(".btn-label").textContent = isLoading ? "Analyzing..." : "Analyze URL";
  button.querySelector(".spinner-border").classList.toggle("d-none", !isLoading);
}

function setStatus(message, isError = false) {
  const status = $("#scan-status");
  status.textContent = message;
  status.classList.toggle("error", isError);
}

function renderResult(data) {
  const resultSection = $("#result-section");
  const finalVerdict = String(data.final_result || "").toUpperCase();
  const resultState = getSecurityResultState(finalVerdict);
  const chartSkeleton = $("#chart-skeleton");
  if (chartSkeleton) chartSkeleton.classList.add("d-none");

  resultSection.innerHTML = `
    <div class="security-result ${resultState.tone}">
      <div class="scanned-url">${escapeHtml(data.original_url || data.url || "")}</div>
      <div class="security-icon" aria-hidden="true">${resultState.icon}</div>
      <h1>${resultState.title}</h1>
      <p class="result-message">${resultState.message}</p>
      <div class="model-predictions-card">
        <h2>MODEL PREDICTIONS</h2>
        ${modelPredictionRow("Random Forest", data.forest_result, data.forest_risk)}
        ${modelPredictionRow("Naive Bayes", data.bayes_result, data.bayes_risk)}
      </div>
    </div>
  `;
  resultSection.classList.remove("d-none");
  resultSection.scrollIntoView({ behavior: "smooth", block: "center" });
}

function displayUrl(result) {
  return result.original_url || result.url || "";
}

function modelPredictionRow(modelName, result, risk) {
  const display = modelLabel(result);
  const confidence = modelConfidence(toNumber(risk), result);
  return `
    <div class="model-prediction-row">
      <span>${escapeHtml(modelName)}</span>
      <strong class="${statusClass(result)}">${escapeHtml(display)}</strong>
      <small>${escapeHtml(modelName)} Confidence: ${formatPercent(confidence)}</small>
    </div>
  `;
}

function modelLabel(result) {
  const value = String(result || "").toUpperCase();
  if (value.includes("PHISHING")) return "Phishing";
  if (value.includes("SAFE") || value.includes("LEGITIMATE")) return "Safe";
  return "Unknown";
}

function getSecurityResultState(finalVerdict) {
  if (finalVerdict.includes("SAFE") || finalVerdict.includes("LEGITIMATE")) {
    return {
      tone: "safe",
      icon: "&#128737;&#65039;",
      title: "YOU'RE SAFE",
      message: "This website appears legitimate and no phishing indicators were detected.",
    };
  }

  if (finalVerdict.includes("MEDIUM")) {
    return {
      tone: "medium-risk",
      icon: "&#9888;&#65039;",
      title: "USE CAUTION",
      message: "This URL shows suspicious signals. Review it carefully before sharing information.",
    };
  }

  return {
    tone: "high-risk",
    icon: "&#9888;&#65039;",
    title: "DANGEROUS WEBSITE",
    message: "This URL contains phishing indicators and may be unsafe.",
  };
}

function renderRiskCard(selector, item) {
  const tone = statusClass(item.status);
  const barColor = tone === "safe" ? "var(--success)" : tone === "medium-risk" ? "var(--warning)" : "var(--danger)";
  $(selector).innerHTML = `
    <div class="risk-top">
      <h3>${escapeHtml(item.title)}</h3>
      <span class="status-badge ${tone}">${escapeHtml(item.status || "UNKNOWN")}</span>
    </div>
    <div class="risk-score ${tone}">${formatPercent(item.risk)}</div>
    <div class="confidence">Confidence Score: ${formatPercent(item.confidence)}</div>
    <div class="progress" role="progressbar" aria-valuenow="${item.risk}" aria-valuemin="0" aria-valuemax="100">
      <div class="progress-bar" style="width:${clamp(item.risk)}%; background:${barColor}"></div>
    </div>
  `;
}

async function loadHistory(showMessage = true) {
  try {
    const history = await api("/api/history?limit=500");
    app.history = Array.isArray(history) ? history : [];
    renderHistory();
    if (showMessage) showToast("History refreshed.", "success");
  } catch (error) {
    showToast(error.message, "danger");
  }
}

function renderHistory() {
  const query = $("#history-search").value.trim().toLowerCase();
  const filter = $("#history-filter").value;
  app.filteredHistory = app.history.filter((row) => {
    const matchesQuery = [displayUrl(row), row.final_result, row.time].some((value) => String(value || "").toLowerCase().includes(query));
    const matchesFilter = filter === "ALL" || row.final_result === filter;
    return matchesQuery && matchesFilter;
  }).sort(compareRows);

  const totalPages = Math.max(Math.ceil(app.filteredHistory.length / app.pageSize), 1);
  app.page = Math.min(app.page, totalPages);
  const start = (app.page - 1) * app.pageSize;
  const pageRows = app.filteredHistory.slice(start, start + app.pageSize);

  $("#history-body").innerHTML = pageRows.length ? pageRows.map((row) => `
    <tr>
      <td>${escapeHtml(displayUrl(row))}</td>
      <td>${riskCell(row.forest_risk)}</td>
      <td>${riskCell(row.bayes_risk)}</td>
      <td><span class="status-badge ${statusClass(row.final_result)}">${escapeHtml(row.final_result || "")}</span></td>
      <td>${escapeHtml(row.time || "")}</td>
    </tr>
  `).join("") : `<tr><td colspan="5" class="text-center text-secondary py-4">No scan history found.</td></tr>`;

  $("#history-count").textContent = `${app.filteredHistory.length} records - page ${app.page} of ${totalPages}`;
  $("#prev-page").disabled = app.page <= 1;
  $("#next-page").disabled = app.page >= totalPages;
}

function sortHistory(key) {
  if (app.sortKey === key) {
    app.sortDirection = app.sortDirection === "asc" ? "desc" : "asc";
  } else {
    app.sortKey = key;
    app.sortDirection = "asc";
  }
  renderHistory();
}

function compareRows(a, b) {
  const key = app.sortKey;
  const av = key.includes("risk") ? toNumber(a[key]) : String(key === "url" ? displayUrl(a) : a[key] || "");
  const bv = key.includes("risk") ? toNumber(b[key]) : String(key === "url" ? displayUrl(b) : b[key] || "");
  const result = av > bv ? 1 : av < bv ? -1 : 0;
  return app.sortDirection === "asc" ? result : -result;
}

function changePage(delta) {
  app.page += delta;
  renderHistory();
}

function exportHistoryCsv() {
  const rows = app.filteredHistory.length ? app.filteredHistory : app.history;
  const headers = ["URL", "Forest Risk", "Bayes Risk", "Verdict", "Date"];
  const csvRows = [headers, ...rows.map((row) => [displayUrl(row), row.forest_risk, row.bayes_risk, row.final_result, row.time])];
  const blob = new Blob([csvRows.map((row) => row.map(csvEscape).join(",")).join("\n")], { type: "text/csv;charset=utf-8" });
  const link = document.createElement("a");
  link.href = URL.createObjectURL(blob);
  link.download = `ai-cyber-shield-history-${new Date().toISOString().slice(0, 10)}.csv`;
  link.click();
  URL.revokeObjectURL(link.href);
  showToast("CSV export generated.", "success");
}

async function deleteHistory() {
  try {
    await api("/api/history", { method: "DELETE" });  // ✅ FIX

    app.history = [];

    showToast("History deleted on server.", "success");

    await loadHistory(false);  // ✅ reload lại từ server
  } catch (error) {
    showToast(error.message, "danger");
  }

  app.page = 1;
  renderHistory();
}

async function handleFeedback(event) {
  event.preventDefault();
  if (!app.latestScan) {
    showToast("Run a scan before submitting feedback.", "warning");
    return;
  }
  const payload = {
    url: app.latestScan.url,
    predicted_result: app.latestScan.final_result,
    user_feedback: document.querySelector("input[name='prediction_correct']:checked").value,
    actual_label: document.querySelector("input[name='actual_label']:checked").value,
    forest_risk: app.latestScan.forest_risk,
    bayes_risk: app.latestScan.bayes_risk,
  };
  try {
    await api("/api/feedback", { method: "POST", body: JSON.stringify(payload) });
    showToast("Feedback submitted.", "success");
  } catch (error) {
    showToast(error.message, "danger");
  }
}

function renderFeatureCharts(data) {
  $("#chart-skeleton").classList.add("d-none");
  $("#feature-charts").classList.remove("d-none");
  const entries = Object.entries(data.features || {});
  const labels = entries.map(([name]) => name);
  const values = entries.map(([, value]) => toNumber(value));
  const importance = entries.map(([, value], index) => Math.max(8, 100 - index * 7 + Math.abs(toNumber(value)) * 3));

  createChart("featureImportanceChart", "bar", {
    labels,
    datasets: [{ label: "Importance", data: importance, backgroundColor: "#00ADB5" }],
  }, true);
  createChart("featureValueChart", "bar", {
    labels,
    datasets: [{ label: "Feature Value", data: values, backgroundColor: values.map((value) => value < 0 ? "#FF4B4B" : value === 0 ? "#FFD43B" : "#00FF7F") }],
  }, true);
  createChart("radarSecurityChart", "radar", {
    labels: ["Domain", "HTML", "Lexical", "Model"],
    datasets: [{ label: "Security Posture", data: radarValues(data.features || {}), borderColor: "#00ADB5", backgroundColor: "rgba(0,173,181,0.2)" }],
  });
}

function renderEmptyFeatureCharts() {
  setTimeout(() => {
    if (!app.latestScan) {
      $("#chart-skeleton").classList.add("d-none");
      $("#feature-charts").classList.remove("d-none");
      renderFeatureCharts({ features: Object.fromEntries(app.featureDocs.map((feature) => [feature.name, 0])) });
    }
  }, 500);
}

async function loadPerformanceMetadata() {
  try {
    const metadata = await api("/api/performance");
    app.performanceRows = Array.isArray(metadata.performance_rows) ? metadata.performance_rows : [];
    app.featureDocs = buildFeatureDocs(metadata.feature_columns || []);
    renderFeatureDocs(app.featureDocs);
    renderFeatureCount(metadata);
    renderPerformance(metadata);
  } catch (error) {
    renderFeatureDocs([]);
    renderFeatureCount({ feature_count: 0 });
    renderPerformanceWarning([error.message]);
    renderPerformance({ performance_rows: [], images: {}, warnings: [error.message] });
  }
}

function renderPerformance(metadata = {}) {
  const rows = Array.isArray(metadata.performance_rows) ? metadata.performance_rows : app.performanceRows;
  const headers = tableHeaders(rows);
  $("#performance-head").innerHTML = headers.length ? `<tr>${headers.map((header) => `<th>${escapeHtml(header)}</th>`).join("")}</tr>` : "";
  $("#performance-body").innerHTML = rows.length ? rows.map((row) => `
    <tr>${headers.map((header) => `<td>${formatTableValue(row[header])}</td>`).join("")}</tr>
  `).join("") : `<tr><td colspan="${Math.max(headers.length, 1)}" class="text-center text-secondary py-4">No performance CSV data found.</td></tr>`;

  renderPerformanceImages(metadata.images || {});
  renderPerformanceWarning(metadata.warnings || []);

  const algorithmKey = findHeader(headers, ["algorithm", "thuật toán", "thuat toan", "model"]);
  const accuracyKey = findHeader(headers, ["accuracy"]);
  const precisionKey = findHeader(headers, ["precision"]);
  const recallKey = findHeader(headers, ["recall"]);
  const f1Key = findHeader(headers, ["f1-score", "f1 score", "f1"]);

  const labels = rows.map((row) => row[algorithmKey] || "Model");
  createChart("accuracyChart", "bar", {
    labels,
    datasets: [{ label: "Accuracy", data: rows.map((row) => toNumber(row[accuracyKey])), backgroundColor: ["#FFD43B", "#00ADB5"] }],
  });
  createChart("scoreChart", "bar", {
    labels,
    datasets: [
      { label: "Precision", data: rows.map((row) => toNumber(row[precisionKey])), backgroundColor: "#00ADB5" },
      { label: "Recall", data: rows.map((row) => toNumber(row[recallKey])), backgroundColor: "#00FF7F" },
      { label: "F1 Score", data: rows.map((row) => toNumber(row[f1Key])), backgroundColor: "#FFD43B" },
    ],
  });
}

function renderPerformanceImages(images) {
  const imageList = ["rf_confusion_matrix", "nb_confusion_matrix", "feature_importance"]
    .map((key) => images[key])
    .filter(Boolean);
  $("#performance-images").innerHTML = imageList.map((image) => {
    if (!image.exists || !image.url) {
      return `
        <figure class="glass-card image-card missing">
          <h3>${escapeHtml(image.title || image.filename)}</h3>
          <div class="asset-warning">Warning: ${escapeHtml(image.filename)} not found.</div>
        </figure>
      `;
    }
    return `
      <figure class="glass-card image-card">
        <h3>${escapeHtml(image.title)}</h3>
        <img src="${escapeHtml(image.url)}" alt="${escapeHtml(image.title)}" loading="lazy">
        
      </figure>
    `;
  }).join("");
}

function renderPerformanceWarning(warnings) {
  const warningEl = $("#performance-warning");
  const messages = (warnings || []).filter(Boolean);
  warningEl.textContent = messages.join(" ");
  warningEl.classList.toggle("d-none", messages.length === 0);
}

function renderFeatureCount(metadata) {
  const currentCount = metadata.feature_count || 0;
  const modelCount = metadata.model_feature_count || currentCount;
  const featureCount = $("#feature-count");
  if (featureCount) {
    featureCount.textContent = `Current Feature Count: ${currentCount} | Model Feature Count: ${modelCount}`;
  }
  const performanceFeatureCount = $("#performance-feature-count");
  if (performanceFeatureCount) {
    performanceFeatureCount.textContent = `Current Feature Count: ${currentCount}`;
  }
}

function buildFeatureDocs(featureColumns) {
  return featureColumns.map((name) => ({
    name,
    description: `Model input feature: ${humanizeFeatureName(name)}.`,
    category: inferFeatureCategory(name),
    impact: "Model",
  }));
}

function tableHeaders(rows) {
  const firstRow = rows.find((row) => row && typeof row === "object");
  return firstRow ? Object.keys(firstRow) : [];
}

function findHeader(headers, candidates) {
  const normalizedCandidates = candidates.map(normalizeHeader);
  return headers.find((header) => normalizedCandidates.includes(normalizeHeader(header))) || "";
}

function normalizeHeader(header) {
  return String(header || "")
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .toLowerCase()
    .trim();
}

function formatTableValue(value) {
  const numeric = Number(value);
  if (Number.isFinite(numeric) && String(value).trim() !== "") {
    return escapeHtml(numeric.toFixed(4));
  }
  return escapeHtml(value);
}

function humanizeFeatureName(name) {
  return String(name || "").replaceAll("_", " ").replace(/\s+/g, " ").trim();
}

function inferFeatureCategory(name) {
  const value = String(name || "").toLowerCase();
  if (/(favicon|request|anchor|links|sfh|submit|iframe|popup|mouseover|right)/.test(value)) return "HTML";
  if (/(domain|dns|ssl|https|port|traffic|google|statistical)/.test(value)) return "Domain";
  if (/(redirect|short|url|symbol|prefix|ip)/.test(value)) return "Lexical";
  return "Model";
}

function renderFeatureDocs(features) {
  $("#feature-docs").innerHTML = features.map((feature) => `
    <article class="feature-doc glass-card">
      <h3>${escapeHtml(feature.name)}</h3>
      <div class="feature-meta">
        <span class="chip">${escapeHtml(feature.category)}</span>
        <span class="chip">${escapeHtml(feature.impact)} Impact</span>
      </div>
      <p>${escapeHtml(feature.description)}</p>
    </article>
  `).join("");
}

function handleFeatureSearch(event) {
  const query = event.target.value.trim().toLowerCase();
  const filtered = app.featureDocs.filter((feature) => Object.values(feature).some((value) => String(value).toLowerCase().includes(query)));
  renderFeatureDocs(filtered);
}

function createChart(id, type, data, horizontal = false) {
  const canvas = document.getElementById(id);
  if (!canvas || typeof Chart === "undefined") return;
  if (app.charts[id]) app.charts[id].destroy();
  app.charts[id] = new Chart(canvas, {
    type,
    data,
    options: {
      responsive: true,
      maintainAspectRatio: false,
      indexAxis: horizontal ? "y" : "x",
      plugins: {
        legend: { labels: { color: chartTextColor(), boxWidth: 12 } },
      },
      scales: type === "doughnut" || type === "radar" ? radarScales(type) : cartesianScales(),
    },
  });
}

function cartesianScales() {
  return {
    x: { ticks: { color: chartTextColor() }, grid: { color: "rgba(154,167,184,0.12)" } },
    y: { beginAtZero: true, ticks: { color: chartTextColor() }, grid: { color: "rgba(154,167,184,0.12)" } },
  };
}

function radarScales(type) {
  if (type !== "radar") return {};
  return {
    r: {
      beginAtZero: true,
      max: 100,
      angleLines: { color: "rgba(154,167,184,0.2)" },
      grid: { color: "rgba(154,167,184,0.16)" },
      pointLabels: { color: chartTextColor() },
      ticks: { color: chartTextColor(), backdropColor: "transparent" },
    },
  };
}

function radarValues(features) {
  const groups = { Domain: [], HTML: [], Lexical: [], Model: [] };
  Object.entries(features).forEach(([name, value]) => {
    const category = inferFeatureCategory(name);
    groups[groups[category] ? category : "Model"].push(toNumber(value));
  });
  return Object.values(groups).map((values) => {
    if (!values.length) return 50;
    const avg = values.reduce((sum, value) => sum + value, 0) / values.length;
    return Math.round(((avg + 1) / 2) * 100);
  });
}

function toggleTheme() {
  const root = document.documentElement;
  const next = root.dataset.theme === "dark" ? "light" : "dark";
  root.dataset.theme = next;
  $("#theme-icon").textContent = next === "dark" ? "☾" : "☀";
  Object.values(app.charts).forEach((chart) => {
    chart.options.plugins.legend.labels.color = chartTextColor();
    chart.update();
  });
}

function showToast(message, type = "success") {
  const toastEl = $("#app-toast");
  toastEl.querySelector(".toast-body").textContent = message;
  toastEl.style.borderColor = type === "danger" ? "var(--danger)" : type === "warning" ? "var(--warning)" : "var(--line)";
  if (window.bootstrap?.Toast) {
    bootstrap.Toast.getOrCreateInstance(toastEl, { delay: 3200 }).show();
    return;
  }
  console[type === "danger" ? "error" : "log"](message);
}

function modelConfidence(risk, status) {
  return String(status || "").includes("PHISHING") ? risk : 100 - risk;
}

function statusClass(status) {
  const value = String(status || "").toUpperCase();
  if (value.includes("SAFE") || value.includes("LEGITIMATE")) return "safe";
  if (value.includes("MEDIUM")) return "medium-risk";
  return "phishing";
}

function riskCell(value) {
  const risk = toNumber(value);
  return `<span class="${risk >= 85 ? "phishing" : risk >= 45 ? "medium-risk" : "safe"}">${formatPercent(risk)}</span>`;
}

function toNumber(value) {
  const parsed = Number(value);
  return Number.isFinite(parsed) ? parsed : 0;
}

function clamp(value) {
  return Math.min(Math.max(toNumber(value), 0), 100);
}

function formatPercent(value) {
  return `${clamp(value).toFixed(2)}%`;
}

function formatDecimal(value) {
  return Number(value).toFixed(4);
}

function csvEscape(value) {
  return `"${String(value ?? "").replaceAll('"', '""')}"`;
}

function chartTextColor() {
  return getComputedStyle(document.documentElement).getPropertyValue("--text").trim() || "#F5F5F5";
}

function escapeHtml(value) {
  return String(value ?? "")
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#039;");
}

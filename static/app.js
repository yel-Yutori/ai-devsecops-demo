const $ = (id) => document.getElementById(id);
const codeBox = $("code");
const scanBtn = $("btn-scan");

function updateCounter() {
  $("counter").textContent = codeBox.value.length + " / " + codeBox.maxLength;
}

async function loadSample(name) {
  const res = await fetch("/static/samples/" + name + ".txt");
  codeBox.value = await res.text();
  updateCounter();
  $("result").classList.add("hidden");
}

function text(tag, className, content) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  node.textContent = content;
  return node;
}

function showVerdict(kind, message) {
  $("result").classList.remove("hidden");
  const verdict = $("verdict");
  verdict.className = "verdict " + kind;
  verdict.textContent = message;
}

function render(data) {
  showVerdict(data.passed ? "pass" : "fail",
    data.passed ? "✓ 通過：可以進入下一關" : "✗ 未通過：不會被部署");

  const stages = $("stages");
  stages.replaceChildren();
  const marks = { pass: "✓", fail: "✗", skip: "–" };
  for (const stage of data.stages) {
    const row = document.createElement("li");
    row.className = stage.status;
    row.append(text("span", "mark", marks[stage.status] || "?"),
               text("span", "", stage.name),
               text("span", "detail", stage.detail));
    stages.append(row);
  }

  const list = $("issues");
  list.replaceChildren();
  $("issues-title").classList.toggle("hidden", data.issues.length === 0);
  for (const issue of data.issues) {
    const row = document.createElement("li");
    row.className = issue.severity;
    row.append(text("div", "", issue.title),
               text("div", "meta", issue.severity + " ｜ " + issue.id + " ｜ 第 " + issue.line + " 行"));
    list.append(row);
  }
}

async function scan() {
  scanBtn.disabled = true;
  scanBtn.textContent = "檢查中…";
  try {
    const res = await fetch("/api/scan", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ code: codeBox.value }),
    });
    const data = await res.json();
    if (!res.ok) {
      showVerdict("error", data.error || "發生錯誤");
      $("stages").replaceChildren();
      $("issues").replaceChildren();
      $("issues-title").classList.add("hidden");
    } else {
      render(data);
    }
  } catch (err) {
    showVerdict("error", "連不上伺服器，請稍後再試");
  } finally {
    scanBtn.disabled = false;
    scanBtn.textContent = "送出檢查";
  }
}

codeBox.addEventListener("input", updateCounter);
scanBtn.addEventListener("click", scan);
$("btn-vuln").addEventListener("click", () => loadSample("vulnerable"));
$("btn-safe").addEventListener("click", () => loadSample("safe"));
$("btn-clear").addEventListener("click", () => {
  codeBox.value = "";
  updateCounter();
  $("result").classList.add("hidden");
});
updateCounter();

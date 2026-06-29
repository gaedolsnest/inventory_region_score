const DATA_URL = "webdata.bin";
const MAGIC = new TextEncoder().encode("SCOREENC\n");
const SALT_LEN = 16;
const NONCE_LEN = 12;
const PBKDF2_ITERS = 200000;
const INTERNAL_PASSPHRASE = "ABCMART_SCOREAPP_INTERNAL_KEY_V1_WEB";
const MASTER_KEY = "audit2026!";
const REGION_MANAGERS = {
  "강원지역": "임동주 지역장", "경남지역": "조우리 지역장", "경북지역": "장규호 지역장",
  "남동지역": "이하림 지역장", "남서지역": "유영찬 지역장", "대경지역": "박양근 지역장",
  "동남지역": "박진선 지역장", "동북지역": "김대훈 지역장", "부경지역": "박근탁 지역장",
  "온더스팟": "김현지 수석", "북동지역": "강민혁 지역장", "북서지역": "하민철 지역장",
  "서남지역": "김잔디 지역장", "서북지역": "김영호 지역장", "전남지역": "최우석 지역장",
  "전북지역": "최승문 지역장", "제주지역": "박준길 지역장", "중남지역": "조재광 지역장",
  "중부지역": "김영규 지역장", "중서지역": "김동순 지역장", "충남지역": "윤영보 지역장",
  "충북지역": "변혜영 지역장"
};

let dataObj = null;
let currentQuarter = null;
let currentQuarterData = null;
let selectedLoginDd = null;
let currentDd = null;
let isMaster = false;
let peopleRows = [];
let selectedPersonKey = null;

const $ = (id) => document.getElementById(id);
const norm = (s) => String(s || "").replace(/\s+/g, "").trim().toLowerCase();
const fmt2 = (v) => {
  const n = Number(v);
  return Number.isFinite(n) ? n.toLocaleString("ko-KR", { minimumFractionDigits: 2, maximumFractionDigits: 2 }) : "-";
};
const avg = (arr) => arr.length ? arr.reduce((a, b) => a + b, 0) / arr.length : null;
const scoreClass = (v) => Number(v) < 85 ? "score-high" : "";
const deltaClass = (v) => !Number.isFinite(v) ? "" : v < 0 ? "bad" : v > 0 ? "good" : "";
const fmtDelta = (v, empty = "N/A") => {
  if (!Number.isFinite(v)) return empty;
  if (Math.abs(v) < 0.005) return "0.00";
  return (v > 0 ? "+" : "") + fmt2(v);
};
const personKey = (r) => {
  const emp = norm(r.emp);
  return emp ? "emp:" + emp : "name:" + norm((r.name || "") + "|" + (r.pos || ""));
};

function noteInfo(item) {
  if (!item) return null;
  const raw = String(item.note_raw || item.note || "").trim();
  const type = item.note_type || (raw.includes("대체") ? "replacement" : raw.includes("인수인계") ? "handover" : "");
  const label = item.note || (type === "replacement" ? "대체" : type === "handover" ? "인수인계" : "");
  return label ? { label, type } : null;
}

function noteBadge(item) {
  const info = noteInfo(item);
  return info ? '<em class="note-badge ' + info.type + '">' + info.label + '</em>' : "";
}

function getSearchInput() {
  return $("qInputInline") || $("qInput");
}

function setStatus(text) {
  $("sessionBadge").innerHTML = '<span class="dot"></span> ' + text;
}

function regionManager(region) {
  return REGION_MANAGERS[region] || "";
}

async function pbkdf2Key(passphrase, salt) {
  const baseKey = await crypto.subtle.importKey("raw", new TextEncoder().encode(passphrase), "PBKDF2", false, ["deriveKey"]);
  return crypto.subtle.deriveKey({ name: "PBKDF2", salt, iterations: PBKDF2_ITERS, hash: "SHA-256" }, baseKey, { name: "AES-GCM", length: 256 }, false, ["decrypt"]);
}

function startsWithMagic(buf) {
  const u = new Uint8Array(buf);
  if (u.length < MAGIC.length) return false;
  for (let i = 0; i < MAGIC.length; i++) if (u[i] !== MAGIC[i]) return false;
  return true;
}

async function decryptBlob(arrayBuffer) {
  if (!startsWithMagic(arrayBuffer)) throw new Error("Invalid webdata.bin");
  const u = new Uint8Array(arrayBuffer);
  let off = MAGIC.length;
  const salt = u.slice(off, off + SALT_LEN); off += SALT_LEN;
  const nonce = u.slice(off, off + NONCE_LEN); off += NONCE_LEN;
  const ct = u.slice(off);
  const key = await pbkdf2Key(INTERNAL_PASSPHRASE, salt);
  const plain = await crypto.subtle.decrypt({ name: "AES-GCM", iv: nonce }, key, ct);
  return new TextDecoder("utf-8").decode(plain);
}

async function loadData() {
  setStatus("데이터 로드 중");
  const res = await fetch(DATA_URL, { cache: "no-store" });
  if (!res.ok) throw new Error("webdata 로드 실패: " + res.status);
  dataObj = JSON.parse(await decryptBlob(await res.arrayBuffer()));
  setCurrentQuarter(dataObj.defaultQuarter || "2026Q1");
  fillQuarterControls();
  fillRegionsForQuarter();
  setStatus("지역 선택 대기");
}

function quarterEntries() {
  return Object.entries(dataObj.quarters || {}).map(([id, data]) => ({
    id,
    label: formatQuarterLabel(id, data.label),
    data,
    rank: quarterRank(id),
  })).sort((a, b) => a.rank - b.rank);
}

function formatQuarterLabel(id, label) {
  const source = String(label || id || "");
  const match = source.match(/(20\d{2})\s*Q([1-4])/i) || String(id || "").match(/(20\d{2})Q([1-4])/i);
  return match ? match[1] + " Q" + match[2] : source;
}

function currentQuarterLabel() {
  const data = dataObj && dataObj.quarters ? dataObj.quarters[currentQuarter] : null;
  return formatQuarterLabel(currentQuarter, data && data.label);
}

function quarterRank(id) {
  const m = String(id).match(/(\d{4})Q([1-4])/);
  return m ? Number(m[1]) * 10 + Number(m[2]) : 0;
}

function setCurrentQuarter(id) {
  const entry = quarterEntries().find((q) => q.id === id) || quarterEntries().at(-1);
  currentQuarter = entry.id;
  currentQuarterData = entry.data;
}

function defaultQuarterId() {
  const entries = quarterEntries();
  if (!entries.length) return "";
  if (dataObj.defaultQuarter && entries.some((q) => q.id === dataObj.defaultQuarter)) return dataObj.defaultQuarter;
  return entries.at(-1).id;
}

function fillQuarterControls() {
  const entries = quarterEntries();
  $("quarterSide").innerHTML = entries.map((q) =>
    '<button class="side-item ' + (q.id === currentQuarter ? "active" : "") + '" type="button" data-quarter="' + q.id + '">' + q.label + '</button>'
  ).join("");
  document.querySelectorAll("[data-quarter]").forEach((btn) => {
    btn.addEventListener("click", () => {
      setCurrentQuarter(btn.dataset.quarter);
      document.querySelectorAll("[data-quarter]").forEach((b) => b.classList.toggle("active", b === btn));
      fillRegionsForQuarter();
      if (currentDd) {
        selectedPersonKey = null;
        paintRegion(currentDd, true);
        setStatus(currentQuarterLabel() + (isMaster ? " · 마스터 · " : " · ") + currentDd + " 조회 중");
        doSearch();
      }
    });
  });
}

function fillRegionsForQuarter() {
  const regions = Object.keys(currentQuarterData.regions || {}).sort((a, b) => a.localeCompare(b, "ko"));
  const preferred = currentDd || selectedLoginDd;
  selectedLoginDd = currentDd ? (regions.includes(preferred) ? preferred : null) : null;
  updateSelectedRegion();
  const picker = $("regionPicker");
  picker.innerHTML = regions.map((dd) => '<button class="region-option" type="button" role="option" data-region="' + dd + '">' + dd + '</button>').join("");
  paintRegion(currentDd || selectedLoginDd || "", Boolean(currentDd));
  if ($("regionFilter")) {
    $("regionFilter").oninput = applyRegionFilter;
    applyRegionFilter();
  }
  picker.querySelectorAll("[data-region]").forEach((button) => {
    button.addEventListener("click", () => {
      if (currentDd && !isMaster) return;
      selectedLoginDd = button.dataset.region;
      if (isMaster) {
        currentDd = selectedLoginDd;
        selectedPersonKey = null;
        paintRegion(currentDd, true);
        setStatus(currentQuarterLabel() + " · 마스터 · " + currentDd + " 조회 중");
        doSearch();
      } else {
        paintRegion(selectedLoginDd, false);
        updateSelectedRegion();
        if ($("codeInput")) $("codeInput").focus();
      }
    });
  });
}

function updateSelectedRegion() {
  const manager = regionManager(selectedLoginDd);
  $("selectedRegionName").innerHTML = selectedLoginDd ? selectedLoginDd + (manager ? '<small>(' + manager + ')</small>' : "") : "지역을 선택하세요";
  if ($("codeInput")) {
    $("codeInput").disabled = !selectedLoginDd;
    $("codeInput").placeholder = selectedLoginDd ? "지역 암호 입력" : "지역을 먼저 선택하세요";
  }
  if ($("enterBtn")) $("enterBtn").disabled = !selectedLoginDd;
}

function applyRegionFilter() {
  const query = norm($("regionFilter") ? $("regionFilter").value : "");
  $("regionPicker").querySelectorAll("[data-region]").forEach((button) => {
    button.classList.toggle("hidden", Boolean(query) && !norm(button.dataset.region).includes(query));
  });
}

function paintRegion(region, locked) {
  $("regionPicker").querySelectorAll("[data-region]").forEach((button) => {
    const active = button.dataset.region === region;
    button.classList.toggle("active", active);
    button.disabled = Boolean(locked && !isMaster && !active);
  });
}

function validateRegion(dd, code) {
  const expected = norm(currentQuarterData.regions[dd]);
  if (!expected) throw new Error("지역 정보가 없습니다.");
  if (norm(code) === norm(MASTER_KEY)) return "master";
  if (norm(code) !== expected) throw new Error("지역/암호가 틀립니다.");
  return "region";
}

function isTargetPosition(pos) {
  const text = norm(pos);
  return text.includes("점장") || text.includes("부점장") || text.includes("매니저");
}

function cleanRows(rows) {
  return (rows || []).filter((r) => r.store !== "(AVG)" && r.name && r.emp && String(r.name).toLowerCase() !== "n/a" && isTargetPosition(r.pos));
}

function rowsForQuarter(id) {
  const q = (dataObj.quarters || {})[id];
  return q ? cleanRows(q.rows).map((r, idx) => ({ ...r, _quarterId: id, _quarterLabel: q.label || formatQuarterLabel(id), _rowIndex: idx })) : [];
}

function rowsThroughSelectedQuarter() {
  const selectedRank = quarterRank(currentQuarter);
  return quarterEntries().filter((q) => q.rank <= selectedRank).flatMap((q) => rowsForQuarter(q.id));
}

function rowDate(row) {
  const dates = [];
  if (Array.isArray(row.records)) {
    row.records.forEach((rec) => {
      if (rec.date) dates.push(String(rec.date));
      if (rec.detail && rec.detail.E) dates.push(String(rec.detail.E));
    });
  }
  return dates.sort().at(-1) || row._quarterLabel || "";
}

function groupByPerson(rows) {
  const map = new Map();
  rows.forEach((row) => {
    const key = personKey(row);
    if (!map.has(key)) map.set(key, []);
    map.get(key).push(row);
  });
  return map;
}

function currentRegionPersonKeys() {
  return new Set(rowsForQuarter(currentQuarter).filter((r) => r.dd === currentDd).map(personKey));
}

function scoreOf(row) {
  const n = Number(row.ap_avg);
  return Number.isFinite(n) ? n : null;
}

function buildPeopleRows() {
  const query = norm(getSearchInput().value);
  const currentRows = rowsForQuarter(currentQuarter).filter((r) => r.dd === currentDd);
  const allowedKeys = new Set(currentRows.map(personKey));
  const historyByPerson = groupByPerson(rowsThroughSelectedQuarter().filter((r) => allowedKeys.has(personKey(r))));
  const currentByPerson = groupByPerson(currentRows);

  peopleRows = Array.from(currentByPerson.entries()).map(([key, rows]) => {
    const history = (historyByPerson.get(key) || []).sort((a, b) => {
      const q = quarterRank(a._quarterId) - quarterRank(b._quarterId);
      if (q) return q;
      return String(rowDate(a)).localeCompare(String(rowDate(b)));
    });
    const scores = history.map(scoreOf).filter((v) => v !== null);
    const currentScores = rows.map(scoreOf).filter((v) => v !== null);
    const currentAvg = avg(currentScores);
    const prevQuarterRows = history.filter((r) => quarterRank(r._quarterId) < quarterRank(currentQuarter));
    const prevQuarterId = prevQuarterRows.at(-1)?._quarterId;
    const prevRows = prevQuarterId ? prevQuarterRows.filter((r) => r._quarterId === prevQuarterId) : [];
    const prevAvg = avg(prevRows.map(scoreOf).filter((v) => v !== null));
    const delta = currentAvg !== null && prevAvg !== null ? currentAvg - prevAvg : null;
    const historyAvg = avg(scores);
    const avgDelta = currentAvg !== null && historyAvg !== null ? currentAvg - historyAvg : null;
    const first = rows[0];
    const stores = [...new Set(rows.map((r) => r.store).filter(Boolean))];
    return {
      key,
      name: first.name || "",
      emp: first.emp || "",
      pos: first.pos || "",
      store: stores.join(", "),
      currentRows: rows,
      history,
      currentAvg,
      prevAvg,
      delta,
      historyAvg,
      avgDelta,
      lowCount: scores.filter((v) => v < 85).length,
      high: scores.length ? Math.max(...scores) : null,
      low: scores.length ? Math.min(...scores) : null,
      count: history.length,
    };
  }).filter((person) => {
    if (!query) return true;
    const hay = norm([person.name, person.emp, person.store, person.pos, ...person.history.map((r) => r.store)].join(" "));
    return hay.includes(query);
  });

  peopleRows.sort((a, b) => {
    const d = (a.currentAvg ?? 999) - (b.currentAvg ?? 999);
    if (d) return d;
    const avgD = (a.avgDelta ?? 0) - (b.avgDelta ?? 0);
    if (avgD) return avgD;
    return a.name.localeCompare(b.name, "ko");
  });
}

function setMetric(index, label, value, sub = "", cls = "") {
  const card = document.querySelectorAll(".metric")[index];
  if (!card) return;
  card.querySelector("span").textContent = label;
  card.querySelector("strong").textContent = value;
  let small = card.querySelector("small");
  if (!small) {
    small = document.createElement("small");
    card.appendChild(small);
  }
  small.className = cls;
  small.textContent = sub;
}

function trendLabel(delta) {
  if (!Number.isFinite(delta)) return { text: "이력 부족", cls: "warn" };
  if (delta >= 2) return { text: "상승", cls: "up" };
  if (delta <= -2) return { text: "하락", cls: "down" };
  return { text: "유지", cls: "flat" };
}

function renderRegionSummary() {
  const scores = peopleRows.map((p) => p.currentAvg).filter((v) => v !== null);
  const historyPeople = peopleRows.filter((p) => p.count > 1).length;
  const manager = regionManager(currentDd);
  setMetric(0, "조회 기준", currentQuarterLabel(), currentDd + (manager ? " · " + manager : ""));
  setMetric(1, "대상 점장", String(peopleRows.length), "선택 분기 기준");
  setMetric(2, "누적 이력", historyPeople + "명", "2회 이상 평가 이력");
  setMetric(3, "지역 평균", fmt2(avg(scores)), "점장 평균 기준");
}

function renderPersonSummary(person) {
  if (!person) return renderRegionSummary();
  setMetric(0, "선택 점장", person.name, person.emp + " · " + person.pos);
  setMetric(1, "평가 점수", fmt2(person.currentAvg), currentQuarterLabel(), Number(person.currentAvg) < 85 ? "bad" : "");
  setMetric(2, "직전 대비", fmtDelta(person.delta), person.prevAvg === null ? "이전 이력 없음" : "이전 평가 기준", deltaClass(person.delta));
  setMetric(3, "평가 이력", person.count + "회", "2025 Q1 이후 누적");
}

function renderTable() {
  const tbody = $("resultTable").querySelector("tbody");
  tbody.innerHTML = peopleRows.map((p) => {
    const selected = p.key === selectedPersonKey;
    const deltaText = fmtDelta(p.delta);
    const avgDeltaText = fmtDelta(p.avgDelta, "0.00");
    return '<tr data-key="' + p.key + '" class="' + (selected ? "selected" : "") + '">' +
      '<td>' + (p.store || "") + '</td><td>' + p.name + '</td><td>' + p.emp + '</td><td>' + p.pos + '</td>' +
      '<td class="num ' + scoreClass(p.currentAvg) + '">' + fmt2(p.currentAvg) + '</td>' +
      '<td class="num ' + deltaClass(p.avgDelta) + '">' + avgDeltaText + '</td>' +
      '<td class="num ' + deltaClass(p.delta) + '">' + deltaText + '</td>' +
      '<td class="num">' + p.count + '회</td></tr>';
  }).join("");
  tbody.querySelectorAll("tr").forEach((tr) => tr.addEventListener("click", () => selectPerson(tr.dataset.key)));
  $("resultHint").textContent = "점장 " + peopleRows.length + "명";
}

function renderDetail(person) {
  if (!person) {
    $("detailScope").textContent = "선택 대기";
    $("detailBody").innerHTML = '<div class="empty">지역 점장 목록에서 행을 선택하세요.</div>';
    return;
  }
  $("detailScope").textContent = person.name + " · " + currentQuarter;
  const regionScores = peopleRows.map((p) => p.currentAvg).filter((v) => v !== null);
  const regionAvg = avg(regionScores);
  const vsRegion = person.currentAvg !== null && regionAvg !== null ? person.currentAvg - regionAvg : null;
  const trendMap = new Map();
  person.history.forEach((row) => {
    if (!trendMap.has(row._quarterId)) trendMap.set(row._quarterId, []);
    const value = scoreOf(row);
    if (value !== null) trendMap.get(row._quarterId).push(value);
  });
  const trend = Array.from(trendMap.entries()).map(([id, values]) => ({ id, label: (dataObj.quarters[id]?.label || id), value: avg(values) }));
  const recentTrend = trendLabel(person.delta);
  const events = person.history.slice().sort((a, b) => {
    const q = quarterRank(a._quarterId) - quarterRank(b._quarterId);
    if (q) return q;
    return String(rowDate(a)).localeCompare(String(rowDate(b)));
  });
  const initial = String(person.name || "?").slice(0, 1);
  $("detailBody").innerHTML =
    '<div class="profile"><div class="avatar">' + initial + '</div><div><strong>' + person.name + '</strong><span>' + person.emp + ' · ' + person.pos + ' · ' + (person.store || "") + '</span></div></div>' +
    '<div class="person-insights">' +
      '<div class="insight-card"><span>개인 평균</span><strong>' + fmt2(person.historyAvg) + '</strong></div>' +
      '<div class="insight-card"><span>누적 평균 대비</span><strong class="' + deltaClass(person.avgDelta) + '">' + fmtDelta(person.avgDelta, "0.00") + '</strong></div>' +
      '<div class="insight-card"><span>지역 평균 대비</span><strong class="' + deltaClass(vsRegion) + '">' + fmtDelta(vsRegion) + '</strong></div>' +
      '<div class="insight-card"><span>최근 흐름</span><strong class="' + recentTrend.cls + '">' + recentTrend.text + '</strong></div>' +
    '</div>' +
    '<div class="detail-title">최근 평가 흐름</div>' +
    '<div class="trend-row">' + trend.map((t) => '<div class="trend-chip"><span>' + t.label + '</span><strong class="' + scoreClass(t.value) + '">' + fmt2(t.value) + '</strong></div>').join("") + '</div>' +
    '<div class="detail-title">점포 / 지역 이동 이력</div>' +
    '<div class="timeline">' + events.map((r) => '<div class="audit-event"><strong>' + r._quarterLabel + ' · ' + (r.store || "") + ' · ' + fmt2(r.ap_avg) + noteBadge(r) + '</strong><span>' + (r.dd || "") + ' · 조사일자 ' + rowDate(r) + '</span></div>').join("") + '</div>' +
    '<p class="notice">선택한 분기 이후의 미래 데이터는 표시하지 않습니다. 2025년 이후 자료는 참고 아카이빙 기준입니다.</p>';
}

function doSearch() {
  buildPeopleRows();
  if (!peopleRows.some((p) => p.key === selectedPersonKey)) selectedPersonKey = peopleRows[0]?.key || null;
  const selected = peopleRows.find((p) => p.key === selectedPersonKey);
  renderPersonSummary(selected);
  renderTable();
  renderDetail(selected);
}

function selectPerson(key) {
  selectedPersonKey = key;
  const selected = peopleRows.find((p) => p.key === key);
  renderPersonSummary(selected);
  renderTable();
  renderDetail(selected);
}

function enter() {
  try {
    const dd = selectedLoginDd;
    if (!dd) throw new Error("지역을 먼저 선택하세요.");
    const mode = validateRegion(dd, $("codeInput").value);
    isMaster = mode === "master";
    currentDd = dd;
    selectedPersonKey = null;
    paintRegion(dd, true);
    $("loginToolbar").classList.add("hidden");
    $("loginNotice").classList.add("hidden");
    if ($("introPanel")) $("introPanel").classList.add("hidden");
    $("summaryGrid").classList.remove("hidden");
    $("searchToolbar").classList.remove("hidden");
    $("contentGrid").classList.remove("hidden");
    setStatus(currentQuarterLabel() + (isMaster ? " · 마스터 · " : " · ") + dd + " 조회 중");
    doSearch();
  } catch (err) {
    alert(err.message || String(err));
  }
}

function logout() {
  currentDd = null;
  isMaster = false;
  selectedPersonKey = null;
  $("codeInput").value = "";
  getSearchInput().value = "";
  $("loginToolbar").classList.remove("hidden");
  $("loginNotice").classList.remove("hidden");
  if ($("introPanel")) $("introPanel").classList.remove("hidden");
  $("summaryGrid").classList.add("hidden");
  $("searchToolbar").classList.add("hidden");
  $("contentGrid").classList.add("hidden");
  fillRegionsForQuarter();
  setStatus("지역 선택 대기");
}

function resetHome() {
  if (!dataObj) return;
  setCurrentQuarter(defaultQuarterId());
  document.querySelectorAll("[data-quarter]").forEach((button) => {
    button.classList.toggle("active", button.dataset.quarter === currentQuarter);
  });
  currentDd = null;
  isMaster = false;
  selectedLoginDd = null;
  selectedPersonKey = null;
  peopleRows = [];
  if ($("codeInput")) $("codeInput").value = "";
  if ($("qInput")) $("qInput").value = "";
  if ($("qInputInline")) $("qInputInline").value = "";
  if ($("regionFilter")) $("regionFilter").value = "";
  $("loginToolbar").classList.remove("hidden");
  $("loginNotice").classList.remove("hidden");
  if ($("introPanel")) $("introPanel").classList.remove("hidden");
  $("summaryGrid").classList.add("hidden");
  $("searchToolbar").classList.add("hidden");
  $("contentGrid").classList.add("hidden");
  fillRegionsForQuarter();
  renderDetail(null);
  setStatus("지역 선택 대기");
}

$("enterBtn").addEventListener("click", enter);
$("codeInput").addEventListener("keydown", (e) => { if (e.key === "Enter") enter(); });
if ($("qInput")) $("qInput").addEventListener("input", doSearch);
if ($("qInputInline")) $("qInputInline").addEventListener("input", doSearch);
$("resetBtn").addEventListener("click", () => { getSearchInput().value = ""; doSearch(); });
$("logoutBtn").addEventListener("click", logout);
if ($("brandHome")) $("brandHome").addEventListener("click", resetHome);

window.addEventListener("keydown", (e) => {
  if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "m") {
    const code = prompt("마스터 암호");
    if (!code) return;
    try {
      const mode = validateRegion(selectedLoginDd, code);
      if (mode !== "master") throw new Error("마스터 암호가 아닙니다.");
      isMaster = true;
      currentDd = selectedLoginDd;
      selectedPersonKey = null;
      $("loginToolbar").classList.add("hidden");
      $("loginNotice").classList.add("hidden");
      if ($("introPanel")) $("introPanel").classList.add("hidden");
      $("summaryGrid").classList.remove("hidden");
      $("searchToolbar").classList.remove("hidden");
      $("contentGrid").classList.remove("hidden");
      paintRegion(currentDd, true);
      setStatus(currentQuarterLabel() + " · 마스터 · " + currentDd + " 조회 중");
      doSearch();
    } catch (err) {
      alert(err.message || String(err));
    }
  }
});

loadData().catch((err) => {
  console.error(err);
  setStatus("데이터 로드 실패");
  alert(err.message || String(err));
});

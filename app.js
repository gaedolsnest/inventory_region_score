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
let expandedQuarterYears = new Set();
let quarterTreeBootstrapped = false;
let loginModalMode = "region";
let detailTab = "summary";
let selectedQuantityKey = null;

const $ = (id) => document.getElementById(id);
const norm = (s) => String(s || "").replace(/\s+/g, "").trim().toLowerCase();
const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (ch) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[ch]));
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
const fmtQty = (v) => {
  const n = Number(v);
  if (!Number.isFinite(n)) return "-";
  return n.toLocaleString("ko-KR", { maximumFractionDigits: 2 });
};
const fmtQtyDiff = (v) => {
  const n = Number(v);
  if (!Number.isFinite(n)) return "-";
  if (Math.abs(n) < 0.0005) return "0";
  return (n > 0 ? "+" : "") + fmtQty(n);
};
const qtyClass = (v) => {
  const n = Number(v);
  if (!Number.isFinite(n) || Math.abs(n) < 0.0005) return "flat";
  return n > 0 ? "qty-pos" : "qty-neg";
};
const personKey = (r) => {
  const alias = norm(r.person_alias || r.person_key);
  if (alias) return "alias:" + alias;
  const emp = norm(r.emp);
  return emp ? "emp:" + emp : "name:" + norm((r.name || "") + "|" + (r.pos || ""));
};

function noteInfo(item) {
  if (!item) return null;
  const raw = String(item.note_raw || item.note || "").trim();
  const type = item.note_type || (raw.includes("대체") ? "replacement" : raw.includes("인수인계") ? "handover" : "");
  const label = type === "replacement" ? "인수인계 대체" : type === "handover" ? "인수인계" : (item.note || "");
  return label ? { label, type } : null;
}

function noteBadge(item) {
  const info = noteInfo(item);
  if (!info) return "";
  const title = info.type === "replacement" ? "정기 재고조사를 인수인계 재고조사로 대체한 건입니다." : info.type === "handover" ? "별도 인수인계 재고조사 기록입니다." : "";
  return '<em class="note-badge ' + info.type + '" title="' + title + '">' + info.label + '</em>';
}

function isHandoverRow(row) {
  const info = noteInfo(row);
  if (info?.type === "handover") return true;
  const records = Array.isArray(row?.records) ? row.records : [];
  return records.length > 0 && records.every((rec) => noteInfo(rec)?.type === "handover");
}

function eventMeta(row) {
  const info = noteInfo(row);
  const regionText = row.dd || "";
  const dateText = "조사일자 " + rowDate(row);
  if (info?.type === "handover") return [regionText, "당시 조사지역", dateText].filter(Boolean).join(" · ");
  if (info?.type === "replacement") return [regionText, "정기 대체", dateText].filter(Boolean).join(" · ");
  return [regionText, dateText].filter(Boolean).join(" · ");
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
  setCurrentQuarter(defaultQuarterId());
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

function updateQuarterCopy() {
  if (!currentQuarter) return;
  const label = currentQuarterLabel();
  const fullLabel = label + " 정기 재고조사";
  if ($("noticeQuarterLabel")) $("noticeQuarterLabel").textContent = fullLabel;
  if ($("introQuarterLabel")) $("introQuarterLabel").textContent = fullLabel;
}

function quarterRank(id) {
  const m = String(id).match(/(\d{4})Q([1-4])/);
  return m ? Number(m[1]) * 10 + Number(m[2]) : 0;
}

function quarterYear(id) {
  const m = String(id || "").match(/(20\d{2})Q[1-4]/i);
  return m ? m[1] : "";
}

function shortQuarterLabel(id, label) {
  const source = String(label || id || "");
  const match = source.match(/(20\d{2})\s*Q([1-4])/i) || String(id || "").match(/(20\d{2})Q([1-4])/i);
  return match ? "Q" + match[2] : formatQuarterLabel(id, label);
}

function shortYearLabel(year) {
  return year;
}

function ensureQuarterYearExpanded() {
  const year = quarterYear(currentQuarter);
  if (year && !quarterTreeBootstrapped) {
    expandedQuarterYears.add(year);
    quarterTreeBootstrapped = true;
  }
}

function setCurrentQuarter(id) {
  const entry = quarterEntries().find((q) => q.id === id) || quarterEntries().at(-1);
  currentQuarter = entry.id;
  currentQuarterData = entry.data;
  ensureQuarterYearExpanded();
  updateQuarterCopy();
}

function defaultQuarterId() {
  const entries = quarterEntries();
  if (!entries.length) return "";
  if (dataObj.defaultQuarter && entries.some((q) => q.id === dataObj.defaultQuarter)) return dataObj.defaultQuarter;
  return entries.at(-1).id;
}

function fillQuarterControls() {
  const entries = quarterEntries();
  const side = $("quarterSide");
  if (!entries.length) {
    side.innerHTML = "";
    return;
  }
  const currentYear = quarterYear(currentQuarter) || quarterYear(entries.at(-1).id);
  if (!quarterTreeBootstrapped && currentYear) {
    expandedQuarterYears.add(currentYear);
    quarterTreeBootstrapped = true;
  }

  const groups = [];
  entries.forEach((q) => {
    const year = quarterYear(q.id) || "\uae30\ud0c0";
    let group = groups.find((item) => item.year === year);
    if (!group) {
      group = { year, entries: [] };
      groups.push(group);
    }
    group.entries.push(q);
  });
  groups.sort((a, b) => (Number(b.year) || 0) - (Number(a.year) || 0));

  side.innerHTML = groups.map((group) => {
    const open = expandedQuarterYears.has(group.year);
    const children = group.entries.map((q) =>
      '<button class="side-item quarter-item ' + (q.id === currentQuarter ? "active" : "") + '" type="button" data-quarter="' + q.id + '" title="' + q.label + '">' + shortQuarterLabel(q.id, q.label) + '</button>'
    ).join("");
    return '<div class="quarter-year">' +
      '<button class="quarter-year-toggle ' + (open ? "open" : "") + '" type="button" data-quarter-year="' + group.year + '" aria-expanded="' + (open ? "true" : "false") + '">' +
        '<span><i class="chevron"></i>' + shortYearLabel(group.year) + '</span>' +
      '</button>' +
      '<div class="quarter-children ' + (open ? "" : "collapsed") + '">' + children + '</div>' +
    '</div>';
  }).join("");

  document.querySelectorAll("[data-quarter-year]").forEach((btn) => {
    btn.addEventListener("click", (event) => {
      event.preventDefault();
      event.stopPropagation();
      const year = String(btn.getAttribute("data-quarter-year") || "");
      if (!year) return;
      if (expandedQuarterYears.has(year)) expandedQuarterYears.delete(year);
      else expandedQuarterYears.add(year);
      fillQuarterControls();
    });
  });
  document.querySelectorAll("[data-quarter]").forEach((btn) => {
    btn.addEventListener("click", () => {
      setCurrentQuarter(btn.dataset.quarter);
      fillQuarterControls();
      fillRegionsForQuarter();
      if (currentDd) {
        selectedPersonKey = null;
        detailTab = "summary";
        selectedQuantityKey = null;
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
  picker.innerHTML = regions.map((dd) =>
    '<div class="region-row" data-region-row="' + dd + '">' +
      '<button class="region-option" type="button" role="option" data-region="' + dd + '">' + dd + '</button>' +
      '<button class="region-access" type="button" data-region-access="' + dd + '" aria-label="' + dd + ' 접속">접속</button>' +
    '</div>'
  ).join("");
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
        detailTab = "summary";
        selectedQuantityKey = null;
        paintRegion(currentDd, true);
        setStatus(currentQuarterLabel() + " · 마스터 · " + currentDd + " 조회 중");
        doSearch();
      } else {
        paintRegion(selectedLoginDd, false);
        updateSelectedRegion();
      }
    });
  });
  picker.querySelectorAll("[data-region-access]").forEach((button) => {
    button.addEventListener("click", (event) => {
      event.stopPropagation();
      if (currentDd && !isMaster) return;
      selectedLoginDd = button.dataset.regionAccess;
      paintRegion(selectedLoginDd, false);
      updateSelectedRegion();
      openLoginModal("region");
    });
  });
}

function updateSelectedRegion() {
  const manager = regionManager(selectedLoginDd);
  $("selectedRegionName").innerHTML = selectedLoginDd ? selectedLoginDd + (manager ? '<small>(' + manager + ')</small>' : "") : "지역을 선택하세요";
  if ($("enterBtn")) {
    $("enterBtn").disabled = !selectedLoginDd;
    $("enterBtn").textContent = selectedLoginDd ? "접속" : "지역 선택";
  }
}

function applyRegionFilter() {
  const query = norm($("regionFilter") ? $("regionFilter").value : "");
  $("regionPicker").querySelectorAll("[data-region-row]").forEach((row) => {
    row.classList.toggle("hidden", Boolean(query) && !norm(row.dataset.regionRow).includes(query));
  });
}

function paintRegion(region, locked) {
  $("regionPicker").querySelectorAll("[data-region-row]").forEach((row) => {
    const active = row.dataset.regionRow === region;
    row.classList.toggle("active", active);
    row.classList.toggle("locked", Boolean(locked && (!isMaster || active)));
  });
  $("regionPicker").querySelectorAll("[data-region]").forEach((button) => {
    const active = button.dataset.region === region;
    button.classList.toggle("active", active);
    button.disabled = Boolean(locked && !isMaster && !active);
  });
  $("regionPicker").querySelectorAll("[data-region-access]").forEach((button) => {
    const active = button.dataset.regionAccess === region;
    button.disabled = Boolean(locked && !isMaster);
    button.classList.toggle("active", active);
  });
}

function validateRegion(dd, code) {
  if (norm(code) === norm(MASTER_KEY)) return "master";
  const expected = norm(currentQuarterData.regions[dd]);
  if (!expected) throw new Error("지역 정보가 없습니다.");
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

function recordDate(row, rec) {
  return String(rec?.date || rec?.detail?.E || rowDate(row) || "");
}

function quantityValue(detail, key) {
  const n = Number(detail?.[key]);
  return Number.isFinite(n) ? n : null;
}

function quantityRecordKey(row, rec, index) {
  return [row._quarterId, row._rowIndex, index, recordDate(row, rec), row.store || ""].join("|");
}

function quantityRecordsForPerson(person) {
  if (!person) return [];
  const records = [];
  const sortedRows = person.history.slice().sort((a, b) => {
    const q = quarterRank(b._quarterId) - quarterRank(a._quarterId);
    if (q) return q;
    return String(rowDate(b)).localeCompare(String(rowDate(a)));
  });
  sortedRows.forEach((row) => {
    (row.records || [])
      .map((rec, index) => ({ rec, index }))
      .sort((a, b) => String(recordDate(row, b.rec)).localeCompare(String(recordDate(row, a.rec))))
      .forEach(({ rec, index }) => {
      const detail = rec.detail || {};
      const hasQuantity = ["F", "H", "I", "O", "Q", "R", "X", "Z", "AA", "AG", "AI", "AJ"].some((key) => quantityValue(detail, key) !== null);
      records.push({
        key: quantityRecordKey(row, rec, index),
        row,
        rec,
        detail,
        hasQuantity,
        date: recordDate(row, rec),
        quarterId: row._quarterId,
        quarterLabel: row._quarterLabel || formatQuarterLabel(row._quarterId),
        store: row.store || "",
        score: Number.isFinite(Number(rec.ap)) ? Number(rec.ap) : scoreOf(row),
      });
    });
  });
  return records;
}

function defaultQuantityKey(records) {
  if (!records.length) return null;
  const current = records.find((record) => record.quarterId === currentQuarter);
  return (current || records[0]).key;
}

function quantityRows(record) {
  const detail = record?.detail || {};
  return [
    { label: "신발", system: detail.F, actual: detail.H, diff: detail.I },
    { label: "용품", system: detail.O, actual: detail.Q, diff: detail.R },
    { label: "의류", system: detail.X, actual: detail.Z, diff: detail.AA },
    { label: "합계", system: detail.AG, actual: detail.AI, diff: detail.AJ, total: true },
  ];
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
  const currentRows = rowsForQuarter(currentQuarter).filter((r) => r.dd === currentDd && !isHandoverRow(r));
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
    const storeD = String(a.store || "").localeCompare(String(b.store || ""), "ko");
    if (storeD) return storeD;
    const nameD = a.name.localeCompare(b.name, "ko");
    if (nameD) return nameD;
    return (a.currentAvg ?? 999) - (b.currentAvg ?? 999);
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
  const detailBody = $("detailBody");
  if (!person) {
    $("detailScope").textContent = "선택 대기";
    detailBody.innerHTML = '<div class="empty">지역 점장 목록에서 행을 선택하세요.</div>';
    detailTab = "summary";
    selectedQuantityKey = null;
    return;
  }

  $("detailScope").textContent = person.name + " · " + currentQuarterLabel();
  const regionScores = peopleRows.map((p) => p.currentAvg).filter((v) => v !== null);
  const regionAvg = avg(regionScores);
  const vsRegion = person.currentAvg !== null && regionAvg !== null ? person.currentAvg - regionAvg : null;
  const trendMap = new Map();
  person.history.forEach((row) => {
    if (!trendMap.has(row._quarterId)) trendMap.set(row._quarterId, []);
    const value = scoreOf(row);
    if (value !== null) trendMap.get(row._quarterId).push(value);
  });
  const trend = Array.from(trendMap.entries())
    .map(([id, values]) => ({ id, label: formatQuarterLabel(id, dataObj.quarters[id]?.label || id), value: avg(values) }))
    .sort((a, b) => quarterRank(b.id) - quarterRank(a.id));
  const events = person.history.slice().sort((a, b) => {
    const q = quarterRank(b._quarterId) - quarterRank(a._quarterId);
    if (q) return q;
    return String(rowDate(b)).localeCompare(String(rowDate(a)));
  });
  const recentTrend = trendLabel(person.delta);
  const quantityRecords = quantityRecordsForPerson(person);
  if (!selectedQuantityKey || !quantityRecords.some((record) => record.key === selectedQuantityKey)) {
    selectedQuantityKey = defaultQuantityKey(quantityRecords);
  }
  const selectedRecord = quantityRecords.find((record) => record.key === selectedQuantityKey) || quantityRecords[0] || null;
  const initial = esc(String(person.name || "?").slice(0, 1));
  const activeTab = ["summary", "quantity", "history"].includes(detailTab) ? detailTab : "summary";
  const tabs =
    '<div class="detail-tabs" role="tablist" aria-label="상세 정보 전환">' +
      '<button class="' + (activeTab === "summary" ? "active" : "") + '" type="button" data-detail-tab="summary">요약</button>' +
      '<button class="' + (activeTab === "quantity" ? "active" : "") + '" type="button" data-detail-tab="quantity">수량</button>' +
      '<button class="' + (activeTab === "history" ? "active" : "") + '" type="button" data-detail-tab="history">이력</button>' +
    '</div>';

  const summaryHtml =
    '<div class="person-insights summary-insights">' +
      '<div class="insight-card"><span>현재 점수</span><strong class="' + scoreClass(person.currentAvg) + '">' + fmt2(person.currentAvg) + '</strong><small>' + esc(currentQuarterLabel()) + '</small></div>' +
      '<div class="insight-card"><span>직전 대비</span><strong class="' + deltaClass(person.delta) + '">' + fmtDelta(person.delta) + '</strong><small>' + (person.prevAvg === null ? "이전 이력 없음" : "이전 평가 기준") + '</small></div>' +
      '<div class="insight-card"><span>누적 평균 대비</span><strong class="' + deltaClass(person.avgDelta) + '">' + fmtDelta(person.avgDelta, "0.00") + '</strong><small>개인 평균 ' + fmt2(person.historyAvg) + '</small></div>' +
      '<div class="insight-card"><span>지역 평균 대비</span><strong class="' + deltaClass(vsRegion) + '">' + fmtDelta(vsRegion) + '</strong><small>지역 평균 ' + fmt2(regionAvg) + '</small></div>' +
      '<div class="insight-card"><span>평가 이력</span><strong>' + person.count + '회</strong><small>2025 Q1 이후 누적</small></div>' +
      '<div class="insight-card"><span>최근 흐름</span><strong class="' + recentTrend.cls + '">' + recentTrend.text + '</strong><small>직전 평가 기준</small></div>' +
    '</div>' +
    '<div class="detail-title">최근 평가 흐름</div>' +
    '<div class="trend-row">' + trend.map((t) => '<div class="trend-chip ' + (t.id === currentQuarter ? "current-quarter" : "") + '" title="' + (t.id === currentQuarter ? "선택한 분기" : "") + '"><span>' + esc(t.label) + '</span><strong class="' + scoreClass(t.value) + '">' + fmt2(t.value) + '</strong></div>').join("") + '</div>';

  const quantitySelector = quantityRecords.length
    ? '<div class="quantity-record-list">' + quantityRecords.map((record) => {
        const isActive = record.key === selectedRecord?.key;
        const marker = record.quarterId === currentQuarter ? '<em>현재 선택 분기</em>' : "";
        return '<button class="' + (isActive ? "active" : "") + '" type="button" data-quantity-key="' + esc(record.key) + '">' +
          '<strong>' + esc(record.quarterLabel) + ' · ' + esc(record.store || "-") + '</strong>' +
          '<span>' + esc(record.date || "날짜 없음") + ' · ' + fmt2(record.score) + '점' + marker + '</span>' +
        '</button>';
      }).join("") + '</div>'
    : '<div class="empty compact">표시할 조사 기록이 없습니다.</div>';
  const quantityTable = selectedRecord && selectedRecord.hasQuantity
    ? '<div class="quantity-table-wrap"><table class="quantity-table"><thead><tr><th>구분</th><th class="num">전산</th><th class="num">실물</th><th class="num">차이</th></tr></thead><tbody>' +
      quantityRows(selectedRecord).map((row) => '<tr class="' + (row.total ? "total" : "") + '"><td>' + row.label + '</td><td class="num">' + fmtQty(row.system) + '</td><td class="num">' + fmtQty(row.actual) + '</td><td class="num ' + qtyClass(row.diff) + '">' + fmtQtyDiff(row.diff) + '</td></tr>').join("") +
      '</tbody></table></div>'
    : '<div class="empty compact">이 기록에는 신발/용품/의류 수량 상세가 없습니다.</div>';
  const quantityHtml =
    '<div class="quantity-panel">' +
      '<div class="detail-title">기록 선택</div>' +
      quantitySelector +
      (selectedRecord ? '<div class="quantity-current"><strong>' + esc(selectedRecord.quarterLabel) + ' · ' + esc(selectedRecord.store || "-") + '</strong><span>' + esc(selectedRecord.date || "날짜 없음") + ' · ' + fmt2(selectedRecord.score) + '점</span></div>' : "") +
      quantityTable +
      '<p class="quantity-note">수량 차이는 점수 판단이 아닌 참고 수량입니다.</p>' +
    '</div>';

  const historyHtml =
    '<div class="detail-title">점포 / 지역 이동 이력</div>' +
    '<div class="timeline">' + events.map((r) => '<div class="audit-event ' + (r._quarterId === currentQuarter ? "current-quarter" : "") + (isHandoverRow(r) ? " handover-event" : "") + '"><strong>' + esc(formatQuarterLabel(r._quarterId, r._quarterLabel)) + ' · ' + esc(r.store || "") + ' · ' + fmt2(r.ap_avg) + noteBadge(r) + '</strong><span>' + esc(eventMeta(r)) + '</span></div>').join("") + '</div>' +
    '<p class="notice detail-notice">선택한 분기 이후의 미래 데이터는 표시하지 않습니다. 2025년 이후 자료는 점장 흐름 확인용 기준입니다.</p>';

  const panelHtml = activeTab === "quantity" ? quantityHtml : activeTab === "history" ? historyHtml : summaryHtml;
  detailBody.innerHTML =
    '<div class="profile compact-profile"><div class="avatar">' + initial + '</div><div><strong>' + esc(person.name) + '</strong><span>' + esc(person.emp + ' · ' + person.pos + ' · ' + (person.store || "")) + '</span></div></div>' +
    tabs +
    '<div class="detail-panel">' + panelHtml + '</div>';

  detailBody.querySelectorAll("[data-detail-tab]").forEach((button) => {
    button.addEventListener("click", () => {
      detailTab = button.dataset.detailTab;
      renderDetail(person);
    });
  });
  detailBody.querySelectorAll("[data-quantity-key]").forEach((button) => {
    button.addEventListener("click", () => {
      selectedQuantityKey = button.dataset.quantityKey;
      detailTab = "quantity";
      renderDetail(person);
    });
  });
}

function doSearch() {
  buildPeopleRows();
  const previousKey = selectedPersonKey;
  if (!peopleRows.some((p) => p.key === selectedPersonKey)) selectedPersonKey = peopleRows[0]?.key || null;
  if (previousKey !== selectedPersonKey) {
    detailTab = "summary";
    selectedQuantityKey = null;
  }
  const selected = peopleRows.find((p) => p.key === selectedPersonKey);
  renderPersonSummary(selected);
  renderTable();
  renderDetail(selected);
}

function selectPerson(key) {
  if (selectedPersonKey !== key) {
    detailTab = "summary";
    selectedQuantityKey = null;
  }
  selectedPersonKey = key;
  const selected = peopleRows.find((p) => p.key === key);
  renderPersonSummary(selected);
  renderTable();
  renderDetail(selected);
}

function firstRegionForQuarter() {
  if (!currentQuarterData || !currentQuarterData.regions) return "";
  return Object.keys(currentQuarterData.regions || {}).sort((a, b) => a.localeCompare(b, "ko"))[0] || "";
}

function openLoginModal(mode = "region") {
  if (!dataObj || !currentQuarterData) {
    alert("데이터 로드가 끝난 뒤 다시 시도하세요.");
    return;
  }
  loginModalMode = mode;
  if (mode === "region" && !selectedLoginDd) {
    setStatus("지역 선택 대기");
    alert("왼쪽 지역 목록에서 접속할 지역을 먼저 선택하세요.");
    return;
  }
  const modal = $("loginModal");
  const input = $("modalCodeInput");
  const region = selectedLoginDd || currentDd || firstRegionForQuarter();
  if ($("loginModalEyebrow")) $("loginModalEyebrow").textContent = mode === "master" ? "마스터 접속" : "지역 접속";
  if ($("loginModalTitle")) $("loginModalTitle").textContent = mode === "master" ? "마스터 암호 입력" : region + " 암호 입력";
  if ($("loginModalDesc")) {
    $("loginModalDesc").textContent = mode === "master"
      ? "마스터 암호로 접속하면 지역 목록에서 다른 지역을 바로 전환할 수 있습니다."
      : "선택한 지역의 암호를 입력하면 해당 지역 점장 목록이 표시됩니다.";
  }
  if (input) input.value = "";
  modal.classList.remove("hidden");
  modal.setAttribute("aria-hidden", "false");
  window.setTimeout(() => input && input.focus(), 30);
}

function closeLoginModal() {
  const modal = $("loginModal");
  if (!modal) return;
  modal.classList.add("hidden");
  modal.setAttribute("aria-hidden", "true");
  if ($("modalCodeInput")) $("modalCodeInput").value = "";
}

function completeLogin(dd) {
  currentDd = dd;
  selectedLoginDd = dd;
  selectedPersonKey = null;
  detailTab = "summary";
  selectedQuantityKey = null;
  paintRegion(dd, true);
  updateSelectedRegion();
  closeLoginModal();
  $("loginToolbar").classList.add("hidden");
  $("loginNotice").classList.add("hidden");
  if ($("introPanel")) $("introPanel").classList.add("hidden");
  if ($("legendPanel")) $("legendPanel").classList.add("hidden");
  if ($("summaryGrid")) $("summaryGrid").classList.remove("hidden");
  $("searchToolbar").classList.remove("hidden");
  $("contentGrid").classList.remove("hidden");
  setStatus(currentQuarterLabel() + (isMaster ? " · 마스터 · " : " · ") + dd + " 조회 중");
  doSearch();
}

function submitLoginModal() {
  try {
    const code = $("modalCodeInput") ? $("modalCodeInput").value : "";
    if (loginModalMode === "master") {
      if (norm(code) !== norm(MASTER_KEY)) throw new Error("마스터 암호가 아닙니다.");
      const dd = selectedLoginDd || currentDd || firstRegionForQuarter();
      if (!dd) throw new Error("조회할 지역 정보가 없습니다.");
      isMaster = true;
      completeLogin(dd);
      return;
    }
    const dd = selectedLoginDd;
    if (!dd) throw new Error("지역을 먼저 선택하세요.");
    const mode = validateRegion(dd, code);
    isMaster = mode === "master";
    completeLogin(dd);
  } catch (err) {
    alert(err.message || String(err));
  }
}

function enter() {
  openLoginModal("region");
}

function logout() {
  currentDd = null;
  isMaster = false;
  selectedPersonKey = null;
  detailTab = "summary";
  selectedQuantityKey = null;
  if ($("modalCodeInput")) $("modalCodeInput").value = "";
  getSearchInput().value = "";
  $("loginToolbar").classList.remove("hidden");
  $("loginNotice").classList.remove("hidden");
  if ($("introPanel")) $("introPanel").classList.remove("hidden");
  if ($("legendPanel")) $("legendPanel").classList.remove("hidden");
  if ($("summaryGrid")) $("summaryGrid").classList.add("hidden");
  $("searchToolbar").classList.add("hidden");
  $("contentGrid").classList.add("hidden");
  fillRegionsForQuarter();
  setStatus("지역 선택 대기");
}

function resetHome() {
  if (!dataObj) return;
  expandedQuarterYears = new Set();
  quarterTreeBootstrapped = false;
  setCurrentQuarter(defaultQuarterId());
  fillQuarterControls();
  currentDd = null;
  isMaster = false;
  selectedLoginDd = null;
  selectedPersonKey = null;
  peopleRows = [];
  detailTab = "summary";
  selectedQuantityKey = null;
  closeLoginModal();
  if ($("qInput")) $("qInput").value = "";
  if ($("qInputInline")) $("qInputInline").value = "";
  if ($("regionFilter")) $("regionFilter").value = "";
  $("loginToolbar").classList.remove("hidden");
  $("loginNotice").classList.remove("hidden");
  if ($("introPanel")) $("introPanel").classList.remove("hidden");
  if ($("legendPanel")) $("legendPanel").classList.remove("hidden");
  if ($("summaryGrid")) $("summaryGrid").classList.add("hidden");
  $("searchToolbar").classList.add("hidden");
  $("contentGrid").classList.add("hidden");
  fillRegionsForQuarter();
  renderDetail(null);
  setStatus("지역 선택 대기");
}

$("enterBtn").addEventListener("click", enter);
if ($("masterAccessBtn")) $("masterAccessBtn").addEventListener("click", () => openLoginModal("master"));
if ($("loginModalSubmit")) $("loginModalSubmit").addEventListener("click", submitLoginModal);
if ($("modalCodeInput")) $("modalCodeInput").addEventListener("keydown", (e) => { if (e.key === "Enter") submitLoginModal(); });
if ($("loginModalClose")) $("loginModalClose").addEventListener("click", closeLoginModal);
if ($("loginModalCancel")) $("loginModalCancel").addEventListener("click", closeLoginModal);
if ($("loginModal")) $("loginModal").addEventListener("click", (e) => { if (e.target === $("loginModal")) closeLoginModal(); });
if ($("qInput")) $("qInput").addEventListener("input", doSearch);
if ($("qInputInline")) $("qInputInline").addEventListener("input", doSearch);
$("resetBtn").addEventListener("click", () => { getSearchInput().value = ""; doSearch(); });
$("logoutBtn").addEventListener("click", logout);
if ($("brandHome")) $("brandHome").addEventListener("click", resetHome);

window.addEventListener("keydown", (e) => {
  if (e.key === "Escape" && $("loginModal") && !$("loginModal").classList.contains("hidden")) {
    closeLoginModal();
    return;
  }
  if (e.ctrlKey && e.shiftKey && e.key.toLowerCase() === "m") {
    openLoginModal("master");
  }
});

loadData().catch((err) => {
  console.error(err);
  setStatus("데이터 로드 실패");
  alert(err.message || String(err));
});

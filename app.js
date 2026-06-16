const DATA_URL = "webdata.bin";
const MAGIC = new TextEncoder().encode("SCOREENC\n");
const SALT_LEN = 16;
const NONCE_LEN = 12;
const PBKDF2_ITERS = 200000;
const INTERNAL_PASSPHRASE = "ABCMART_SCOREAPP_INTERNAL_KEY_V1_WEB";
const MASTER_KEY = "audit2026!";
const REGION_MANAGERS = {
  "강원지역": "임동주 지역장",
  "경남지역": "조우리 지역장",
  "경북지역": "장규호 지역장",
  "남동지역": "이하림 지역장",
  "남서지역": "유영찬 지역장",
  "대경지역": "박양근 지역장",
  "동남지역": "박진선 지역장",
  "동북지역": "김대훈 지역장",
  "부경지역": "박근탁 지역장",
  "온더스팟": "김현지 수석",
  "북동지역": "강민혁 지역장",
  "북서지역": "하민철 지역장",
  "서남지역": "김잔디 지역장",
  "서북지역": "김영호 지역장",
  "전남지역": "최우석 지역장",
  "전북지역": "최승문 지역장",
  "제주지역": "박준길 지역장",
  "중남지역": "조재광 지역장",
  "중부지역": "김영규 지역장",
  "중서지역": "김동순 지역장",
  "충남지역": "윤영보 지역장",
  "충북지역": "변혜영 지역장"
};

let dataObj = null;
let currentQuarter = null;
let currentQuarterData = null;
let currentDd = null;
let isMaster = false;
let visibleRows = [];
let selectedId = null;
let selectedLoginDd = null;

const $ = (id) => document.getElementById(id);
const norm = (s) => String(s || "").replace(/\s+/g, "").trim().toLowerCase();
const fmt2 = (v) => {
  const n = Number(v);
  if (!Number.isFinite(n)) return "";
  return n.toLocaleString("ko-KR", { minimumFractionDigits: 2, maximumFractionDigits: 2 });
};
const personKey = (r) => norm((r.emp || r.name || "") + "|" + (r.pos || ""));

function regionManager(region) {
  return REGION_MANAGERS[region] || "";
}

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

function setStatus(text) {
  $("sessionBadge").innerHTML = '<span class="dot"></span> ' + text;
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
  if (!res.ok) throw new Error("webdata.bin 로드 실패: " + res.status);
  dataObj = JSON.parse(await decryptBlob(await res.arrayBuffer()));
  if (!dataObj || (!dataObj.quarters && (!dataObj.regions || !Array.isArray(dataObj.rows)))) throw new Error("데이터 형식 오류");
  fillRegionControls();
  if (!currentQuarterData || !currentQuarterData.regions || !Array.isArray(currentQuarterData.rows)) throw new Error("분기 데이터 형식 오류");
  setStatus("지역 선택 대기");
}

function getQuarterEntries() {
  if (dataObj.quarters) {
    return Object.entries(dataObj.quarters).map(([id, q]) => ({
      id,
      label: q.label || id.replace(/Q([1-4])$/, " Q$1"),
      data: q,
    }));
  }
  return [{ id: "2026Q1", label: "2026 Q1", data: dataObj }];
}

function setCurrentQuarter(id) {
  const entries = getQuarterEntries();
  const entry = entries.find((q) => q.id === id) || entries[0];
  currentQuarter = entry.id;
  currentQuarterData = entry.data;
}

function fillRegionControls() {
  const entries = getQuarterEntries();
  setCurrentQuarter(entries[0].id);
  $("quarterSide").innerHTML = entries.map((q, i) => '<button class="side-item ' + (i === 0 ? "active" : "") + '" type="button" data-quarter="' + q.id + '">' + q.label + '</button>').join("");
  document.querySelectorAll("[data-quarter]").forEach((btn) => {
    btn.addEventListener("click", () => {
      const wasLoggedIn = Boolean(currentDd);
      const preferredDd = currentDd || selectedLoginDd;
      document.querySelectorAll("[data-quarter]").forEach((b) => b.classList.toggle("active", b === btn));
      setCurrentQuarter(btn.dataset.quarter);
      fillRegionsForQuarter(preferredDd);
      if (wasLoggedIn) {
        currentDd = selectedLoginDd;
        selectedId = null;
        paintRegion(currentDd, true);
        setStatus(isMaster ? currentQuarter + " · 마스터 · " + currentDd + " 조회 중" : currentQuarter + " · " + currentDd + " 조회 중");
        doSearch();
      }
    });
  });
  fillRegionsForQuarter();
}

function fillRegionsForQuarter(preferredDd = "") {
  const regions = Object.keys(currentQuarterData.regions || {}).sort((a, b) => a.localeCompare(b, "ko"));
  selectedLoginDd = regions.includes(preferredDd) ? preferredDd : (regions[0] || null);
  updateSelectedRegion();
  const picker = $("regionPicker");
  picker.innerHTML = regions.map((dd) => '<button class="region-option" type="button" role="option" data-region="' + dd + '">' + dd + '</button>').join("");
  paintRegion(selectedLoginDd || regions[0] || "", Boolean(currentDd));
  picker.querySelectorAll("[data-region]").forEach((button) => {
    button.addEventListener("click", () => {
      if (currentDd && !isMaster) return;
      selectedLoginDd = button.dataset.region;
      if (isMaster) {
        currentDd = selectedLoginDd;
        selectedId = null;
        paintRegion(selectedLoginDd, true);
        setStatus(currentQuarter + " · 마스터 · " + selectedLoginDd + " 조회 중");
        doSearch();
        return;
      }
      paintRegion(selectedLoginDd, false);
      updateSelectedRegion();
    });
  });
}

function updateSelectedRegion() {
  const el = $("selectedRegionName");
  if (el) {
    const manager = regionManager(selectedLoginDd);
    el.innerHTML = (selectedLoginDd || "-") + (manager ? '<small>(' + manager + ')</small>' : "");
  }
}

function paintRegion(region, locked) {
  const picker = $("regionPicker");
  if (picker) {
    picker.querySelectorAll("[data-region]").forEach((button) => {
      const active = button.dataset.region === region;
      button.classList.toggle("active", active);
      button.disabled = Boolean(locked && !isMaster && !active);
    });
  }
}

function validateRegion(dd, code) {
  const expected = norm(currentQuarterData.regions[dd]);
  if (!expected) throw new Error("지역 정보가 없습니다.");
  if (norm(code) === norm(MASTER_KEY)) return "master";
  if (norm(code) !== expected) throw new Error("지역/암호가 틀립니다.");
  return "region";
}

function rowSortDate(row) {
  const dates = [];
  if (Array.isArray(row.records)) {
    for (const rec of row.records) {
      if (rec.date) dates.push(String(rec.date));
      if (rec.detail && rec.detail.E) dates.push(String(rec.detail.E));
    }
  }
  if (row.latest_date) dates.push(String(row.latest_date));
  return dates.sort().at(-1) || "";
}

function buildAvgRow(rows, idSeed) {
  const scores = rows.map((r) => Number(r.ap_avg)).filter(Number.isFinite);
  if (scores.length <= 1) return null;
  const base = rows[0];
  const stores = rows.map((r) => r.store).filter(Boolean);
  const storeScores = rows.map((r) => ({
    store: r.store || "",
    ap_avg: r.ap_avg,
    latest_date: rowSortDate(r),
    dd: r.dd || "",
    note: r.note || "",
    note_type: r.note_type || "",
    note_raw: r.note_raw || "",
  }));
  return {
    ...base,
    _id: "avg-" + idSeed,
    _isAvg: true,
    _children: rows,
    store: "(AVG)",
    ap_avg: scores.reduce((a, b) => a + b, 0) / scores.length,
    audit_count: rows.length,
    stores,
    store_scores: storeScores,
    records: [],
  };
}

function buildVisibleRows() {
  const q = norm($("qInput").value);
  const globalSearch = isMaster && q;
  let sourceRows = currentQuarterData.rows
    .filter((row) => row.store !== "(AVG)")
    .map((row, idx) => ({ ...row, _id: "row-" + idx, _isAvg: false }));

  if (currentDd && !globalSearch) {
    const localKeys = new Set(sourceRows.filter((r) => r.dd === currentDd).map(personKey));
    sourceRows = sourceRows.filter((r) => localKeys.has(personKey(r)));
  }

  if (q) sourceRows = sourceRows.filter((r) => norm(r.store).includes(q) || norm(r.name).includes(q));

  const groups = new Map();
  for (const row of sourceRows) {
    const key = personKey(row);
    if (!groups.has(key)) groups.set(key, []);
    groups.get(key).push(row);
  }

  const groupList = Array.from(groups.values()).map((rows, groupIdx) => {
    rows.sort((a, b) => {
      const aLocal = a.dd === currentDd ? 0 : 1;
      const bLocal = b.dd === currentDd ? 0 : 1;
      if (!isMaster && aLocal !== bLocal) return aLocal - bLocal;
      const date = rowSortDate(a).localeCompare(rowSortDate(b));
      if (date) return date;
      return String(a.store || "").localeCompare(String(b.store || ""), "ko");
    });
    const avg = buildAvgRow(rows, groupIdx);
    const first = rows[0];
    return {
      key: personKey(first),
      name: first.name || "",
      emp: first.emp || "",
      pos: first.pos || "",
      rows: avg ? [avg, ...rows] : rows,
    };
  });

  groupList.sort((a, b) => {
    const n = String(a.name).localeCompare(String(b.name), "ko");
    if (n) return n;
    const e = String(a.emp).localeCompare(String(b.emp), "ko");
    if (e) return e;
    return String(a.pos).localeCompare(String(b.pos), "ko");
  });

  visibleRows = [];
  for (const group of groupList) {
    group.rows.forEach((row, index) => {
      visibleRows.push({ ...row, _groupKey: group.key, _groupStart: index === 0, _groupSize: group.rows.length });
    });
  }
}

function rowKind(row) {
  if (row.store === "(AVG)") return "평가 평균";
  if (isMaster) return row.dd || "";
  return row.dd === currentDd ? currentDd : "타지역";
}

function badgeClass(row) {
  if (row.store === "(AVG)") return "badge avg";
  if (!isMaster && row.dd !== currentDd) return "badge other";
  return "badge";
}

function renderSummary() {
  const localRows = visibleRows.filter((r) => isMaster || r.dd === currentDd);
  const stores = new Set(localRows.filter((r) => r.store && r.store !== "(AVG)").map((r) => r.store));
  const scores = localRows.map((r) => Number(r.ap_avg)).filter(Number.isFinite);
  const avg = scores.length ? scores.reduce((a, b) => a + b, 0) / scores.length : null;
  {
    const manager = regionManager(currentDd);
    $("metricRegion").innerHTML = (currentDd || "-") + (manager ? '<small>(' + manager + ')</small>' : "");
  }
  $("metricStores").textContent = String(stores.size);
  $("metricRows").textContent = String(new Set(localRows.map(personKey)).size);
  $("metricAvg").textContent = avg === null ? "-" : fmt2(avg);
}

function renderTable() {
  const tbody = $("resultTable").querySelector("tbody");
  tbody.innerHTML = visibleRows.map((r) => {
    const selected = r._id === selectedId;
    const store = r.store === "(AVG)" ? "평가 평균" : (r.store || "");
    const groupClass = (r._groupStart ? " group-start" : "") + (r._isAvg ? " avg-row" : "");
    return '<tr data-id="' + r._id + '" class="' + (selected ? "selected" : "") + groupClass + '">' +
      '<td><span class="' + badgeClass(r) + '">' + rowKind(r) + '</span></td>' +
      '<td>' + store + '</td><td>' + (r.name || "") + '</td><td>' + (r.emp || "") + '</td><td>' + (r.pos || "") + '</td>' +
      '<td class="num ' + (Number(r.ap_avg) < 85 ? "score-high" : "") + '">' + fmt2(r.ap_avg) + '</td></tr>';
  }).join("");
  tbody.querySelectorAll("tr").forEach((tr) => tr.addEventListener("click", () => selectRow(tr.dataset.id)));
  $("resultHint").textContent = "조회 결과 " + visibleRows.length + "건";
}

function renderDetail(row) {
  if (!row) {
    $("detailBody").innerHTML = '<div class="empty">조회 결과에서 행을 선택하세요.</div>';
    $("detailScope").textContent = "선택 대기";
    return;
  }
  const initial = String(row.name || "?").slice(0, 1);
  const storeLabel = row.store === "(AVG)" ? "평가 평균" : (row.store || "");
  const isOther = !isMaster && row.dd !== currentDd && row.store !== "(AVG)";
  $("detailScope").textContent = rowKind(row);
  const scoreTitle = row.store === "(AVG)" ? "평가 평균" : "최종 점수";
  let html = '<div class="profile"><div class="avatar">' + initial + '</div><div><strong>' + (row.name || "") + '</strong><span>' + (row.emp || "") + ' · ' + (row.pos || "") + ' · ' + storeLabel + '</span></div></div>';
  html += '<div class="score-box"><div class="mini"><span>' + scoreTitle + '</span><strong class="' + (Number(row.ap_avg) < 85 ? "score-high" : "") + '">' + fmt2(row.ap_avg) + '</strong></div><div class="mini"><span>구분</span><strong>' + rowKind(row) + '</strong></div></div>';
  if (row.store === "(AVG)" && Array.isArray(row.store_scores)) {
    html += '<div class="timeline">' + row.store_scores.map((s) => '<div class="audit"><strong>' + (s.store || "") + ' · ' + fmt2(s.ap_avg) + noteBadge(s) + '</strong><span>최근 조사일 ' + (s.latest_date || "-") + '</span></div>').join("") + '</div>';
  } else if (isOther) {
    html += '<div class="audit"><strong>타지역 점수 요약</strong><span>평균 산정을 위한 점수만 표시하고 상세 조사 내역은 숨깁니다.</span></div>';
  } else if (Array.isArray(row.records) && row.records.length) {
    html += '<div class="timeline">' + row.records.map((rec) => {
      const d = rec.detail || {};
      return '<div class="audit"><strong>' + (rec.date || d.E || "-") + ' · ' + fmt2(rec.ap) + noteBadge(rec.note ? rec : row) + '</strong><span>신발 ' + (d.I ?? "") + ' · 용품 ' + (d.R ?? "") + ' · 의류 ' + (d.AA ?? "") + '</span></div>';
    }).join("") + '</div>';
  }
  $("detailBody").innerHTML = html;
}

function selectRow(id) {
  selectedId = id;
  renderTable();
  renderDetail(visibleRows.find((r) => r._id === id));
}

function doSearch() {
  buildVisibleRows();
  renderSummary();
  if (!visibleRows.some((r) => r._id === selectedId)) selectedId = visibleRows[0]?._id ?? null;
  renderTable();
  renderDetail(visibleRows.find((r) => r._id === selectedId));
}

function enter() {
  try {
    const dd = selectedLoginDd;
    const mode = validateRegion(dd, $("codeInput").value);
    isMaster = mode === "master";
    currentDd = dd;
    paintRegion(dd, true);
    $("loginToolbar").classList.add("hidden");
    $("loginNotice").classList.add("hidden");
    $("summaryGrid").classList.remove("hidden");
    $("searchToolbar").classList.remove("hidden");
    $("contentGrid").classList.remove("hidden");
    setStatus(isMaster ? currentQuarter + " · 마스터 · " + dd + " 조회 중" : currentQuarter + " · " + dd + " 접속 중");
    doSearch();
  } catch (err) {
    setStatus(err.message || String(err));
  }
}

function logout() {
  currentDd = null;
  currentQuarterData = currentQuarterData || getQuarterEntries()[0].data;
  isMaster = false;
  selectedId = null;
  $("codeInput").value = "";
  $("qInput").value = "";
  $("loginToolbar").classList.remove("hidden");
  $("loginNotice").classList.remove("hidden");
  $("summaryGrid").classList.add("hidden");
  $("searchToolbar").classList.add("hidden");
  $("contentGrid").classList.add("hidden");
  paintRegion(selectedLoginDd, false);
  updateSelectedRegion();
  setStatus("지역 선택 대기");
}

$("enterBtn").addEventListener("click", enter);
$("codeInput").addEventListener("keydown", (e) => { if (e.key === "Enter") enter(); });
$("qInput").addEventListener("input", doSearch);
$("resetBtn").addEventListener("click", () => { $("qInput").value = ""; doSearch(); });
$("logoutBtn").addEventListener("click", logout);


document.addEventListener("keydown", (event) => {
  if (event.ctrlKey && event.shiftKey && (event.key === "M" || event.key === "m")) {
    event.preventDefault();
    const input = prompt("마스터키 입력");
    if (input === null) return;
    if (norm(input) !== norm(MASTER_KEY)) {
      setStatus("마스터키가 틀립니다.");
      return;
    }
    if (!dataObj || !currentQuarterData) {
      setStatus("데이터 로드 후 다시 시도하세요.");
      return;
    }
    isMaster = true;
    currentDd = selectedLoginDd;
    selectedId = null;
    $("loginToolbar").classList.add("hidden");
    $("loginNotice").classList.add("hidden");
    $("summaryGrid").classList.remove("hidden");
    $("searchToolbar").classList.remove("hidden");
    $("contentGrid").classList.remove("hidden");
    paintRegion(currentDd, true);
    setStatus(currentQuarter + " · 마스터 · " + currentDd + " 조회 중");
    doSearch();
  }
});

loadData().catch((err) => setStatus("데이터 로드 실패: " + (err.message || err)));


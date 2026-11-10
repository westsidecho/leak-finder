(() => {
  "use strict";

  const SCOPE = "https://www.googleapis.com/auth/gmail.readonly";
  const API = "https://gmail.googleapis.com/gmail/v1/users/me";
  const NOTICE_Q = [
    'subject:(개인정보 유출)', 'subject:(개인정보 침해)', 'subject:(정보 유출 사과)',
    'subject:("data security incident")', 'subject:("security incident")',
    'subject:("data breach")', 'subject:("unauthorized access")',
  ].join(" OR ");

  const $ = (id) => document.getElementById(id);
  const esc = (s) => String(s ?? "").replace(/[&<>"']/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;" }[c]));
  const views = ["view-start", "view-progress", "view-result"];
  const show = (id) => views.forEach((v) => ($(v).hidden = v !== id));

  // ── 설정 ───────────────────────────────────────────
  const storage = {
    get(k) { try { return localStorage.getItem(k); } catch { return null; } },
    set(k, v) { try { localStorage.setItem(k, v); } catch { /* 저장 불가 환경 */ } },
  };
  const clientId = () => (window.APP_CONFIG && window.APP_CONFIG.googleClientId) || storage.get("clientId") || "";
  const refreshWarn = () => ($("setup-warn").hidden = !!clientId());

  $("client-box").hidden = !!(window.APP_CONFIG && window.APP_CONFIG.googleClientId);
  $("btn-settings").onclick = () => { $("in-client").value = clientId(); $("in-name").value = storage.get("userName") || ""; $("dlg-settings").showModal(); };
  $("btn-save").onclick = () => { storage.set("clientId", $("in-client").value.trim()); storage.set("userName", $("in-name").value.trim()); refreshWarn(); toast("저장했습니다"); };

  function toast(msg) {
    const t = $("toast");
    t.textContent = msg; t.hidden = false;
    clearTimeout(toast.t); toast.t = setTimeout(() => (t.hidden = true), 2200);
  }

  // ── 매칭 도우미 ─────────────────────────────────────
  const domainOf = (from) => {
    const m = String(from).match(/@([^>\s]+)/);
    return m ? m[1].toLowerCase() : "";
  };
  const matchesDomain = (dom, d) => dom === d || dom.endsWith("." + d);
  const breachForDomain = (dom) =>
    window.BREACHES.find((b) => b.domains.some((d) => matchesDomain(dom, d)));
  const fmtDate = (d) => {
    const x = new Date(d);
    return isNaN(x) ? "" : `${x.getFullYear()}.${String(x.getMonth() + 1).padStart(2, "0")}.${String(x.getDate()).padStart(2, "0")}`;
  };
  const gmailDate = (iso) => iso.replace(/-/g, "/");

  // ── Gmail API ──────────────────────────────────────
  async function gget(token, path) {
    const r = await fetch(API + path, { headers: { Authorization: "Bearer " + token } });
    if (!r.ok) throw new Error("Gmail API " + r.status);
    return r.json();
  }
  async function listIds(token, q, max) {
    const j = await gget(token, `/messages?maxResults=${max}&q=${encodeURIComponent(q)}`);
    return (j.messages || []).map((m) => m.id);
  }
  async function meta(token, id) {
    const j = await gget(token, `/messages/${id}?format=metadata&metadataHeaders=From&metadataHeaders=Subject&metadataHeaders=Date`);
    const h = Object.fromEntries((j.payload?.headers || []).map((x) => [x.name.toLowerCase(), x.value]));
    return { from: h.from || "", subject: h.subject || "", date: h.date || (j.internalDate ? new Date(+j.internalDate).toISOString() : "") };
  }
  async function pool(items, n, fn) {
    const out = []; let i = 0;
    await Promise.all(Array.from({ length: n }, async () => {
      while (i < items.length) { const k = i++; out[k] = await fn(items[k], k); }
    }));
    return out;
  }

  async function scan(token) {
    const progress = (p, text) => { $("bar-fill").style.width = p + "%"; $("progress-text").textContent = text; };
    const hits = new Map();
    const unmatched = [];

    // 1) 유출 통지 메일
    progress(5, "유출 통지 메일을 찾고 있어요");
    const noticeIds = await listIds(token, NOTICE_Q, 50);
    const notices = await pool(noticeIds, 6, (id) => meta(token, id));
    for (const n of notices) {
      const dom = domainOf(n.from);
      if (window.PERSONAL_DOMAINS.includes(dom)) continue;
      const b = breachForDomain(dom);
      if (b) {
        if (!hits.has(b.id)) hits.set(b.id, { breach: b, status: "notified", evidence: n });
      } else if (/(유출|침해|incident|breach|unauthori)/i.test(n.subject) && /(통지|사과|안내|notif|notice)/i.test(n.subject)) {
        unmatched.push(n);
      }
    }

    // 2) 사고 전부터 가입돼 있었는지
    const targets = window.BREACHES.filter((b) => b.scope !== "small" && !hits.has(b.id));
    let done = 0;
    await pool(targets, 5, async (b) => {
      const q = `from:(${b.domains.join(" OR ")}) before:${gmailDate(b.date)}`;
      const ids = await listIds(token, q, 1);
      if (ids.length) {
        const m = await meta(token, ids[0]);
        if (b.domains.some((d) => matchesDomain(domainOf(m.from), d))) {
          hits.set(b.id, { breach: b, status: b.scope === "all" ? "likely" : "possible", evidence: m });
        }
      }
      done++;
      progress(10 + Math.round((done / targets.length) * 88), `${b.name} 확인 중 (${done}/${targets.length})`);
    });

    progress(100, "보낸 문의에 회신이 왔는지 확인하고 있어요");
    await checkReplies(token);
    return { hits: [...hits.values()], unmatched };
  }

  // ── 로그인 ─────────────────────────────────────────
  $("btn-google").onclick = () => {
    if (!clientId()) { $("btn-settings").click(); return; }
    if (!window.google?.accounts?.oauth2) { toast("Google 로그인 스크립트를 불러오지 못했습니다"); return; }
    const tc = google.accounts.oauth2.initTokenClient({
      client_id: clientId(),
      scope: SCOPE,
      callback: async (resp) => {
        if (resp.error || !google.accounts.oauth2.hasGrantedAllScopes(resp, SCOPE)) {
          toast("메일 읽기 권한이 필요합니다"); return;
        }
        demoInquiries = null; isDemo = false;
        show("view-progress");
        try { userEmail = (await gget(resp.access_token, "/profile")).emailAddress || ""; } catch { /* 없어도 진행 */ }
        try {
          const result = await scan(resp.access_token);
          render(result);
        } catch (e) {
          console.error(e);
          show("view-start");
          toast("메일함을 읽지 못했습니다: " + e.message);
        } finally {
          google.accounts.oauth2.revoke(resp.access_token, () => {});
        }
      },
    });
    tc.requestAccessToken();
  };

  // ── 예시 데이터 ────────────────────────────────────
  $("btn-demo").onclick = async () => {
    show("view-progress");
    for (let p = 0; p <= 100; p += 20) {
      $("bar-fill").style.width = p + "%";
      $("progress-text").textContent = "예시 메일함을 확인하고 있어요";
      await new Promise((r) => setTimeout(r, 180));
    }
    const B = Object.fromEntries(window.BREACHES.map((b) => [b.id, b]));
    isDemo = true;
    demoInquiries = [
      { id: "tving-2026", name: "티빙", to: "tving@cj.net", sentAt: addDays(TODAY, -6), due: addDays(TODAY, 4), status: "replied",
        reply: { subject: "[티빙] 개인정보 열람 요구에 대한 답변드립니다", date: addDays(TODAY, -2) } },
      { id: "myrealtrip-2026", name: "마이리얼트립", to: "help@myrealtrip.com", sentAt: addDays(TODAY, -13), due: addDays(TODAY, -3), status: "waiting" },
    ];
    const ev = (from, subject, date) => ({ from, subject, date });
    render({
      hits: [
        { breach: B["myrealtrip-2026"], status: "notified", evidence: ev("noreply@myrealtrip.com", "[마이리얼트립] 개인정보 유출 사실 통지 및 사과문", "2026-10-28") },
        { breach: B["tving-2026"], status: "notified", evidence: ev("no-reply@tving.com", "[TVING] 개인정보 유출 사실 통지 및 사과문", "2026-06-05") },
        { breach: B["coupang-2025"], status: "notified", evidence: ev("no_reply@coupang.com", "[쿠팡]_구매이용권 안내드립니다.", "2026-01-16") },
        { breach: B["yes24-2025"], status: "likely", evidence: ev("no-reply@yes24.com", "예스24 서비스 이용약관 개정 안내", "2025-06-06") },
        { breach: B["marriott-2018"], status: "notified", evidence: ev("starwood@email-marriott.com", "Starwood Guest Reservation Database Security Incident", "2018-12-17") },
        { breach: B["skt-2025"], status: "likely", evidence: ev("TUniverse@sktelecom.com", "[T 우주] 개인정보 이용내역 안내", "2025-04-02") },
        { breach: B["kakaopay-2024"], status: "likely", evidence: ev("noti@kakaopaycorp.com", "[카카오페이] 개인정보 이용·제공 내역 안내", "2023-12-06") },
        { breach: B["linkedin-2012"], status: "likely", evidence: ev("messages-noreply@linkedin.com", "Welcome to LinkedIn", "2012-03-10") },
        { breach: B["dropbox-2012"], status: "likely", evidence: ev("no-reply@dropboxmail.com", "Welcome to Dropbox", "2011-02-01") },
        { breach: B["notion-2026"], status: "possible", evidence: ev("team@mail.notion.so", "Your workspace summary", "2026-10-20") },
        { breach: B["openai-2025"], status: "possible", evidence: ev("noreply@email.openai.com", "Your API usage", "2025-09-01") },
      ],
      unmatched: [],
    });
  };

  // ── 결과 화면 ──────────────────────────────────────
  const GROUPS = [
    { key: "notified", title: "유출 통지를 받은 곳", hint: "회사가 직접 알려온 곳", tag: ["red", "통지 받음"] },
    { key: "likely", title: "사고 당시 가입돼 있던 곳", hint: "통지는 못 찾았지만 이용자 대부분이 대상이었던 사고", tag: ["amber", "대상일 가능성 높음"] },
    { key: "possible", title: "일부만 대상이었던 곳", hint: "가입은 돼 있었지만 일부 이용자만 영향받은 사고", tag: ["gray", "확인 필요"] },
  ];
  const COMP = {
    open: (c) => `<div class="comp open"><b>지금 신청할 수 있는 보상이 있어요.</b> ${esc(c.note)}</div>`,
    closed: (c) => `<div class="comp closed">보상 신청 마감${c.note ? " · " + esc(c.note) : ""}</div>`,
    unknown: (c) => c.note ? `<div class="comp closed">${esc(c.note)}</div>` : "",
    none: (c) => c.note ? `<div class="comp closed">${esc(c.note)}</div>` : "",
  };

  // ── 금액 계산 ──────────────────────────────────────
  const TODAY = new Date().toISOString().slice(0, 10);
  const won = (n) => n.toLocaleString("ko-KR") + "원";
  const yearsSince = (iso) => (Date.now() - new Date(iso)) / (365.25 * 864e5);
  function money(h) {
    const b = h.breach, mine = h.status === "notified" || h.status === "likely";
    const offer = b.offer && mine ? b.offer : null;
    const missed = offer && offer.deadline < TODAY ? offer : null;
    const openOffer = offer && offer.deadline >= TODAY ? offer : null;
    let claim = null;
    if (mine && b.claim) claim = b.claim;
    else if (mine && b.region === "KR" && b.scope === "all" && yearsSince(b.date) < 3)
      claim = { won: 100000, basis: "과거 판례·분쟁조정 기준 1인당 10만 원 안팎 (예상)",
        why: [...(b.claimWhy || []),
          "판례 기준: 2014년 카드 3사 유출 사건에서 법원이 1인당 위자료 10만 원을 인정",
          "분쟁조정 기준: 2026년 쿠팡 사건에서 소비자분쟁조정위원회가 1인당 10만 원을 결정",
          `법정손해배상(개인정보 보호법 제39조의2): 실제 손해를 증명하지 않아도 최대 300만 원까지 청구 가능`,
          `청구 기한: 사고를 안 날부터 3년 (이 사고는 ${fmtDate(addDays(b.date, 1096))}경까지)`] };
    return { missed, openOffer, claim };
  }

  const addDays = (iso, n) => { const d = new Date(iso); d.setDate(d.getDate() + n); return d.toISOString().slice(0, 10); };
  const korDate = (iso) => { const [y, m, d] = iso.split("-").map(Number); return `${y}년 ${m}월 ${d}일`; };

  let isDemo = false, userEmail = "";

  function letter(b, status, name, email) {
    const late = b.comp.status === "closed" && status === "notified";
    const due = addDays(TODAY, 10);
    const subject = late ? "개인정보 열람 요구 및 유출 보상 추가 신청 요청" : "개인정보 열람 요구 및 피해구제 문의";
    const lines = [
      `안녕하세요. ${b.name} 회원 ${name || ""}입니다.`.replace(" 입니다", "입니다"),
      "",
      ...(email ? [`가입 이메일: ${email}`, ""] : []),
      status === "notified"
        ? `${b.name}의 개인정보 유출 통지 메일을 이 이메일 주소로 받았습니다.`
        : `${fmtDate(b.date)} 전후에 발생한 개인정보 유출 사고와 관련해 문의드립니다.`,
      "",
      "1. 개인정보 보호법 제35조에 따라 제 개인정보의 열람을 요구합니다. 제 계정에서 실제로 유출된 항목과 유출 시점을 알려주시기 바랍니다.",
      late
        ? "2. 보상 신청 기간을 놓쳤습니다. 유출 통지 대상자로서 지금이라도 신청할 수 있는지, 가능하다면 방법을 알려주시기 바랍니다."
        : "2. 보상이나 피해구제 절차가 있다면 대상, 신청 방법, 기한을 알려주시기 바랍니다.",
      "",
      `개인정보 보호법 시행령 제41조에 따라 열람 요구를 받은 날부터 10일 이내(${korDate(due)}까지) 회신해 주시기 바랍니다. 기한 안에 회신이 없으면 개인정보침해신고센터(118)에 신고할 예정입니다.`,
      "",
      "회신은 이 이메일 주소로 부탁드립니다. 감사합니다.",
      "",
      name ? `${name} 드림` : "",
    ];
    return { subject, body: lines.join("\n").trim(), due };
  }

  function reportText(q) {
    const b = window.BREACHES.find((x) => x.id === q.id);
    return [
      "제목: 개인정보 열람 요구 미회신 신고",
      "",
      `신고 대상: ${b.name}`,
      `요구 일자: ${korDate(q.sentAt)} (${q.to} 앞 이메일)`,
      `회신 기한: ${korDate(q.due)} (개인정보 보호법 시행령 제41조, 10일)`,
      "",
      `${b.name}의 개인정보 유출 사고(${fmtDate(b.date)})와 관련해 개인정보 보호법 제35조에 따른 열람을 요구했으나, 기한이 지나도록 회신을 받지 못했습니다.`,
      "유출된 제 개인정보 항목을 확인할 수 있도록 조치를 요청합니다.",
      "",
      "접수처: 개인정보침해신고센터 privacy.kisa.or.kr (국번 없이 118)",
    ].join("\n");
  }

  // ── 문의 현황 (이 브라우저에만 저장) ─────────────────
  let demoInquiries = null;
  const loadInq = () => { if (demoInquiries) return demoInquiries; try { return JSON.parse(storage.get("inquiries") || "[]"); } catch { return []; } };
  const saveInq = (list) => { if (demoInquiries) { demoInquiries = list; return; } storage.set("inquiries", JSON.stringify(list)); };
  function addInquiry(b, due) {
    const list = loadInq().filter((q) => q.id !== b.id);
    list.push({ id: b.id, name: b.name, to: b.contact.email, sentAt: TODAY, due, status: "waiting" });
    saveInq(list);
  }
  async function checkReplies(token) {
    const list = loadInq();
    for (const q of list.filter((x) => x.status === "waiting")) {
      const b = window.BREACHES.find((x) => x.id === q.id);
      const ids = await listIds(token, `from:(${b.domains.concat(q.to.split("@")[1]).join(" OR ")}) after:${gmailDate(q.sentAt)}`, 1);
      if (ids.length) { const m = await meta(token, ids[0]); q.status = "replied"; q.reply = { subject: m.subject, date: m.date }; }
    }
    saveInq(list);
  }
  function trackerHtml() {
    const list = loadInq();
    if (!list.length) return "";
    const replied = list.filter((q) => q.status === "replied").length;
    const rows = list.map((q) => {
      const left = Math.ceil((new Date(q.due) - new Date(TODAY)) / 864e5);
      let state, extra = "";
      if (q.status === "replied") { state = `<span class="tag green">회신 도착</span>`; extra = `<p class="evidence">“${esc(q.reply.subject)}” · ${esc(fmtDate(q.reply.date))}</p>`; }
      else if (left < 0) { state = `<span class="tag red">기한 ${-left}일 초과</span>`; extra = `<div class="actions"><button class="btn small primary" data-act="report" data-id="${q.id}">118 신고문 복사</button><a class="btn small" href="https://privacy.kisa.or.kr" target="_blank" rel="noopener">신고센터 열기</a></div>`; }
      else { state = `<span class="tag amber">회신 대기 D-${left}</span>`; }
      return `<div class="trow"><div class="card-head"><div><b>${esc(q.name)}</b><div class="card-sub">${esc(fmtDate(q.sentAt))} 문의 · ${esc(fmtDate(q.due))}까지 회신 의무</div></div>${state}</div>${extra}</div>`;
    }).join("");
    return `<section class="tracker"><h2>내 문의 현황 ${replied ? `<small class="new">새 회신 ${replied}건</small>` : ""}</h2>
      <p class="muted small">회사가 답하면 저희가 메일함에서 찾아 여기 알려드려요. 10일이 지나도 답이 없으면 신고까지 도와드려요.</p>${rows}</section>`;
  }

  function moneyBlock(m) {
    const rows = [];
    if (m.missed) rows.push(`<div class="mrow missed"><span>놓친 보상</span><b>${m.missed.won ? won(m.missed.won) : "보험"}</b><em>${esc(m.missed.label)} · ${esc(fmtDate(m.missed.deadline))} 마감</em></div>`);
    if (m.openOffer) rows.push(`<div class="mrow open"><span>지금 받을 수 있는 보상</span><b>${m.openOffer.won ? won(m.openOffer.won) : "신청 가능"}</b><em>${esc(m.openOffer.label)} · ${esc(fmtDate(m.openOffer.deadline))}까지</em></div>`);
    if (m.claim) rows.push(`<div class="mrow claim"><span>지금 청구할 수 있는 금액</span><b>${won(m.claim.won)}</b><em>${esc(m.claim.basis)}</em></div>`);
    return rows.length ? `<div class="money">${rows.join("")}</div>` : "";
  }

  function card(h) {
    const b = h.breach, g = GROUPS.find((x) => x.key === h.status);
    const ev = h.evidence;
    const evLine = h.status === "notified"
      ? `<span class="q">받은 메일</span> “${esc(ev.subject)}” · ${esc(fmtDate(ev.date))}`
      : `<span class="q">사고 전 받은 메일</span> ${esc(domainOf(ev.from))} · ${esc(fmtDate(ev.date))}`;
    const todo = (b.todo || []).length ? `<ul class="todo">${b.todo.map((t) => `<li>${esc(t)}</li>`).join("")}</ul>` : "";
    const actions = [];
    if (b.contact?.email) actions.push(`<button class="btn small primary" data-act="mail" data-id="${b.id}" data-st="${h.status}">문의 메일 쓰기</button>`);
    actions.push(`<button class="btn small" data-act="copy" data-id="${b.id}" data-st="${h.status}">문의문 복사</button>`);
    if (b.contact?.phone) actions.push(`<span class="card-sub" style="align-self:center">전화 ${esc(b.contact.phone)}</span>`);
    return `<article class="card">
      <div class="card-head">
        <div><div class="card-title">${esc(b.name)}</div><div class="card-sub">${b.region === "KR" ? "국내" : "해외"} · 사고 ${esc(fmtDate(b.date))}</div></div>
        <span class="tag ${g.tag[0]}">${g.tag[1]}</span>
      </div>
      <p class="evidence">${evLine}</p>
      ${moneyBlock(money(h))}
      <p class="items"><span class="muted">유출 항목</span> ${esc(b.items)}</p>
      ${(COMP[b.comp.status] || COMP.none)(b.comp)}
      ${todo}
      <div class="actions">${actions.join("")}</div>
    </article>`;
  }

  function render({ hits, unmatched }) {
    const by = (k) => hits.filter((h) => h.status === k);
    const ms = hits.map((h) => ({ h, m: money(h) }));
    const missed = ms.filter((x) => x.m.missed);
    const claims = ms.filter((x) => x.m.claim || x.m.openOffer);
    const missedWon = missed.reduce((s, x) => s + (x.m.missed.won || 0), 0);
    const missedPerks = missed.filter((x) => !x.m.missed.won);
    const claimWon = claims.reduce((s, x) => s + (x.m.claim?.won || 0) + (x.m.openOffer?.won || 0), 0);
    const chip = (x, k) => {
      if (k === "missed") return `<li><b>${esc(x.h.breach.name)}</b> ${x.m.missed.won ? won(x.m.missed.won) : esc(x.m.missed.label)} <span>${esc(fmtDate(x.m.missed.deadline))} 마감</span></li>`;
      const c = x.m.claim || {};
      const why = c.why || [c.basis];
      return `<li><details class="why"><summary><b>${esc(x.h.breach.name)}</b> ${won((c.won || 0) + (x.m.openOffer?.won || 0))} <span class="why-hint">근거 보기</span></summary>
        <p class="why-basis">${esc(c.basis || "")}</p><ul>${why.map((w) => `<li>${esc(w)}</li>`).join("")}</ul></details></li>`;
    };
    $("summary").innerHTML = `
      <p class="eyebrow">확인 결과 · 털린 곳 ${hits.length}곳</p>
      <div class="hero-money">
        <div class="hm missed">
          <span class="hm-label">이미 놓친 보상</span>
          <b class="hm-num">${won(missedWon)}${missedPerks.length ? ` <small>+ 보험 ${missedPerks.length}건</small>` : ""}</b>
          <p>회사가 보상을 내놨지만, 메일을 못 보고 기한이 지나 사라졌어요.</p>
          <ul class="chips">${missed.map((x) => chip(x, "missed")).join("") || "<li>없음</li>"}</ul>
        </div>
        <div class="hm claim">
          <span class="hm-label">지금 받을 수 있는 보상</span>
          <b class="hm-num">${won(claimWon)}</b>
          <p>분쟁조정이나 공동소송으로 아직 청구할 수 있는 예상 금액이에요.</p>
          <ul class="chips">${claims.map((x) => chip(x, "claim")).join("") || "<li>없음</li>"}</ul>
        </div>
      </div>
      <div class="help">
        <div>
          <b>이번엔 놓치지 마세요. 청구는 저희가 대신 준비해 드릴게요.</b>
          <p>대상 확인 문의 → 분쟁조정 신청서 작성 → 공동소송 연결까지 한 번에. 새 유출 사고가 나면 보상 기한 전에 먼저 알려드려요.</p>
        </div>
        <button class="btn primary" id="btn-help" type="button">${claimWon ? won(claimWon) + " 청구 시작하기" : "알림 받기"}</button>
      </div>
      <div class="stats">
        <div class="stat"><b>${by("notified").length}</b><span>통지를 받은 곳</span></div>
        <div class="stat"><b>${by("likely").length}</b><span>대상일 가능성 높은 곳</span></div>
        <div class="stat"><b>${by("possible").length}</b><span>확인이 필요한 곳</span></div>
      </div>`;
    let html = GROUPS.map((g) => {
      const list = by(g.key);
      if (!list.length) return "";
      list.sort((a, b) => b.breach.date.localeCompare(a.breach.date));
      return `<section class="group"><h2>${g.title} <small>${g.hint}</small></h2>${list.map(card).join("")}</section>`;
    }).join("");
    if (unmatched.length) {
      html += `<section class="group"><h2>목록에 없는 유출 통지 <small>사건 데이터에 아직 없는 곳</small></h2>${unmatched.map((n) => `
        <article class="card"><div class="card-title">${esc(domainOf(n.from))}</div>
        <p class="evidence">“${esc(n.subject)}” · ${esc(fmtDate(n.date))}</p></article>`).join("")}</section>`;
    }
    $("groups").innerHTML = trackerHtml() + (html || `<p class="lead">찾은 곳이 없어요.</p>`);
    window.__hits = hits;
    show("view-result");
    window.scrollTo(0, 0);
  }

  $("groups").addEventListener("click", async (e) => {
    const btn = e.target.closest("button[data-act]");
    if (!btn) return;
    const b = window.BREACHES.find((x) => x.id === btn.dataset.id);
    if (btn.dataset.act === "report") {
      const q = loadInq().find((x) => x.id === b.id);
      try { await navigator.clipboard.writeText(reportText(q)); toast("신고문을 복사했습니다"); }
      catch { toast("복사하지 못했습니다"); }
      return;
    }
    const { subject, body, due } = letter(b, btn.dataset.st, sender().name, sender().email);
    if (btn.dataset.act === "mail") {
      const url = `https://mail.google.com/mail/?view=cm&fs=1&to=${encodeURIComponent(b.contact.email)}&su=${encodeURIComponent(subject)}&body=${encodeURIComponent(body)}`;
      window.open(url, "_blank", "noopener");
      addInquiry(b, due);
      const tr = $("groups").querySelector(".tracker");
      const fresh = document.createElement("div"); fresh.innerHTML = trackerHtml();
      if (tr) tr.replaceWith(fresh.firstElementChild); else $("groups").prepend(fresh.firstElementChild);
      toast("보내고 나면 회신이 오는지 저희가 지켜볼게요");
    } else {
      try { await navigator.clipboard.writeText(`제목: ${subject}\n\n${body}`); toast("문의문을 복사했습니다"); }
      catch { toast("복사하지 못했습니다"); }
    }
  });

  // ── 청구 메일 보내기 ───────────────────────────────
  let drafts = [], stepIdx = -1;
  // 유출을 찾은 메일함 주소 = 그 서비스에 가입한 이메일
  const sender = () => ({ name: isDemo ? "조준호" : (storage.get("userName") || ""), email: isDemo ? "junhocho@example.com" : userEmail });

  function openHelp() {
    const me = sender();
    drafts = (window.__hits || [])
      .filter((h) => h.breach.contact?.email && (h.status === "notified" || h.status === "likely"))
      .filter((h) => !loadInq().some((q) => q.id === h.breach.id))
      .map((h) => ({ h, ...letter(h.breach, h.status, me.name, me.email), to: h.breach.contact.email, state: "ready" }));
    $("help-title").textContent = drafts.length ? `${drafts.length}곳에 문의 메일을 보낼게요` : "보낼 메일이 없어요";
    $("help-from").textContent = `보내는 사람: ${me.name || "이름 미입력"} <${me.email || "로그인한 Gmail"}> · 이 주소를 가입 이메일로 적어 보냅니다`;
    stepIdx = -1;
    renderDrafts();
    $("dlg-help").showModal();
  }

  function renderDrafts() {
    const stepping = stepIdx >= 0;
    $("help-actions").hidden = stepping || !drafts.some((d) => d.state === "ready");
    $("step-actions").hidden = !stepping;
    $("step-bar").hidden = !stepping;
    if (stepping) $("step-bar").textContent = `${stepIdx + 1} / ${drafts.length} · ${drafts[stepIdx].h.breach.name}`;
    $("mail-list").innerHTML = drafts.map((d, i) => {
      const b = d.h.breach;
      if (stepping && i !== stepIdx) return "";
      const done = d.state === "sent", skipped = d.state === "skipped";
      const open = stepping || i === 0;
      return `<details class="draft ${done ? "sent" : ""}" data-i="${i}" ${open ? "open" : ""}>
        <summary><b>${esc(b.name)}</b> <span class="muted small">${esc(d.to)}</span>
          ${b.contact.unverified ? `<span class="tag amber">주소 확인 필요</span>` : ""}
          ${done ? `<span class="tag green">보냄</span>` : skipped ? `<span class="tag gray">건너뜀</span>` : ""}</summary>
        <label>받는 사람</label><input data-f="to" value="${esc(d.to)}" ${done ? "disabled" : ""} />
        <label>제목</label><input data-f="subject" value="${esc(d.subject)}" ${done ? "disabled" : ""} />
        <label>본문</label><textarea data-f="body" rows="14" ${done ? "disabled" : ""}>${esc(d.body)}</textarea>
      </details>`;
    }).join("") || `<p class="muted">새로 보낼 곳이 없어요. 이미 보낸 문의는 '내 문의 현황'에서 확인하세요.</p>`;
  }

  // 수정한 내용을 drafts에 반영
  $("mail-list").addEventListener("input", (e) => {
    const f = e.target.dataset.f, card = e.target.closest(".draft");
    if (f && card) drafts[+card.dataset.i][f] = e.target.value;
  });

  const b64 = (s) => btoa(String.fromCharCode(...new TextEncoder().encode(s)));
  const b64url = (s) => b64(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  let sendToken = null;
  function getSendToken() {
    if (sendToken) return Promise.resolve(sendToken);
    const scope = "https://www.googleapis.com/auth/gmail.send";
    return new Promise((resolve, reject) => {
      google.accounts.oauth2.initTokenClient({
        client_id: clientId(), scope,
        callback: (r) => (r.error || !google.accounts.oauth2.hasGrantedAllScopes(r, scope)) ? reject(new Error("메일 보내기 권한이 필요합니다")) : resolve(sendToken = r.access_token),
      }).requestAccessToken();
    });
  }
  async function sendDraft(d) {
    if (!isDemo) {
      const token = await getSendToken();
      const mime = [`To: ${d.to}`, `Subject: =?UTF-8?B?${b64(d.subject)}?=`, "MIME-Version: 1.0",
        "Content-Type: text/plain; charset=UTF-8", "Content-Transfer-Encoding: base64", "", b64(d.body)].join("\r\n");
      const r = await fetch(API + "/messages/send", { method: "POST", headers: { Authorization: "Bearer " + token, "Content-Type": "application/json" }, body: JSON.stringify({ raw: b64url(mime) }) });
      if (!r.ok) throw new Error("보내기 실패 " + r.status);
    }
    d.state = "sent";
    const list = loadInq().filter((q) => q.id !== d.h.breach.id);
    list.push({ id: d.h.breach.id, name: d.h.breach.name, to: d.to, sentAt: TODAY, due: d.due, status: "waiting" });
    saveInq(list);
  }
  function refreshTracker() {
    const tr = $("groups").querySelector(".tracker");
    const fresh = document.createElement("div"); fresh.innerHTML = trackerHtml();
    if (!fresh.firstElementChild) return;
    if (tr) tr.replaceWith(fresh.firstElementChild); else $("groups").prepend(fresh.firstElementChild);
  }
  function finish() {
    const n = drafts.filter((d) => d.state === "sent").length;
    $("dlg-help").close(); refreshTracker();
    toast(n ? `${n}곳에 보냈어요${isDemo ? " (예시: 실제로 보내지 않았습니다)" : ""}. 회신이 오면 알려드릴게요` : "보낸 메일이 없어요");
  }

  $("summary").addEventListener("click", (e) => { if (e.target.closest("#btn-help")) openHelp(); });
  $("btn-help-close").onclick = () => { $("dlg-help").close(); refreshTracker(); };
  $("btn-send-all").onclick = async () => {
    try { for (const d of drafts.filter((x) => x.state === "ready")) await sendDraft(d); finish(); }
    catch (e) { renderDrafts(); toast(e.message); }
  };
  $("btn-step").onclick = () => { stepIdx = drafts.findIndex((d) => d.state === "ready"); renderDrafts(); };
  const nextStep = () => {
    stepIdx = drafts.findIndex((d, i) => i > stepIdx && d.state === "ready");
    if (stepIdx < 0) finish(); else renderDrafts();
  };
  $("btn-send-one").onclick = async () => {
    if (!drafts[stepIdx]) return;
    try { await sendDraft(drafts[stepIdx]); toast(`${drafts[stepIdx].h.breach.name}에 보냈어요`); nextStep(); }
    catch (e) { toast(e.message); }
  };
  $("btn-skip").onclick = () => { if (!drafts[stepIdx]) return; drafts[stepIdx].state = "skipped"; nextStep(); };

  $("btn-again").onclick = () => show("view-start");
  refreshWarn();
})();

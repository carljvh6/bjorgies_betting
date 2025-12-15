import "./style.css";
import { db, auth, provider, fns } from "./firebase";
import { signInWithPopup, signOut, onAuthStateChanged } from "firebase/auth";
import {
  collection,
  doc,
  getDocs,
  onSnapshot,
  orderBy,
  query,
  setDoc,
  serverTimestamp,
  Timestamp,
  where,
} from "firebase/firestore";
import { httpsCallable } from "firebase/functions";


let currentUser = null;
let currentView = "dashboard"; // "dashboard" | "profile"
let unsubscribeUpcomingEvents = null;
let unsubscribeEventMarkets = null;
let unsubscribeAccount = null;
let unsubscribePendingBets = null;
let unsubscribeUserDoc = null;
let currentBalance = null;
let headerAccountMetaEl = null;
const eventsCache = new Map(); // eventId -> event data

const appEl = document.querySelector("#app");
appEl.innerHTML = `
  <div style="max-width: 980px; margin: 32px auto; padding: 0 16px; text-align: left;">
    <header style="display:flex; align-items:center; justify-content:space-between; gap: 16px;">
      <div>
        <div style="font-size: 28px; font-weight: 750; letter-spacing: -0.02em;">Bjorgies betting</div>
        <div id="subtitle" style="opacity: 0.8; margin-top: 4px;">Pick winners. Track bets. Get paid.</div>
      </div>
      <div style="display:flex; align-items:center; gap: 16px;">
        <img
          src="/bjorn.webp"
          alt="Bjorgies betting"
          style="width: 88px; height: 88px; border-radius: 14px; object-fit: cover;"
        />
        <div id="authArea" style="display:flex; align-items:center; gap: 12px;"></div>
      </div>
    </header>

    <main id="main" style="margin-top: 24px;"></main>
  </div>
`;

const authAreaEl = document.querySelector("#authArea");
const mainEl = document.querySelector("#main");

function clearUpcomingEventsListener() {
  if (typeof unsubscribeUpcomingEvents === "function") {
    unsubscribeUpcomingEvents();
  }
  unsubscribeUpcomingEvents = null;
}

function clearEventMarketsListener() {
  if (typeof unsubscribeEventMarkets === "function") {
    unsubscribeEventMarkets();
  }
  unsubscribeEventMarkets = null;
}

function clearProfileListeners() {
  if (typeof unsubscribeAccount === "function") {
    unsubscribeAccount();
  }
  if (typeof unsubscribePendingBets === "function") {
    unsubscribePendingBets();
  }
  unsubscribeAccount = null;
  unsubscribePendingBets = null;
}

function clearUserDocListener() {
  if (typeof unsubscribeUserDoc === "function") {
    unsubscribeUserDoc();
  }
  unsubscribeUserDoc = null;
  currentBalance = null;
}

function updateHeaderMeta() {
  if (!headerAccountMetaEl) return;
  if (currentBalance == null) return;
  const existing = String(headerAccountMetaEl.textContent || "");
  if (existing.includes("balance")) {
    // Already set elsewhere; leave.
    return;
  }
  headerAccountMetaEl.textContent = `balance ${currentBalance}`;
}

function fmtTs(ts) {
  try {
    const d = ts?.toDate?.();
    if (!d) return "-";
    return d.toLocaleString();
  } catch {
    return "-";
  }
}

async function refreshAccountPanel(uid) {
  // Bets count (query bets where uid == current user)
  const betsQ = query(collection(db, "bets"), where("uid", "==", uid));
  const betsSnap = await getDocs(betsQ);

  // Ledger total (sum of deltas)
  const ledgerCol = collection(db, "users", uid, "ledger");
  const ledgerSnap = await getDocs(ledgerCol);
  let ledgerDeltaTotal = 0;
  for (const d of ledgerSnap.docs) {
    const delta = Number(d.data()?.delta ?? 0);
    if (Number.isFinite(delta)) ledgerDeltaTotal += delta;
  }

  return { betsCount: betsSnap.size, ledgerDeltaTotal };
}

function setView(nextView, user, payload = {}) {
  currentView = nextView;
  if (!user) return;

  if (nextView === "profile") {
    clearUpcomingEventsListener();
    clearEventMarketsListener();
    renderProfile(user);
    return;
  }

  if (nextView === "event") {
    clearUpcomingEventsListener();
    clearProfileListeners();
    renderEvent(user, payload.eventId);
    return;
  }

  // default
  clearProfileListeners();
  clearEventMarketsListener();
  renderDashboard(user);
}

function renderLoggedOut() {
  clearUpcomingEventsListener();
  clearEventMarketsListener();
  clearProfileListeners();
  clearUserDocListener();
  currentUser = null;
  currentView = "dashboard";

  authAreaEl.innerHTML = `
    <button id="login">Login</button>
  `;

  mainEl.innerHTML = `
    <section style="padding: 16px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
      <h1 style="margin: 0 0 8px 0; font-size: 42px; line-height: 1.1;">Welcome to Bjorgies betting</h1>
      <div style="opacity: 0.85; margin-bottom: 16px;">Sign in to see the upcoming events.</div>
      <button id="login2">Sign in with Google</button>
    </section>
  `;

  const login = async () => {
    try {
      await signInWithPopup(auth, provider);
    } catch (e) {
      console.error(e);
      mainEl.insertAdjacentHTML(
        "beforeend",
        `<div style="margin-top:12px; color: #b00020;">${e?.code || "error"}: ${e?.message || String(e)}</div>`
      );
    }
  };

  document.querySelector("#login").onclick = login;
  document.querySelector("#login2").onclick = login;
}

function renderDashboard(user) {
  clearUpcomingEventsListener();
  clearEventMarketsListener();

  mainEl.innerHTML = `
    <section style="padding: 16px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
      <div style="display:flex; align-items:flex-end; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
        <div>
          <div style="font-size: 18px; font-weight: 750;">Upcoming events</div>
          <div style="opacity: 0.8; margin-top: 4px;">All events that haven’t occurred yet.</div>
        </div>
        <div id="eventsStatus" style="opacity: 0.8;"></div>
      </div>
      <div id="eventsList" style="margin-top: 12px; display:flex; flex-direction:column; gap: 12px;"></div>
    </section>
  `;

  const eventsStatusEl = document.querySelector("#eventsStatus");
  const eventsListEl = document.querySelector("#eventsList");

  eventsStatusEl.textContent = "Loading…";

  const upcomingQ = query(
    collection(db, "events"),
    where("startTime", ">", Timestamp.now()),
    orderBy("startTime", "asc")
  );

  unsubscribeUpcomingEvents = onSnapshot(
    upcomingQ,
    (snap) => {
      eventsStatusEl.textContent = `${snap.size} event${snap.size === 1 ? "" : "s"}`;
      eventsCache.clear();

      if (snap.empty) {
        eventsListEl.innerHTML = `<div style="opacity:0.8; padding: 12px 0;">No upcoming events.</div>`;
        return;
      }

      const rows = snap.docs.map((d) => {
        const ev = d.data() || {};
        eventsCache.set(d.id, ev);
        const title = ev.name || d.id;
        const league = ev.league || ev.sport || "";
        const status = ev.status || "";
        const when = fmtTs(ev.startTime);
        const venue = ev.venue || "";

        return `
          <article data-event-id="${d.id}" style="padding: 12px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px; cursor: pointer;">
            <div style="display:flex; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
              <div style="font-weight: 750;">${title}</div>
              <div style="opacity: 0.8;">${when}</div>
            </div>
            <div style="opacity: 0.85; margin-top: 6px;">
              ${league ? `<span>${league}</span>` : ""}
              ${league && status ? `<span> • </span>` : ""}
              ${status ? `<span>${status}</span>` : ""}
              ${(league || status) && venue ? `<span> • </span>` : ""}
              ${venue ? `<span>${venue}</span>` : ""}
            </div>
          </article>
        `;
      });

      eventsListEl.innerHTML = rows.join("");
    },
    (err) => {
      console.error(err);
      eventsStatusEl.textContent = "Failed to load events";
      eventsListEl.innerHTML = `
        <div style="margin-top: 12px; color: #b00020;">
          ${err?.code || "error"}: ${err?.message || String(err)}
        </div>
      `;
    }
  );

  // Navigate to event detail via event delegation.
  eventsListEl.onclick = (e) => {
    const article = e.target?.closest?.("[data-event-id]");
    const eventId = article?.getAttribute?.("data-event-id");
    if (!eventId) return;
    setView("event", user, { eventId });
  };
}

function renderProfile(user) {
  clearProfileListeners();
  clearEventMarketsListener();

  mainEl.innerHTML = `
    <section style="padding: 16px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
      <div style="display:flex; align-items:flex-end; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
        <div>
          <div style="font-size: 18px; font-weight: 750;">Profile</div>
          <div style="opacity: 0.8; margin-top: 4px;">Balance and pending bets.</div>
        </div>
        <button id="backToEvents">Back to events</button>
      </div>

      <div style="margin-top: 16px; padding: 14px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
        <div style="opacity: 0.8; font-size: 12px;">Balance</div>
        <div id="balanceVal" style="font-size: 36px; font-weight: 850; letter-spacing: -0.02em; margin-top: 4px;">-</div>
      </div>

      <div style="margin-top: 16px;">
        <div style="display:flex; align-items:flex-end; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
          <div style="font-size: 16px; font-weight: 750;">Pending bets</div>
          <div id="pendingStatus" style="opacity: 0.8;"></div>
        </div>
        <div id="pendingList" style="margin-top: 12px; display:flex; flex-direction:column; gap: 12px;"></div>
      </div>
    </section>
  `;

  document.querySelector("#backToEvents").onclick = () => setView("dashboard", user);

  const balanceValEl = document.querySelector("#balanceVal");
  const pendingStatusEl = document.querySelector("#pendingStatus");
  const pendingListEl = document.querySelector("#pendingList");

  pendingStatusEl.textContent = "Loading…";

  unsubscribeAccount = onSnapshot(
    doc(db, "users", user.uid),
    (snap) => {
      const bal = snap.data()?.balance;
      const b = Number(bal);
      balanceValEl.textContent = Number.isFinite(b) ? String(b) : "-";
    },
    (err) => {
      console.error(err);
      balanceValEl.textContent = "-";
    }
  );

  const pendingQ = query(
    collection(db, "bets"),
    where("uid", "==", user.uid),
    where("status", "==", "placed")
  );

  unsubscribePendingBets = onSnapshot(
    pendingQ,
    (snap) => {
      pendingStatusEl.textContent = `${snap.size} bet${snap.size === 1 ? "" : "s"}`;

      if (snap.empty) {
        pendingListEl.innerHTML = `<div style="opacity:0.8; padding: 12px 0;">No pending bets.</div>`;
        return;
      }

      const rows = snap.docs.map((d) => {
        const b = d.data() || {};
        const stake = b.stake ?? "-";
        const option = b.option ?? "-";
        const marketId = b.marketId ?? d.id;
        const when = fmtTs(b.createdAt);
        return `
          <article style="padding: 12px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
            <div style="display:flex; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
              <div style="font-weight: 750;">${marketId}</div>
              <div style="opacity: 0.8;">${when}</div>
            </div>
            <div style="opacity: 0.85; margin-top: 6px;">
              <span><strong>Pick:</strong> ${option}</span>
              <span> • </span>
              <span><strong>Stake:</strong> ${stake}</span>
            </div>
          </article>
        `;
      });

      pendingListEl.innerHTML = rows.join("");
    },
    (err) => {
      console.error(err);
      pendingStatusEl.textContent = "Failed to load pending bets";
      pendingListEl.innerHTML = `
        <div style="margin-top: 12px; color: #b00020;">
          ${err?.code || "error"}: ${err?.message || String(err)}
        </div>
      `;
    }
  );
}

function americanToDecimal(american) {
  const a = Number(american);
  if (!Number.isFinite(a) || a === 0) return null;
  if (a > 0) return 1 + a / 100;
  return 1 + 100 / Math.abs(a);
}

function formatOdds(market, option) {
  const oddsTypeRaw = String(market?.oddsType || "").toLowerCase();
  const oddsType =
    oddsTypeRaw ||
    (market?.oddsAmerican ? "american" : market?.oddsDecimal ? "decimal" : "american");

  if (oddsType === "decimal") {
    const dec = Number(market?.oddsDecimal?.[option]);
    if (Number.isFinite(dec) && dec > 1) return { oddsType: "decimal", label: `${dec.toFixed(2)}x`, decimal: dec };

    // Fallback: equal odds (decimal) if not provided
    const opts = Array.isArray(market?.options) ? market.options : [];
    const fallback = opts.length >= 2 ? 2 : null;
    return fallback ? { oddsType: "decimal", label: `${fallback.toFixed(2)}x`, decimal: fallback } : { oddsType: "decimal", label: "—", decimal: null };
  }

  // American odds (UFC default)
  const raw = market?.oddsAmerican?.[option];
  const a = Number(raw);
  const american = Number.isFinite(a) && a !== 0 ? a : 100; // equal odds fallback: +100
  const label = american > 0 ? `+${american}` : String(american);
  return { oddsType: "american", label, decimal: americanToDecimal(american) };
}

function renderEvent(user, eventId) {
  clearEventMarketsListener();

  const ev = eventsCache.get(eventId) || {};
  const title = ev.name || eventId;
  const when = fmtTs(ev.startTime);
  const league = ev.league || ev.sport || "";

  mainEl.innerHTML = `
    <section style="padding: 16px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
      <div style="display:flex; align-items:flex-end; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
        <div>
          <div style="font-size: 18px; font-weight: 850;">${title}</div>
          <div style="opacity: 0.85; margin-top: 4px;">
            ${league ? `<span>${league}</span><span> • </span>` : ""}
            <span>${when}</span>
          </div>
        </div>
        <div style="display:flex; align-items:center; gap: 10px;">
          <div style="opacity: 0.8;">Balance: <span id="eventBalanceVal">-</span></div>
          <button id="backToEvents">Back</button>
        </div>
      </div>

      <div style="margin-top: 16px;">
        <div style="display:flex; align-items:flex-end; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
          <div style="font-size: 16px; font-weight: 750;">Odds & bet</div>
          <div id="marketsStatus" style="opacity: 0.8;"></div>
        </div>
        <div id="marketsList" style="margin-top: 12px; display:flex; flex-direction:column; gap: 12px;"></div>
        <div id="betMsg" style="margin-top: 12px;"></div>
      </div>
    </section>
  `;

  document.querySelector("#backToEvents").onclick = () => setView("dashboard", user);

  const eventBalanceValEl = document.querySelector("#eventBalanceVal");
  const marketsStatusEl = document.querySelector("#marketsStatus");
  const marketsListEl = document.querySelector("#marketsList");
  const betMsgEl = document.querySelector("#betMsg");

  const balText = currentBalance == null ? "-" : String(currentBalance);
  eventBalanceValEl.textContent = balText;

  marketsStatusEl.textContent = "Loading…";

  // Avoid composite index requirement (eventId + closesAt).
  // We sort client-side instead.
  const marketsQ = query(collection(db, "markets"), where("eventId", "==", eventId));

  unsubscribeEventMarkets = onSnapshot(
    marketsQ,
    (snap) => {
      const openDocs = snap.docs
        .filter((d) => (d.data()?.status || "open") !== "settled")
        .sort((a, b) => {
          const ad = a.data()?.closesAt?.toDate?.();
          const bd = b.data()?.closesAt?.toDate?.();
          const at = ad ? ad.getTime() : 0;
          const bt = bd ? bd.getTime() : 0;
          return at - bt;
        });
      marketsStatusEl.textContent = `${openDocs.length} market${openDocs.length === 1 ? "" : "s"}`;

      if (openDocs.length === 0) {
        marketsListEl.innerHTML = `<div style="opacity:0.8; padding: 12px 0;">No open markets for this event.</div>`;
        return;
      }

      const rows = openDocs.map((d) => {
        const m = d.data() || {};
        const question = m.question || "Market";
        const closesAt = fmtTs(m.closesAt);
        const opts = Array.isArray(m.options) ? m.options : [];

        const optionRows = opts.map((opt) => {
          const odds = formatOdds(m, opt);
          return `
            <div style="display:flex; align-items:center; justify-content:space-between; gap: 12px; padding: 10px; border: 1px solid rgba(127,127,127,0.18); border-radius: 10px;">
              <div>
                <div style="font-weight: 750;">${opt}</div>
                <div style="opacity: 0.8; font-size: 12px;">Odds (${odds.oddsType}): ${odds.label}</div>
              </div>
              <button data-bet-btn="1" data-market-id="${d.id}" data-option="${opt}">Bet</button>
            </div>
          `;
        }).join("");

        return `
          <article style="padding: 12px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
            <div style="display:flex; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
              <div style="font-weight: 850;">${question}</div>
              <div style="opacity: 0.8;">Closes: ${closesAt}</div>
            </div>
            <div style="margin-top: 10px;">
              <label style="display:flex; align-items:center; gap: 10px;">
                <span style="opacity: 0.85;">Stake</span>
                <input id="stake_${d.id}" type="number" min="1" step="1" inputmode="numeric" style="padding: 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,0.25); width: 140px;" placeholder="10" />
              </label>
            </div>
            <div style="margin-top: 12px; display:flex; flex-direction:column; gap: 10px;">
              ${optionRows}
            </div>
          </article>
        `;
      });

      marketsListEl.innerHTML = rows.join("");
    },
    (err) => {
      console.error(err);
      marketsStatusEl.textContent = "Failed to load markets";
      marketsListEl.innerHTML = `
        <div style="margin-top: 12px; color: #b00020;">
          ${err?.code || "error"}: ${err?.message || String(err)}
        </div>
      `;
    }
  );

  marketsListEl.onclick = async (e) => {
    const btn = e.target?.closest?.("[data-bet-btn]");
    if (!btn) return;

    const marketId = btn.getAttribute("data-market-id");
    const option = btn.getAttribute("data-option");
    const stakeEl = document.querySelector(`#stake_${CSS.escape(marketId)}`);
    const stake = Number(stakeEl?.value || "");

    betMsgEl.textContent = "";
    if (!marketId || !option) return;
    if (!Number.isInteger(stake) || stake <= 0) {
      betMsgEl.innerHTML = `<div style="color:#b00020;">Enter a valid stake amount.</div>`;
      return;
    }
    if (currentBalance != null && stake > currentBalance) {
      betMsgEl.innerHTML = `<div style="color:#b00020;">Stake exceeds your balance.</div>`;
      return;
    }

    try {
      btn.disabled = true;
      btn.textContent = "Placing…";
      const placeBet = httpsCallable(fns, "placeBet");
      const res = await placeBet({ marketId, option, stake });
      betMsgEl.innerHTML = `<div style="color:#0a7a2f;">Bet placed (${res.data?.betId || "ok"}). Balance will update.</div>`;
    } catch (err) {
      console.error(err);
      betMsgEl.innerHTML = `<div style="color:#b00020;">${err?.code || "error"}: ${err?.message || String(err)}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "Bet";
    }
  };
}

async function renderLoggedIn(user) {
  clearUpcomingEventsListener();
  clearProfileListeners();
  currentUser = user;

  authAreaEl.innerHTML = `
    <div style="display:flex; flex-direction:column; align-items:flex-end; gap: 2px;">
      <button id="profileLink" style="all: unset; cursor: pointer; font-weight: 650; text-align: right;">
        ${user.displayName || user.email || "Signed in"}
      </button>
      <div id="accountMeta" style="opacity: 0.8; font-size: 12px;"></div>
    </div>
    <button id="logout">Logout</button>
  `;

  headerAccountMetaEl = document.querySelector("#accountMeta");
  document.querySelector("#profileLink").onclick = () => setView("profile", user);
  document.querySelector("#logout").onclick = async () => {
    await signOut(auth);
  };
  const accountMetaEl = document.querySelector("#accountMeta");

  try {
    // Client-owned profile (safe to write from client).
    const profileRef = doc(db, "profiles", user.uid);
    await setDoc(
      profileRef,
      {
        displayName: user.displayName,
        email: user.email,
        photoURL: user.photoURL,
        updatedAt: serverTimestamp(),
      },
      { merge: true }
    );

    // Ensure server-owned `users/{uid}` exists (balance, role, etc).
    const ensureUser = httpsCallable(fns, "ensureUser");
    await ensureUser();

    const { betsCount, ledgerDeltaTotal } = await refreshAccountPanel(user.uid);
    accountMetaEl.textContent = `${betsCount} bets • ledger Δ ${ledgerDeltaTotal}`;
  } catch (e) {
    console.error(e);
    accountMetaEl.textContent = "Account load failed";
  }

  // Live user doc (balance updates after betting).
  clearUserDocListener();
  unsubscribeUserDoc = onSnapshot(
    doc(db, "users", user.uid),
    (snap) => {
      const bal = Number(snap.data()?.balance);
      currentBalance = Number.isFinite(bal) ? bal : null;
      updateHeaderMeta();

      const profileBalEl = document.querySelector("#balanceVal");
      if (profileBalEl) profileBalEl.textContent = currentBalance == null ? "-" : String(currentBalance);

      const eventBalEl = document.querySelector("#eventBalanceVal");
      if (eventBalEl) eventBalEl.textContent = currentBalance == null ? "-" : String(currentBalance);
    },
    (err) => {
      console.error(err);
      currentBalance = null;
    }
  );

  // Default view after login: dashboard.
  setView(currentView || "dashboard", user);
}

onAuthStateChanged(auth, async (user) => {
  if (!user) return renderLoggedOut();
  return renderLoggedIn(user);
});

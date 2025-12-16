import "./style.css";
import { db, auth, provider, fns } from "./firebase";
import { signInWithPopup, signOut, onAuthStateChanged, updateProfile } from "firebase/auth";
import {
  collection,
  doc,
  getDoc,
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
let currentProfile = null;
let currentView = "dashboard"; // "dashboard" | "profile"
let unsubscribeUpcomingEvents = null;
let unsubscribeEventMarkets = null;
let unsubscribeAccount = null;
let unsubscribePendingBets = null;
let unsubscribeUserDoc = null;
let unsubscribeGroupLeaderboard = null;
let groupLeaderboardGroup = null;
let currentBalance = null;
let currentGroup = null;
let headerAccountMetaEl = null;
const eventsCache = new Map(); // eventId -> event data

const STARTING_BALANCE = 1000;
let isGuest = false;
let guestBalance = STARTING_BALANCE;
const guestPendingBets = []; // local-only; cleared on refresh

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
  currentGroup = null;
}

function clearGroupLeaderboardListener() {
  if (typeof unsubscribeGroupLeaderboard === "function") {
    unsubscribeGroupLeaderboard();
  }
  unsubscribeGroupLeaderboard = null;
  groupLeaderboardGroup = null;
}

async function fetchProfile(uid) {
  if (!uid) return null;
  const snap = await getDoc(doc(db, "profiles", uid));
  if (!snap.exists()) return null;
  return { id: snap.id, ...snap.data() };
}

function updateHeaderMeta() {
  if (!headerAccountMetaEl) return;
  if (currentBalance == null) return;
  const existing = String(headerAccountMetaEl.textContent || "").trim();

  if (isGuest) {
    headerAccountMetaEl.textContent = `balance ${currentBalance} • not saved`;
    return;
  }

  // Only show balance if the header meta is empty or already showing balance.
  // (Don't overwrite "X bets • ledger Δ Y".)
  if (!existing || existing.startsWith("balance")) {
    headerAccountMetaEl.textContent = `balance ${currentBalance}`;
  }
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
  clearGroupLeaderboardListener();
  currentUser = null;
  currentProfile = null;
  currentView = "dashboard";
  isGuest = false;
  guestBalance = STARTING_BALANCE;
  guestPendingBets.length = 0;

  authAreaEl.innerHTML = `
    <div style="display:flex; gap: 8px;">
      <button id="login">Login</button>
      <button id="signupStart">Sign up</button>
      <button id="guestStart" style="opacity:0.9;">Enter as guest</button>
    </div>
  `;

  mainEl.innerHTML = `
    <section style="padding: 16px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
      <h1 style="margin: 0 0 8px 0; font-size: 42px; line-height: 1.1;">Welcome to Bjorgies betting</h1>
      <div style="opacity: 0.85; margin-bottom: 0;">Use the Login / Sign up buttons in the top right to get started.</div>
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
  document.querySelector("#signupStart").onclick = login;
  document.querySelector("#guestStart").onclick = async () => {
    // Ensure Firestore requests are truly unauthenticated in guest mode.
    try {
      await signOut(auth);
    } catch {
      // ignore
    }
    isGuest = true;
    guestBalance = STARTING_BALANCE;
    guestPendingBets.length = 0;
    renderGuest();
  };
}

function renderGuest() {
  clearProfileListeners();
  clearUserDocListener();
  clearGroupLeaderboardListener();
  currentUser = null;
  currentProfile = null;
  currentView = currentView || "dashboard";
  isGuest = true;
  currentBalance = guestBalance;

  authAreaEl.innerHTML = `
    <div style="text-align:right;">
      <div style="font-weight: 650;">Guest</div>
      <div id="accountMeta" style="opacity: 0.8; font-size: 12px;">balance ${guestBalance} • not saved</div>
    </div>
    <button id="exitGuest">Exit</button>
  `;
  headerAccountMetaEl = document.querySelector("#accountMeta");
  document.querySelector("#exitGuest").onclick = () => renderLoggedOut();

  // Guests can browse dashboard/event (reads are public when signed out).
  setView(currentView || "dashboard", { uid: "guest" });
}

function renderSignup(user) {
  clearUpcomingEventsListener();
  clearEventMarketsListener();
  clearProfileListeners();
  clearUserDocListener();
  clearGroupLeaderboardListener();
  currentUser = user;
  currentView = "signup";
  currentProfile = null;

  authAreaEl.innerHTML = `
    <div style="text-align:right;">
      <div style="font-weight: 650;">${user.email || "Signed in"}</div>
      <div style="opacity: 0.75; font-size: 12px;">Complete signup</div>
    </div>
    <button id="logout">Logout</button>
  `;

  document.querySelector("#logout").onclick = async () => {
    await signOut(auth);
  };

  const defaultDisplayName = user.displayName || "";
  const defaultPhoto = user.photoURL || "";

  mainEl.innerHTML = `
    <section style="padding: 16px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
      <h1 style="margin: 0 0 8px 0; font-size: 34px;">Create your profile</h1>
      <div style="opacity: 0.85; margin-bottom: 16px;">Choose how you’ll appear to others before placing bets.</div>
      <form id="signupForm" style="display:flex; flex-direction:column; gap: 16px;">
        <label style="display:flex; flex-direction:column; gap: 6px;">
          <span style="font-weight: 600;">Display name</span>
          <input id="signupDisplayName" type="text" maxlength="40" placeholder="e.g. Bjorg" value="${defaultDisplayName}" style="padding: 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,0.25);" required />
        </label>

        <label style="display:flex; flex-direction:column; gap: 6px;">
          <span style="font-weight: 600;">Group</span>
          <input id="signupGroup" type="text" maxlength="32" placeholder="e.g. boys_trip_2025" style="padding: 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,0.25);" />
          <div style="opacity:0.75; font-size: 12px;">Optional. People with the same group can see a shared leaderboard.</div>
        </label>

        <div id="signupMsg"></div>

        <button id="signupSubmit" type="submit" style="align-self:flex-start;">Create profile</button>
      </form>
    </section>
  `;

  const displayNameInput = document.querySelector("#signupDisplayName");
  const groupInput = document.querySelector("#signupGroup");
  const previewImg = null;
  const previewPlaceholder = null;
  const signupForm = document.querySelector("#signupForm");
  const signupMsgEl = document.querySelector("#signupMsg");
  const submitBtn = document.querySelector("#signupSubmit");
  let activePreviewUrl = "";

  const showPreview = () => {};

  signupForm.onsubmit = async (e) => {
    e.preventDefault();
    signupMsgEl.innerHTML = "";
    const displayName = displayNameInput.value.trim();
    const group = String(groupInput?.value || "").trim();
    if (!displayName) {
      signupMsgEl.innerHTML = `<div style="color:#b00020;">Display name is required.</div>`;
      return;
    }

    submitBtn.disabled = true;
    submitBtn.textContent = "Creating…";

    try {
      const uploadedPhotoUrl = defaultPhoto || "";

      const profileRef = doc(db, "profiles", user.uid);
      await setDoc(profileRef, {
        displayName,
        email: user.email || null,
        photoURL: uploadedPhotoUrl || null,
        createdAt: serverTimestamp(),
        updatedAt: serverTimestamp(),
      });

      try {
        await updateProfile(user, {
          displayName,
          photoURL: uploadedPhotoUrl || null,
        });
      } catch (err) {
        console.warn("Failed to update auth profile", err);
      }

      const ensureUserFn = httpsCallable(fns, "ensureUser");
      await ensureUserFn();

      if (group) {
        const setGroup = httpsCallable(fns, "setGroup");
        await setGroup({ group });
      }

      currentProfile = {
        displayName,
        email: user.email || null,
        photoURL: uploadedPhotoUrl || null,
      };
      currentView = "dashboard";

      signupMsgEl.innerHTML = `<div style="color:#0a7a2f;">Profile created. Redirecting…</div>`;
      setTimeout(() => {
        renderAwaitingApproval(user, currentProfile);
      }, 300);
    } catch (err) {
      console.error(err);
      signupMsgEl.innerHTML = `<div style="color:#b00020;">${err?.code || "error"}: ${err?.message || String(err)}</div>`;
    } finally {
      submitBtn.disabled = false;
      submitBtn.textContent = "Create profile";
    }
  };
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
  clearGroupLeaderboardListener();
  const profileName = currentProfile?.displayName || user.displayName || user.email || "Your profile";
  const profileEmail = currentProfile?.email || user.email || "";
  const profilePhoto = currentProfile?.photoURL || user.photoURL || "";
  const fallbackInitial = profileName?.charAt?.(0)?.toUpperCase?.() || "?";
  const avatarInner = profilePhoto
    ? `<img src="${profilePhoto}" alt="${profileName}" style="width:100%; height:100%; object-fit:cover;" />`
    : `<div style="font-size:24px; font-weight:700; color:#213547;">${fallbackInitial}</div>`;

  mainEl.innerHTML = `
    <section style="padding: 16px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
      <div style="display:flex; align-items:flex-end; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
        <div>
          <div style="font-size: 18px; font-weight: 750;">Profile</div>
          <div style="opacity: 0.8; margin-top: 4px;">Balance and pending bets.</div>
        </div>
        <button id="backToEvents">Back to events</button>
      </div>

      <div style="margin-top: 16px; display:flex; align-items:center; gap: 14px; padding: 12px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
        <div style="width: 72px; height: 72px; border-radius: 20px; background: rgba(127,127,127,0.15); display:flex; align-items:center; justify-content:center; overflow:hidden;">
          ${avatarInner}
        </div>
        <div>
          <div style="font-size: 20px; font-weight: 750;">${profileName}</div>
          ${profileEmail ? `<div style="opacity:0.75;">${profileEmail}</div>` : ""}
        </div>
      </div>

      <div style="margin-top: 16px; padding: 14px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
        <div style="opacity: 0.8; font-size: 12px;">Balance</div>
        <div id="balanceVal" style="font-size: 36px; font-weight: 850; letter-spacing: -0.02em; margin-top: 4px;">-</div>
      </div>

      <div style="margin-top: 16px; padding: 14px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
        <div style="display:flex; align-items:flex-end; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
          <div>
            <div style="font-size: 16px; font-weight: 750;">Group</div>
            <div id="groupHint" style="opacity: 0.8; margin-top: 4px; font-size: 12px;">Set a group to see your group leaderboard.</div>
          </div>
        </div>
        <div style="margin-top: 10px; display:flex; gap: 10px; flex-wrap: wrap; align-items:center;">
          <input id="groupInput" type="text" maxlength="32" placeholder="e.g. boys_trip_2025" style="padding: 10px; border-radius: 10px; border: 1px solid rgba(127,127,127,0.25); width: 260px;" />
          <button id="saveGroup">Save group</button>
          <button id="clearGroup" style="opacity:0.9;">Clear</button>
        </div>
        <div id="groupMsg" style="margin-top: 10px;"></div>
      </div>

      <div style="margin-top: 16px;">
        <div style="display:flex; align-items:flex-end; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
          <div style="font-size: 16px; font-weight: 750;">Group leaderboard</div>
          <div id="groupLbStatus" style="opacity: 0.8;"></div>
        </div>
        <div id="groupLbList" style="margin-top: 12px; display:flex; flex-direction:column; gap: 10px;"></div>
      </div>

      <div style="margin-top: 16px;">
        <div style="display:flex; align-items:flex-end; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
          <div style="font-size: 16px; font-weight: 750;">Pending bets</div>
          <div id="pendingStatus" style="opacity: 0.8;"></div>
        </div>
        <div id="pendingList" style="margin-top: 12px; display:flex; flex-direction:column; gap: 12px;"></div>
      </div>

      <div id="adminPanel" style="margin-top: 16px; padding: 14px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px; display:none;">
        <div style="display:flex; align-items:flex-end; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
          <div>
            <div style="font-size: 16px; font-weight: 850;">Admin: pending approvals</div>
            <div style="opacity: 0.8; margin-top: 4px; font-size: 12px;">Approve new signups so they can use the app.</div>
          </div>
          <button id="refreshPending">Refresh</button>
        </div>
        <div id="pendingApprovalsStatus" style="opacity:0.8; margin-top: 10px;"></div>
        <div id="pendingApprovalsList" style="margin-top: 12px; display:flex; flex-direction:column; gap: 10px;"></div>
      </div>
    </section>
  `;

  document.querySelector("#backToEvents").onclick = () => setView("dashboard", user);

  const balanceValEl = document.querySelector("#balanceVal");
  const groupHintEl = document.querySelector("#groupHint");
  const groupInputEl = document.querySelector("#groupInput");
  const groupMsgEl = document.querySelector("#groupMsg");
  const groupLbStatusEl = document.querySelector("#groupLbStatus");
  const groupLbListEl = document.querySelector("#groupLbList");
  const pendingStatusEl = document.querySelector("#pendingStatus");
  const pendingListEl = document.querySelector("#pendingList");
  const adminPanelEl = document.querySelector("#adminPanel");
  const pendingApprovalsStatusEl = document.querySelector("#pendingApprovalsStatus");
  const pendingApprovalsListEl = document.querySelector("#pendingApprovalsList");

  pendingStatusEl.textContent = "Loading…";
  groupLbStatusEl.textContent = "";
  groupLbListEl.innerHTML = `<div style="opacity:0.8; padding: 12px 0;">Set a group to see your leaderboard.</div>`;

  const loadPendingApprovals = async () => {
    pendingApprovalsStatusEl.textContent = "Loading…";
    pendingApprovalsListEl.innerHTML = "";
    try {
      const listPendingUsers = httpsCallable(fns, "listPendingUsers");
      const res = await listPendingUsers();
      const users = Array.isArray(res.data?.users) ? res.data.users : [];
      pendingApprovalsStatusEl.textContent = `${users.length} pending`;

      if (users.length === 0) {
        pendingApprovalsListEl.innerHTML = `<div style="opacity:0.8; padding: 10px 0;">No pending approvals.</div>`;
        return;
      }

      const html = users.map((u) => {
        const uid = String(u.uid || "");
        const name = String(u.displayName || "").trim() || String(u.email || "").trim() || uid;
        const group = String(u.group || "").trim();
        return `
          <article data-pending-uid="${uid}" style="padding: 10px 12px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
            <div style="display:flex; justify-content:space-between; gap: 12px; flex-wrap: wrap; align-items:center;">
              <div>
                <div style="font-weight: 750;">${name}</div>
                <div style="opacity:0.8; font-size: 12px;">uid: ${uid}${group ? ` • group: ${group}` : ""}</div>
              </div>
              <button data-approve-btn="1" data-uid="${uid}">Approve</button>
            </div>
          </article>
        `;
      });
      pendingApprovalsListEl.innerHTML = html.join("");
    } catch (err) {
      console.error(err);
      pendingApprovalsStatusEl.textContent = "Failed to load";
      pendingApprovalsListEl.innerHTML = `<div style="color:#b00020; padding: 10px 0;">${err?.code || "error"}: ${
        err?.message || String(err)
      }</div>`;
    }
  };

  document.querySelector("#refreshPending").onclick = loadPendingApprovals;
  pendingApprovalsListEl.onclick = async (e) => {
    const btn = e.target?.closest?.("[data-approve-btn]");
    if (!btn) return;
    const uid = btn.getAttribute("data-uid");
    if (!uid) return;
    btn.disabled = true;
    btn.textContent = "Approving…";
    try {
      const approveUser = httpsCallable(fns, "approveUser");
      await approveUser({ uid });
      await loadPendingApprovals();
    } catch (err) {
      console.error(err);
      pendingApprovalsStatusEl.textContent = `${err?.code || "error"}: ${err?.message || String(err)}`;
    } finally {
      btn.disabled = false;
      btn.textContent = "Approve";
    }
  };

  const startGroupLeaderboard = (group) => {
    groupMsgEl.innerHTML = "";
    if (!group) {
      clearGroupLeaderboardListener();
      groupHintEl.textContent = "Set a group to see your group leaderboard.";
      groupLbStatusEl.textContent = "";
      groupLbListEl.innerHTML = `<div style="opacity:0.8; padding: 12px 0;">Set a group to see your leaderboard.</div>`;
      return;
    }

    groupHintEl.textContent = `Group: ${group}`;
    if (groupLeaderboardGroup === group && typeof unsubscribeGroupLeaderboard === "function") {
      return;
    }

    clearGroupLeaderboardListener();
    groupLeaderboardGroup = group;
    groupLbStatusEl.textContent = "Loading…";
    groupLbListEl.innerHTML = "";

    const q = query(collection(db, "users"), where("group", "==", group));
    unsubscribeGroupLeaderboard = onSnapshot(
      q,
      (snap) => {
        const rows = snap.docs.map((d) => ({ uid: d.id, ...(d.data() || {}) }));
        rows.sort((a, b) => Number(b.balance || 0) - Number(a.balance || 0));

        groupLbStatusEl.textContent = `${rows.length} member${rows.length === 1 ? "" : "s"}`;

        if (rows.length === 0) {
          groupLbListEl.innerHTML = `<div style="opacity:0.8; padding: 12px 0;">No one is in this group yet.</div>`;
          return;
        }

        const html = rows.map((u, idx) => {
          const bal = Number(u.balance);
          const balance = Number.isFinite(bal) ? bal : 0;
          const profit = balance - STARTING_BALANCE;
          const name =
            String(u.displayName || "").trim() ||
            String(u.email || "").trim() ||
            `${String(u.uid || "").slice(0, 6)}…`;
          const isMe = u.uid === user.uid;
          return `
            <article style="padding: 10px 12px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px; ${
              isMe ? "background: rgba(70, 130, 180, 0.10);" : ""
            }">
              <div style="display:flex; justify-content:space-between; gap: 12px; flex-wrap: wrap;">
                <div style="font-weight: 750;">#${idx + 1} ${name}${isMe ? " (you)" : ""}</div>
                <div style="opacity:0.9;">Profit: <strong>${profit}</strong> • Balance: ${balance}</div>
              </div>
            </article>
          `;
        });

        groupLbListEl.innerHTML = html.join("");
      },
      (err) => {
        console.error(err);
        groupLbStatusEl.textContent = "Failed to load";
        groupLbListEl.innerHTML = `<div style="color:#b00020; padding: 12px 0;">${err?.code || "error"}: ${
          err?.message || String(err)
        }</div>`;
      }
    );
  };

  unsubscribeAccount = onSnapshot(
    doc(db, "users", user.uid),
    (snap) => {
      const bal = snap.data()?.balance;
      const b = Number(bal);
      balanceValEl.textContent = Number.isFinite(b) ? String(b) : "-";

      const g = snap.data()?.group;
      currentGroup = typeof g === "string" && g ? g : null;
      if (groupInputEl) groupInputEl.value = currentGroup || "";
      startGroupLeaderboard(currentGroup);

      const role = String(snap.data()?.role || "user");
      if (role === "admin") {
        adminPanelEl.style.display = "block";
        if (!pendingApprovalsListEl.innerHTML) {
          loadPendingApprovals();
        }
      } else {
        adminPanelEl.style.display = "none";
      }
    },
    (err) => {
      console.error(err);
      balanceValEl.textContent = "-";
    }
  );

  document.querySelector("#saveGroup").onclick = async () => {
    groupMsgEl.innerHTML = "";
    const group = String(groupInputEl?.value || "").trim();
    try {
      const setGroup = httpsCallable(fns, "setGroup");
      await setGroup({ group });
      groupMsgEl.innerHTML = `<div style="color:#0a7a2f;">Saved.</div>`;
    } catch (err) {
      console.error(err);
      groupMsgEl.innerHTML = `<div style="color:#b00020;">${err?.code || "error"}: ${err?.message || String(
        err
      )}</div>`;
    }
  };

  document.querySelector("#clearGroup").onclick = async () => {
    groupMsgEl.innerHTML = "";
    try {
      const setGroup = httpsCallable(fns, "setGroup");
      await setGroup({ group: "" });
      if (groupInputEl) groupInputEl.value = "";
      groupMsgEl.innerHTML = `<div style="color:#0a7a2f;">Cleared.</div>`;
    } catch (err) {
      console.error(err);
      groupMsgEl.innerHTML = `<div style="color:#b00020;">${err?.code || "error"}: ${err?.message || String(
        err
      )}</div>`;
    }
  };

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
      if (isGuest) {
        if (!Number.isInteger(guestBalance)) guestBalance = STARTING_BALANCE;
        if (stake > guestBalance) throw new Error("Stake exceeds your balance.");
        guestBalance -= stake;
        currentBalance = guestBalance;
        updateHeaderMeta();
        eventBalanceValEl.textContent = String(guestBalance);
        guestPendingBets.push({
          marketId,
          option,
          stake,
          createdAt: new Date().toISOString(),
        });
        betMsgEl.innerHTML = `<div style="color:#0a7a2f;">Guest bet placed (not saved). Balance updated locally.</div>`;
      } else {
        const placeBet = httpsCallable(fns, "placeBet");
        const res = await placeBet({ marketId, option, stake });
        betMsgEl.innerHTML = `<div style="color:#0a7a2f;">Bet placed (${res.data?.betId || "ok"}). Balance will update.</div>`;
      }
    } catch (err) {
      console.error(err);
      betMsgEl.innerHTML = `<div style="color:#b00020;">${err?.code || "error"}: ${err?.message || String(err)}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "Bet";
    }
  };
}

async function renderLoggedIn(user, profile) {
  clearUpcomingEventsListener();
  clearProfileListeners();
  clearGroupLeaderboardListener();
  currentUser = user;
  currentProfile = profile || null;

  const profileName = currentProfile?.displayName || user.displayName || user.email || "Signed in";
  authAreaEl.innerHTML = `
    <div style="display:flex; flex-direction:column; align-items:flex-end; gap: 2px;">
      <button id="profileLink" style="all: unset; cursor: pointer; font-weight: 650; text-align: right;">
        ${profileName}
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
    if (currentProfile) {
      const profileRef = doc(db, "profiles", user.uid);
      await setDoc(
        profileRef,
        {
          email: user.email || null,
          updatedAt: serverTimestamp(),
        },
        { merge: true }
      );
    }

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
      const g = snap.data()?.group;
      currentGroup = typeof g === "string" && g ? g : null;
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

function renderAwaitingApproval(user, profile) {
  clearUpcomingEventsListener();
  clearEventMarketsListener();
  clearProfileListeners();
  clearUserDocListener();
  clearGroupLeaderboardListener();
  currentUser = user;
  currentProfile = profile || null;
  currentView = "awaitingApproval";

  const profileName = currentProfile?.displayName || user.displayName || user.email || "Signed in";
  authAreaEl.innerHTML = `
    <div style="text-align:right;">
      <div style="font-weight: 650;">${profileName}</div>
      <div style="opacity: 0.75; font-size: 12px;">Awaiting approval</div>
    </div>
    <button id="logout">Logout</button>
  `;
  document.querySelector("#logout").onclick = async () => {
    await signOut(auth);
  };

  mainEl.innerHTML = `
    <section style="padding: 16px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
      <h1 style="margin: 0 0 10px 0; font-size: 34px;">Awaiting admin approval</h1>
      <div style="opacity: 0.85; margin-bottom: 14px;">
        Your profile was created, but an admin must approve your account before you can view events or place bets.
      </div>
      <div id="approvalMsg" style="margin-top: 12px;"></div>
      <div style="display:flex; gap: 10px; flex-wrap: wrap; margin-top: 12px;">
        <button id="checkApproval">Check approval status</button>
        <button id="logout2">Logout</button>
      </div>
    </section>
  `;

  document.querySelector("#logout2").onclick = async () => {
    await signOut(auth);
  };

  const msgEl = document.querySelector("#approvalMsg");
  document.querySelector("#checkApproval").onclick = async () => {
    msgEl.textContent = "Checking…";
    try {
      const ensureUser = httpsCallable(fns, "ensureUser");
      const res = await ensureUser();
      const approved = Boolean(res.data?.approved);
      if (!approved) {
        msgEl.innerHTML = `<div style="opacity:0.85;">Still pending. Please try again later.</div>`;
        return;
      }

      const refreshedProfile = await fetchProfile(user.uid);
      renderLoggedIn(user, refreshedProfile || profile || null);
    } catch (err) {
      console.error(err);
      msgEl.innerHTML = `<div style="color:#b00020;">${err?.code || "error"}: ${err?.message || String(err)}</div>`;
    }
  };
}

onAuthStateChanged(auth, async (user) => {
  if (!user) {
    if (isGuest) return renderGuest();
    return renderLoggedOut();
  }

  currentUser = user;
  currentProfile = null;

  authAreaEl.innerHTML = `
    <div style="text-align:right;">
      <div style="font-weight: 650;">Loading account…</div>
      <div style="opacity: 0.75; font-size: 12px;">${user.email || ""}</div>
    </div>
    <button id="logout">Logout</button>
  `;
  document.querySelector("#logout").onclick = async () => {
    await signOut(auth);
  };

  mainEl.innerHTML = `
    <section style="padding: 16px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
      <div>Loading your account…</div>
    </section>
  `;

  try {
    const profile = await fetchProfile(user.uid);
    if (!profile) {
      renderSignup(user);
      return;
    }

    const ensureUser = httpsCallable(fns, "ensureUser");
    const res = await ensureUser();
    const approved = Boolean(res.data?.approved);
    if (!approved) {
      renderAwaitingApproval(user, profile);
      return;
    }

    renderLoggedIn(user, profile);
  } catch (err) {
    console.error(err);
    mainEl.innerHTML = `
      <section style="padding: 16px; border: 1px solid rgba(127,127,127,0.25); border-radius: 12px;">
        <div style="color:#b00020;">Failed to load your profile. Please refresh or logout.</div>
      </section>
    `;
  }
});

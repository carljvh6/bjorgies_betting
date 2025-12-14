import "./style.css";
import { db, auth, provider, fns } from "./firebase";
import { signInWithPopup, signOut, onAuthStateChanged } from "firebase/auth";
import { collection, doc, getDoc, getDocs, query, setDoc, serverTimestamp, Timestamp, where } from "firebase/firestore";
import { httpsCallable } from "firebase/functions";


let currentUser = null;

document.querySelector("#app").innerHTML = `
  <div style="font-family: system-ui; max-width: 720px; margin: 40px auto;">
    <h1>Sports Bets (learning)</h1>
    <div style="display:flex; gap:12px; margin: 16px 0;">
      <button id="login">Sign in with Google</button>
      <button id="logout">Sign out</button>
    </div>
    <pre id="state" style="background:#111; color:#ddd; padding:12px; border-radius:12px;"></pre>

    <div id="accountPanel" style="margin-top:16px; padding:12px; border:1px solid #ddd; border-radius:12px;">
      <div style="font-weight:600; margin-bottom:8px;">Account</div>
      <div><strong>User:</strong> <span id="ap_name">-</span></div>
      <div><strong>Bets:</strong> <span id="ap_bets">-</span></div>
      <div><strong>Ledger amount:</strong> <span id="ap_ledger">-</span></div>
    </div>
  </div>
  <button id="seed">Seed test event + market</button>
  <button id="placeBet">Place bet via function</button>
  <button id="settle">Settle market (Arsenal wins)</button>


`;

const stateEl = document.querySelector("#state");
const apNameEl = document.querySelector("#ap_name");
const apBetsEl = document.querySelector("#ap_bets");
const apLedgerEl = document.querySelector("#ap_ledger");

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

  apBetsEl.textContent = String(betsSnap.size);
  apLedgerEl.textContent = String(ledgerDeltaTotal);
}

document.querySelector("#login").onclick = async () => {
  try {
    await signInWithPopup(auth, provider);
  } catch (e) {
    console.error(e);
    stateEl.textContent = `${e.code || "error"}: ${e.message || e}`;
  }
};


document.querySelector("#logout").onclick = async () => {
  await signOut(auth);
};

onAuthStateChanged(auth, async (user) => {
  currentUser = user || null;

  if (!user) {
    stateEl.textContent = "Not signed in";
    apNameEl.textContent = "-";
    apBetsEl.textContent = "-";
    apLedgerEl.textContent = "-";
    return;
  }

  try {
    // Client-owned profile (safe to write from client).
    const profileRef = doc(db, "profiles", user.uid);
    await setDoc(profileRef, {
      displayName: user.displayName,
      email: user.email,
      photoURL: user.photoURL,
      updatedAt: serverTimestamp(),
    }, { merge: true });

    const ensureUser = httpsCallable(fns, "ensureUser");
    const r = await ensureUser();

    const profileSnap = await getDoc(profileRef);
    apNameEl.textContent = profileSnap.data()?.displayName || user.displayName || user.email || user.uid;
    await refreshAccountPanel(user.uid);

    const u = await getDoc(doc(db, "users", user.uid));

    stateEl.textContent = JSON.stringify({
      balance: r.data?.balance,
      userDoc: u.data(),
    }, null, 2);
  } catch (e) {
    console.error(e);
    stateEl.textContent = `${e.code || "error"}\n${e.message || e}`;
  }
});


document.querySelector("#seed").onclick = async () => {
  if (!currentUser) { stateEl.textContent = "Sign in first"; return; }

  try {
    await setDoc(doc(db, "events", "testEvent1"), {
      sport: "soccer",
      name: "Arsenal vs Spurs",
      startTime: Timestamp.fromDate(new Date("2025-12-21T17:00:00+02:00")),
      status: "scheduled",
      createdAt: serverTimestamp(),
      createdBy: currentUser.uid,
    }, { merge: true });

    await setDoc(doc(db, "markets", "testMarket1"), {
      eventId: "testEvent1",
      question: "Who wins?",
      options: ["Arsenal", "Draw", "Spurs"],
      closesAt: Timestamp.fromDate(new Date("2025-12-21T16:55:00+02:00")),
      status: "open",
      winningOption: null,
      settledAt: null,
      createdAt: serverTimestamp(),
      createdBy: currentUser.uid,
    }, { merge: true });

    stateEl.textContent = "Seeded events/testEvent1 and markets/testMarket1";
  } catch (e) {
    console.error(e);
    stateEl.textContent = `${e.code}\n${e.message}`;
  }
};

document.querySelector("#placeBet").onclick = async () => {
  if (!currentUser) { stateEl.textContent = "Sign in first"; return; }
  try {
    const placeBet = httpsCallable(fns, "placeBet");
    const res = await placeBet({ marketId: "testMarket1", option: "Arsenal", stake: 10 });
    stateEl.textContent = `Bet placed via function: ${res.data.betId}`;
    await refreshAccountPanel(currentUser.uid);
  } catch (e) {
    console.error(e);
    stateEl.textContent = `${e.code || "error"}\n${e.message || e}`;
  }
};

document.querySelector("#settle").onclick = async () => {
  if (!currentUser) { stateEl.textContent = "Sign in first"; return; }
  try {
    const settle = httpsCallable(fns, "settleMarket");
    await settle({ marketId: "testMarket1", winningOption: "Arsenal" });
    stateEl.textContent = "Market settled";
    await refreshAccountPanel(currentUser.uid);
  } catch (e) {
    console.error(e);
    stateEl.textContent = `${e.code || "error"}\n${e.message || e}`;
  }
};

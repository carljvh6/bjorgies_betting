const { setGlobalOptions } = require("firebase-functions/v2");
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const { FieldValue } = require("firebase-admin/firestore");

admin.initializeApp();
const db = admin.firestore();

setGlobalOptions({ region: "us-central1" });

async function requireAdmin(tx, uid) {
  const userRef = db.collection("users").doc(uid);
  const snap = await tx.get(userRef);
  if (!snap.exists || snap.data()?.role !== "admin") {
    throw new HttpsError("permission-denied", "Admin access required");
  }
}

exports.ensureUser = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Sign in required");

  const userRef = db.collection("users").doc(uid);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(userRef);
    if (!snap.exists) {
      tx.set(userRef, {
        balance: 1000,
        role: "user",
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      });
    } else {
      tx.update(userRef, { updatedAt: FieldValue.serverTimestamp() });
    }
  });

  const snap = await userRef.get();
  return { balance: snap.data()?.balance };
});

exports.placeBet = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Sign in required");

  const { marketId, option, stake } = request.data || {};
  if (typeof marketId !== "string" || !marketId) throw new HttpsError("invalid-argument", "marketId required");
  if (typeof option !== "string" || !option) throw new HttpsError("invalid-argument", "option required");

  const stakeNum = Number(stake);
  if (!Number.isInteger(stakeNum) || stakeNum <= 0 || stakeNum > 1000) {
    throw new HttpsError("invalid-argument", "stake must be int 1..1000");
  }

  // Deterministic bet id: one bet per user per market.
  const betId = `${uid}_${marketId}`;
  const betRef = db.collection("bets").doc(betId);
  const userRef = db.collection("users").doc(uid);
  const marketRef = db.collection("markets").doc(marketId);
  const ledgerRef = userRef.collection("ledger").doc(); // subcollection under users/{uid}

  await db.runTransaction(async (tx) => {
    const [existingBet, userSnap, marketSnapTx] = await Promise.all([
      tx.get(betRef),
      tx.get(userRef),
      tx.get(marketRef),
    ]);

    if (existingBet.exists) throw new HttpsError("already-exists", "Bet already placed for this market");
    if (!marketSnapTx.exists) throw new HttpsError("not-found", "Market not found");
    if (!userSnap.exists) throw new HttpsError("failed-precondition", "User not initialized (call ensureUser)");

    const marketTx = marketSnapTx.data();
    if (marketTx.status !== "open") throw new HttpsError("failed-precondition", "Market not open");
    const closesAtTx = marketTx.closesAt?.toDate?.();
    if (!closesAtTx) throw new HttpsError("failed-precondition", "Market missing closesAt");
    if (new Date() >= closesAtTx) throw new HttpsError("failed-precondition", "Market closed");

    const options = marketTx.options || [];
    if (!Array.isArray(options) || !options.includes(option)) {
      throw new HttpsError("invalid-argument", "Invalid option");
    }

    const bal = userSnap.data().balance ?? 0;
    if (!Number.isInteger(bal)) throw new HttpsError("failed-precondition", "Invalid balance");
    if (bal < stakeNum) throw new HttpsError("failed-precondition", "Insufficient balance");

    tx.update(userRef, { balance: bal - stakeNum, updatedAt: FieldValue.serverTimestamp() });

    tx.set(ledgerRef, {
      type: "bet_placed",
      marketId,
      betId,
      delta: -stakeNum,
      balanceBefore: bal,
      balanceAfter: bal - stakeNum,
      createdAt: FieldValue.serverTimestamp(),
    });

    tx.set(betRef, {
      uid,
      marketId,
      option,
      stake: stakeNum,
      createdAt: FieldValue.serverTimestamp(),
      status: "placed",
    });
  });

  return { betId };
});

exports.settleMarket = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Sign in required");

  const { marketId, winningOption } = request.data || {};
  if (!marketId || !winningOption) {
    throw new HttpsError("invalid-argument", "marketId and winningOption required");
  }
  if (typeof marketId !== "string" || typeof winningOption !== "string") {
    throw new HttpsError("invalid-argument", "marketId and winningOption must be strings");
  }

  const marketRef = db.collection("markets").doc(marketId);

  await db.runTransaction(async (tx) => {
    await requireAdmin(tx, uid);

    const marketSnap = await tx.get(marketRef);
    if (!marketSnap.exists) throw new HttpsError("not-found", "Market not found");

    const market = marketSnap.data();
    if (market.status === "settled") throw new HttpsError("failed-precondition", "Market already settled");

    const betsQuery = db.collection("bets").where("marketId", "==", marketId);
    const betsSnap = await tx.get(betsQuery);
    if (betsSnap.empty) throw new HttpsError("failed-precondition", "No bets for market");

    const bets = betsSnap.docs.map((d) => ({ id: d.id, ...d.data() }));

    // Winner-takes-pool settlement: pool is sum of stakes.
    const pool = bets.reduce((s, b) => s + (Number(b.stake) || 0), 0);
    if (!Number.isInteger(pool) || pool <= 0) throw new HttpsError("failed-precondition", "Invalid pool");

    const winners = bets.filter((b) => b.option === winningOption);
    const losers = bets.filter((b) => b.option !== winningOption);

    const winningStakeTotal = winners.reduce((s, b) => s + (Number(b.stake) || 0), 0);
    if (!Number.isInteger(winningStakeTotal) || winningStakeTotal <= 0) {
      throw new HttpsError("failed-precondition", "No winning bets");
    }

    // Deterministic order for remainder distribution.
    winners.sort((a, b) => String(a.id).localeCompare(String(b.id)));

    // Compute floor payouts (integer math to avoid float drift).
    const payoutByBetId = new Map();
    let distributed = 0;
    for (const bet of winners) {
      const stake = Number(bet.stake) || 0;
      if (!Number.isInteger(stake) || stake <= 0) {
        throw new HttpsError("failed-precondition", "Invalid stake on bet");
      }
      const payout = Math.floor((stake * pool) / winningStakeTotal);
      payoutByBetId.set(bet.id, payout);
      distributed += payout;
    }

    // Deterministically distribute remainder (+1) across winners by betId order.
    let remainder = pool - distributed;
    for (let i = 0; remainder > 0 && winners.length > 0; i = (i + 1) % winners.length) {
      const betId = winners[i].id;
      payoutByBetId.set(betId, (payoutByBetId.get(betId) || 0) + 1);
      remainder -= 1;
    }

    // Apply updates.
    for (const bet of winners) {
      const payout = payoutByBetId.get(bet.id) || 0;
      const userRef = db.collection("users").doc(bet.uid);
      const ledgerRef = userRef.collection("ledger").doc();

      const userSnap = await tx.get(userRef);
      if (!userSnap.exists) throw new HttpsError("failed-precondition", "User not initialized");
      const bal = userSnap.data()?.balance ?? 0;
      if (!Number.isInteger(bal)) throw new HttpsError("failed-precondition", "Invalid balance");

      tx.update(userRef, {
        balance: bal + payout,
        updatedAt: FieldValue.serverTimestamp(),
      });

      tx.set(ledgerRef, {
        type: "payout",
        marketId,
        betId: bet.id,
        delta: payout,
        balanceBefore: bal,
        balanceAfter: bal + payout,
        createdAt: FieldValue.serverTimestamp(),
      });

      tx.update(db.collection("bets").doc(bet.id), {
        status: "settled",
        result: "win",
        payout,
      });
    }

    for (const bet of losers) {
      tx.update(db.collection("bets").doc(bet.id), {
        status: "settled",
        result: "loss",
        payout: 0,
      });
    }

    tx.update(marketRef, {
      status: "settled",
      winningOption,
      settledAt: FieldValue.serverTimestamp(),
    });
  });

  return { ok: true };
});

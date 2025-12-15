const { setGlobalOptions } = require("firebase-functions/v2");
const { onCall, HttpsError } = require("firebase-functions/v2/https");
const admin = require("firebase-admin");
const { FieldValue } = require("firebase-admin/firestore");
const { randomUUID } = require("crypto");

function buildAppConfig() {
  try {
    const cfg = JSON.parse(process.env.FIREBASE_CONFIG || "{}");
    const appConfig = {};
    if (cfg.projectId) appConfig.projectId = cfg.projectId;
    if (cfg.storageBucket) appConfig.storageBucket = cfg.storageBucket;
    return appConfig;
  } catch (err) {
    console.warn("Failed to parse FIREBASE_CONFIG", err);
    return {};
  }
}

admin.initializeApp(buildAppConfig());
const db = admin.firestore();

setGlobalOptions({ region: "us-central1" });

const STARTING_BALANCE = 1000;

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

  const authToken = request.auth?.token || {};
  const authName = typeof authToken.name === "string" ? authToken.name : null;
  const authEmail = typeof authToken.email === "string" ? authToken.email : null;
  const authPicture = typeof authToken.picture === "string" ? authToken.picture : null;

  const userRef = db.collection("users").doc(uid);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(userRef);
    if (!snap.exists) {
      tx.set(userRef, {
        balance: STARTING_BALANCE,
        role: "user",
        approved: false,
        approvedAt: null,
        approvedBy: null,
        group: null,
        displayName: authName,
        email: authEmail,
        photoURL: authPicture,
        createdAt: FieldValue.serverTimestamp(),
        updatedAt: FieldValue.serverTimestamp(),
      });
    } else {
      const patch = {
        updatedAt: FieldValue.serverTimestamp(),
      };
      if (authName) patch.displayName = authName;
      if (authEmail) patch.email = authEmail;
      if (authPicture) patch.photoURL = authPicture;
      tx.set(userRef, patch, { merge: true });
    }
  });

  const snap = await userRef.get();
  return {
    balance: snap.data()?.balance,
    group: snap.data()?.group ?? null,
    approved: Boolean(snap.data()?.approved),
    role: snap.data()?.role || "user",
  };
});

exports.setGroup = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Sign in required");

  const raw = request.data?.group;
  const group = typeof raw === "string" ? raw.trim() : "";

  // Allow clearing group with empty string.
  if (group) {
    if (group.length > 32) throw new HttpsError("invalid-argument", "group too long (max 32)");
    if (!/^[a-zA-Z0-9 _-]+$/.test(group)) {
      throw new HttpsError("invalid-argument", "group contains invalid characters");
    }
  }

  const userRef = db.collection("users").doc(uid);
  await db.runTransaction(async (tx) => {
    const snap = await tx.get(userRef);
    if (!snap.exists) throw new HttpsError("failed-precondition", "User not initialized (call ensureUser)");
    tx.set(
      userRef,
      {
        group: group || null,
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
  });

  return { group: group || null };
});

exports.listPendingUsers = onCall(async (request) => {
  try {
    const uid = request.auth?.uid;
    if (!uid) throw new HttpsError("unauthenticated", "Sign in required");

    // Admin check (server-side; not governed by Firestore rules).
    await db.runTransaction(async (tx) => {
      await requireAdmin(tx, uid);
    });

    // Avoid requiring a composite index by NOT ordering in Firestore.
    // We'll sort client-side using createdAt (if present).
    const snap = await db.collection("users").where("approved", "==", false).limit(200).get();

    const users = snap.docs
      .map((d) => {
        const data = d.data() || {};
        return {
          uid: d.id,
          displayName: data.displayName || null,
          email: data.email || null,
          createdAt: data.createdAt || null,
          group: data.group || null,
        };
      })
      .sort((a, b) => {
        const at = a.createdAt?.toDate?.()?.getTime?.() ?? 0;
        const bt = b.createdAt?.toDate?.()?.getTime?.() ?? 0;
        return at - bt;
      })
      .slice(0, 100);

    return { users };
  } catch (err) {
    console.error("listPendingUsers error", err);
    if (err instanceof HttpsError) throw err;
    throw new HttpsError("internal", err?.message || "Failed to list pending users");
  }
});

exports.approveUser = onCall(async (request) => {
  const uid = request.auth?.uid;
  if (!uid) throw new HttpsError("unauthenticated", "Sign in required");

  const targetUid = String(request.data?.uid || "").trim();
  if (!targetUid) throw new HttpsError("invalid-argument", "uid required");

  const targetUserRef = db.collection("users").doc(targetUid);
  const targetProfileRef = db.collection("profiles").doc(targetUid);

  await db.runTransaction(async (tx) => {
    await requireAdmin(tx, uid);

    const targetSnap = await tx.get(targetUserRef);
    if (!targetSnap.exists) throw new HttpsError("not-found", "Target user not found");

    tx.set(
      targetUserRef,
      {
        approved: true,
        approvedAt: FieldValue.serverTimestamp(),
        approvedBy: uid,
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true }
    );

    // Optional: mark profile as approved too (client can’t write this field).
    tx.set(
      targetProfileRef,
      {
        approved: true,
        approvedAt: FieldValue.serverTimestamp(),
        approvedBy: uid,
        updatedAt: FieldValue.serverTimestamp(),
      },
      { merge: true }
    );
  });

  return { ok: true };
});

exports.uploadProfilePhoto = onCall(async (request) => {
  try {
    const uid = request.auth?.uid;
    if (!uid) throw new HttpsError("unauthenticated", "Sign in required");

    const { imageData, contentType } = request.data || {};
    if (typeof imageData !== "string" || !imageData) {
    throw new HttpsError("invalid-argument", "imageData (base64) required");
  }
  const safeContentType =
    typeof contentType === "string" && contentType.startsWith("image/") ? contentType : "image/jpeg";

  let buffer;
  try {
    buffer = Buffer.from(imageData, "base64");
  } catch {
    throw new HttpsError("invalid-argument", "imageData must be valid base64");
  }

  if (buffer.length === 0) throw new HttpsError("invalid-argument", "Image is empty");
  if (buffer.length > 2 * 1024 * 1024) {
    throw new HttpsError("invalid-argument", "Image exceeds 2MB limit");
  }

    const appBucket =
      admin.app().options?.storageBucket ||
      process.env.FIREBASE_STORAGE_BUCKET ||
      (process.env.GCLOUD_PROJECT ? `${process.env.GCLOUD_PROJECT}.appspot.com` : null);
    if (!appBucket) throw new HttpsError("failed-precondition", "Storage bucket not configured");

    const bucket = admin.storage().bucket(appBucket);
    const ext = safeContentType.split("/")[1] || "jpg";
    const filePath = `profiles/${uid}/avatar_${Date.now()}_${randomUUID().slice(0, 8)}.${ext}`;
    const downloadToken = randomUUID();

    await bucket.file(filePath).save(buffer, {
    metadata: {
      contentType: safeContentType,
      metadata: {
        firebaseStorageDownloadTokens: downloadToken,
      },
    },
  });

    const photoURL = `https://firebasestorage.googleapis.com/v0/b/${bucket.name}/o/${encodeURIComponent(
      filePath
    )}?alt=media&token=${downloadToken}`;

    return { photoURL, path: filePath };
  } catch (err) {
    console.error("uploadProfilePhoto error", err);
    if (err instanceof HttpsError) throw err;
    throw new HttpsError("internal", err?.message || "Failed to upload photo");
  }
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
    if (userSnap.data()?.approved !== true) {
      throw new HttpsError("permission-denied", "Awaiting admin approval");
    }

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

/**
 * Settle UFC 325 main card markets with official results.
 * Results from: https://www.ufc.com/event/ufc-325
 *
 * Usage (from functions/):
 *   npm run settle:ufc325
 *
 * Options:
 *   --dry-run   Print what would be settled (no Firestore writes)
 *
 * Requires: gcloud auth application-default login (or GOOGLE_APPLICATION_CREDENTIALS)
 */

const admin = require("firebase-admin");
const path = require("path");
const fs = require("fs");

function getProjectId() {
  if (process.env.GCLOUD_PROJECT) return process.env.GCLOUD_PROJECT;
  if (process.env.FIREBASE_CONFIG) {
    try {
      const cfg = JSON.parse(process.env.FIREBASE_CONFIG);
      if (cfg?.projectId) return cfg.projectId;
    } catch {
      // ignore
    }
  }
  try {
    const rcPath = path.resolve(__dirname, "..", "..", ".firebaserc");
    const rc = JSON.parse(fs.readFileSync(rcPath, "utf8"));
    const pid = rc?.projects?.default;
    if (pid) return pid;
  } catch {
    // ignore
  }
  return null;
}

// UFC 325 main card results (winner per market)
// marketId suffix _ml, eventId = marketId without _ml
const UFC_325_RESULTS = [
  { marketId: "ufc-325_alexander-volkanovski_vs_diego-lopes_2_ml", winningOption: "Alexander Volkanovski" },
  { marketId: "ufc-325_dan-hooker_vs_beno-t-saint-denis_ml", winningOption: "Benoît Saint Denis" },
  { marketId: "ufc-325_rafael-fiziev_vs_mauricio-ruffy_ml", winningOption: "Mauricio Ruffy" },
  { marketId: "ufc-325_tai-tuivasa_vs_tallison-teixeira_ml", winningOption: "Tallison Teixeira" },
  { marketId: "ufc-325_quillan-salkilld_vs_jamie-mullarkey_ml", winningOption: "Quillan Salkilld" },
];

async function main() {
  const args = new Set(process.argv.slice(2));
  if (args.has("--help") || args.has("-h")) {
    // eslint-disable-next-line no-console
    console.log(
      [
        "Settle UFC 325 main card markets with official results.",
        "",
        "Usage:",
        "  npm run settle:ufc325",
        "",
        "Options:",
        "  --dry-run   Print what would be settled (no Firestore writes)",
        "  --help      Show this help",
      ].join("\n")
    );
    return;
  }
  const dryRun = args.has("--dry-run");

  const projectId = getProjectId();
  if (!projectId) {
    throw new Error("Could not determine projectId. Set GCLOUD_PROJECT or configure .firebaserc.");
  }

  if (!dryRun) {
    admin.initializeApp({ projectId });
  }
  const db = dryRun ? null : admin.firestore();
  const FieldValue = admin.firestore?.FieldValue;

  for (const { marketId, winningOption } of UFC_325_RESULTS) {
    if (dryRun) {
      // eslint-disable-next-line no-console
      console.log(`[dry-run] Would settle ${marketId} -> winner: ${winningOption}`);
      continue;
    }

    const marketRef = db.collection("markets").doc(marketId);
    const marketSnap = await marketRef.get();
    if (!marketSnap.exists) {
      // eslint-disable-next-line no-console
      console.warn(`[skip] Market not found: ${marketId}`);
      continue;
    }

    const market = marketSnap.data();
    if (market.status === "settled") {
      // eslint-disable-next-line no-console
      console.log(`[skip] Already settled: ${marketId}`);
      continue;
    }

    const betsSnap = await db.collection("bets").where("marketId", "==", marketId).get();
    const bets = betsSnap.docs.map((d) => ({ id: d.id, ...d.data() }));

    if (bets.length === 0) {
      // No bets: just mark market as settled
      await marketRef.update({
        status: "settled",
        winningOption,
        settledAt: FieldValue.serverTimestamp(),
      });
      // eslint-disable-next-line no-console
      console.log(`[settled] ${marketId} (no bets) -> ${winningOption}`);
      continue;
    }

    // Run settlement logic (same as settleMarket Cloud Function)
    const pool = bets.reduce((s, b) => s + (Number(b.stake) || 0), 0);
    const winners = bets.filter((b) => b.option === winningOption);
    const losers = bets.filter((b) => b.option !== winningOption);
    const winningStakeTotal = winners.reduce((s, b) => s + (Number(b.stake) || 0), 0);

    if (winners.length === 0 || winningStakeTotal <= 0) {
      // eslint-disable-next-line no-console
      console.warn(`[skip] No winning bets for ${marketId} (winningOption: ${winningOption})`);
      continue;
    }

    winners.sort((a, b) => String(a.id).localeCompare(String(b.id)));
    const payoutByBetId = new Map();
    let distributed = 0;
    for (const bet of winners) {
      const stake = Number(bet.stake) || 0;
      const payout = Math.floor((stake * pool) / winningStakeTotal);
      payoutByBetId.set(bet.id, payout);
      distributed += payout;
    }
    let remainder = pool - distributed;
    for (let i = 0; remainder > 0 && winners.length > 0; i = (i + 1) % winners.length) {
      const betId = winners[i].id;
      payoutByBetId.set(betId, (payoutByBetId.get(betId) || 0) + 1);
      remainder -= 1;
    }

    const batch = db.batch();

    for (const bet of winners) {
      const payout = payoutByBetId.get(bet.id) || 0;
      const userRef = db.collection("users").doc(bet.uid);
      const ledgerRef = userRef.collection("ledger").doc();

      const userSnap = await userRef.get();
      if (!userSnap.exists) {
        // eslint-disable-next-line no-console
        console.warn(`[skip] User ${bet.uid} not found for bet ${bet.id}`);
        continue;
      }
      const bal = userSnap.data()?.balance ?? 0;

      batch.update(userRef, {
        balance: bal + payout,
        updatedAt: FieldValue.serverTimestamp(),
      });
      batch.set(ledgerRef, {
        type: "payout",
        marketId,
        betId: bet.id,
        delta: payout,
        balanceBefore: bal,
        balanceAfter: bal + payout,
        createdAt: FieldValue.serverTimestamp(),
      });
      batch.update(db.collection("bets").doc(bet.id), {
        status: "settled",
        result: "win",
        payout,
      });
    }

    for (const bet of losers) {
      batch.update(db.collection("bets").doc(bet.id), {
        status: "settled",
        result: "loss",
        payout: 0,
      });
    }

    batch.update(marketRef, {
      status: "settled",
      winningOption,
      settledAt: FieldValue.serverTimestamp(),
    });

    await batch.commit();
    // eslint-disable-next-line no-console
    console.log(`[settled] ${marketId} -> ${winningOption} (${bets.length} bets, ${winners.length} winners)`);
  }

  // eslint-disable-next-line no-console
  console.log("UFC 325 main card settlement complete.");
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exitCode = 1;
});

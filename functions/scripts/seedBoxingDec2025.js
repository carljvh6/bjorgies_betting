/**
 * One-time Firestore seeding script for a couple of boxing events.
 *
 * Usage (from repo root):
 *   npm --prefix functions run seed:boxing
 *
 * Options:
 *   --dry-run   Print docs that would be written (no Firestore writes)
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

function slug(s) {
  return String(s)
    .toLowerCase()
    .replace(/['’]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}

async function main() {
  const args = new Set(process.argv.slice(2));
  const dryRun = args.has("--dry-run");

  const projectId = getProjectId();
  if (!projectId) {
    throw new Error(
      "Could not determine projectId. Set GCLOUD_PROJECT or FIREBASE_CONFIG, or configure .firebaserc."
    );
  }

  if (!dryRun) {
    admin.initializeApp({ projectId });
  }
  const db = dryRun ? null : admin.firestore();

  const fights = [
    {
      // Source: Wikipedia
      cardId: "boxing-judgment-day-2025",
      cardName: "Judgment Day",
      venue: "Kaseya Center, Miami, Florida, USA",
      sport: "boxing",
      league: "Boxing",
      boutType: "Heavyweight",
      a: "Jake Paul",
      b: "Anthony Joshua",
      // Miami evening; choose a sane default and allow override.
      startEnv: "BOXING_PAUL_JOSHUA_START",
      startIso: "2025-12-20T01:00:00.000Z",
    },
    {
      // Source: Forbes coverage (event details corroborated via press release/search results)
      cardId: "boxing-fight-before-christmas-2025",
      cardName: "The Fight Before Christmas",
      venue: "Dubai Duty Free Tennis Stadium, Dubai, UAE",
      sport: "boxing",
      league: "Boxing",
      boutType: "Boxing",
      a: "Andrew Tate",
      b: "Chase DeMoor",
      // Reported main event approx 02:27 Dubai time (UTC+4) on Dec 21 => 22:27Z Dec 20.
      startEnv: "BOXING_TATE_DEMOOR_START",
      startIso: "2025-12-20T22:27:00.000Z",
    },
  ];

  const created = [];

  for (const f of fights) {
    const startIso = process.env[f.startEnv] || f.startIso;
    const startDate = new Date(startIso);
    if (Number.isNaN(startDate.getTime())) throw new Error(`Invalid ${f.startEnv}: ${startIso}`);

    const closesAtDate = new Date(startDate.getTime() - 5 * 60 * 1000);

    const eventId = `${f.cardId}_${slug(f.a)}_vs_${slug(f.b)}`;
    const marketId = `${eventId}_ml`;

    const eventDoc = {
      sport: f.sport,
      league: f.league,
      cardId: f.cardId,
      cardName: f.cardName,
      venue: f.venue,
      boutType: f.boutType,
      name: `${f.a} vs ${f.b}`,
      startTime: startDate.toISOString(),
      status: "scheduled",
      seededBy: "seedBoxingDec2025.js",
    };

    const marketDoc = {
      eventId,
      question: "Who wins?",
      options: [f.a, f.b],
      oddsType: "american",
      oddsAmerican: { [f.a]: 100, [f.b]: 100 },
      closesAt: closesAtDate.toISOString(),
      status: "open",
      winningOption: null,
      settledAt: null,
      seededBy: "seedBoxingDec2025.js",
    };

    if (dryRun) {
      // eslint-disable-next-line no-console
      console.log(`\n[dry-run] events/${eventId}`);
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(eventDoc, null, 2));
      // eslint-disable-next-line no-console
      console.log(`\n[dry-run] markets/${marketId}`);
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(marketDoc, null, 2));
    } else {
      const startTime = admin.firestore.Timestamp.fromDate(startDate);
      const closesAt = admin.firestore.Timestamp.fromDate(closesAtDate);

      await db.collection("events").doc(eventId).set(
        {
          ...eventDoc,
          startTime,
          seededAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );

      await db.collection("markets").doc(marketId).set(
        {
          ...marketDoc,
          closesAt,
          seededAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
    }

    created.push({ eventId, marketId });
  }

  // eslint-disable-next-line no-console
  console.log(`${dryRun ? "Planned" : "Seeded"} boxing fights into project ${projectId}:`);
  for (const x of created) {
    // eslint-disable-next-line no-console
    console.log(`- events/${x.eventId}`);
    // eslint-disable-next-line no-console
    console.log(`  markets/${x.marketId}`);
  }
}

main().catch((err) => {
  // eslint-disable-next-line no-console
  console.error(err);
  process.exitCode = 1;
});



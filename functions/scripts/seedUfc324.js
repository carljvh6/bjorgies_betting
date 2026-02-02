/**
 * One-time Firestore seeding script for UFC 324 (main card).
 *
 * Usage (from repo root):
 *   npm --prefix functions run seed:ufc324
 *
 * Auth:
 * - Recommended: `gcloud auth application-default login`
 * - Or set `GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json`
 *
 * Optional env:
 * - UFC324_START: ISO date string (defaults to 2026-01-25T04:00:00+02:00)
 */
const admin = require("firebase-admin");
const path = require("path");
const fs = require("fs");

function getProjectId() {
  if (process.env.GCLOUD_PROJECT) return process.env.GCLOUD_PROJECT;

  // Firebase Functions style env var (sometimes present locally too)
  if (process.env.FIREBASE_CONFIG) {
    try {
      const cfg = JSON.parse(process.env.FIREBASE_CONFIG);
      if (cfg?.projectId) return cfg.projectId;
    } catch {
      // ignore
    }
  }

  // Fallback: read repo root .firebaserc (../.firebaserc relative to functions/)
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
  if (args.has("--help") || args.has("-h")) {
    // eslint-disable-next-line no-console
    console.log(
      [
        "Seed UFC 324 (main card) into Firestore.",
        "",
        "Usage:",
        "  npm --prefix functions run seed:ufc324",
        "",
        "Options:",
        "  --dry-run   Print docs that would be written (no Firestore writes)",
        "  --help      Show this help",
        "",
        "Env:",
        "  UFC324_START=2026-01-25T04:00:00+02:00",
      ].join("\n")
    );
    return;
  }
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

  const eventCardId = "ufc-324";
  const cardName = "UFC 324";
  const cardVenue = "T-Mobile Arena, Las Vegas, NV";

  const startIso = process.env.UFC324_START || "2026-01-25T04:00:00+02:00"; // 4:00 AM SAST
  const mainCardStartDate = new Date(startIso);
  if (Number.isNaN(mainCardStartDate.getTime())) {
    throw new Error(`Invalid UFC324_START: ${startIso}`);
  }

  const fights = [
    { bout: "Lightweight Interim Title Bout", a: "Justin Gaethje", b: "Paddy Pimblett" },
    { bout: "Women's Bantamweight Title Bout", a: "Kayla Harrison", b: "Amanda Nunes" },
    { bout: "Bantamweight Bout", a: "Sean O'Malley", b: "Song Yadong" },
  ];

  const created = [];
  for (const f of fights) {
    const eventId = `${eventCardId}_${slug(f.a)}_vs_${slug(f.b)}`;
    const marketId = `${eventId}_ml`;

    // We don't know exact walkout times; keep all tied to the main card start for now.
    const startTimeDate = mainCardStartDate;
    const closesAtDate = new Date(mainCardStartDate.getTime() - 5 * 60 * 1000);

    const eventDoc = {
      sport: "mma",
      league: "UFC",
      cardId: eventCardId,
      cardName,
      venue: cardVenue,
      boutType: f.bout,
      name: `${f.a} vs ${f.b}`,
      startTime: startTimeDate.toISOString(),
      status: "scheduled",
      seededBy: "seedUfc324.js",
    };

    const marketDoc = {
      eventId,
      question: "Who wins?",
      options: [f.a, f.b],
      oddsType: "american",
      // Equal odds for now (even money).
      oddsAmerican: { [f.a]: 100, [f.b]: 100 },
      closesAt: closesAtDate.toISOString(),
      status: "open",
      winningOption: null,
      settledAt: null,
      seededBy: "seedUfc324.js",
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
      const startTime = admin.firestore.Timestamp.fromDate(startTimeDate);
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
  console.log(`${dryRun ? "Planned" : "Seeded"} UFC 324 main card into project ${projectId}:`);
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


/**
 * One-time Firestore seeding script for Springboks rugby fixtures.
 *
 * Usage (from repo root):
 *   npm --prefix functions run seed:springboks
 *
 * Options:
 *   --dry-run   Print docs that would be written (no Firestore writes)
 *
 * Notes:
 * - `events` collection in this app represents a single match.
 * - This seeds one event + one match-result market (home/draw/away) per fixture.
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

function toIsoNoonUtc(dateStr) {
  // Fixture dates are provided without time/timezone.
  // Use a stable default (12:00 UTC) and allow override via env if needed.
  return `${String(dateStr)}T12:00:00.000Z`;
}

async function main() {
  const args = new Set(process.argv.slice(2));
  if (args.has("--help") || args.has("-h")) {
    // eslint-disable-next-line no-console
    console.log(
      [
        "Seed Springboks rugby fixtures into Firestore.",
        "",
        "Usage:",
        "  npm --prefix functions run seed:springboks",
        "",
        "Options:",
        "  --dry-run   Print docs that would be written (no Firestore writes)",
        "  --help      Show this help",
        "",
        "Env:",
        "  You can override the default match start (UTC ISO) per date:",
        "    SPRINGBOKS_2025_06_28_START=2025-06-28T15:00:00.000Z",
      ].join("\n")
    );
    return;
  }

  const dryRun = args.has("--dry-run");

  const fixtures = [
    {
      date: "2025-06-28",
      home_team: "South Africa",
      away_team: "Barbarians",
      competition: "Summer Test",
      location: "Cape Town, South Africa",
      note: "Non-cap or invitational format",
    },
    {
      date: "2025-07-05",
      home_team: "South Africa",
      away_team: "Italy",
      competition: "Incoming Test",
      location: "Pretoria, South Africa",
    },
    {
      date: "2025-07-12",
      home_team: "South Africa",
      away_team: "Italy",
      competition: "Incoming Test",
      location: "Gqeberha, South Africa",
    },
    {
      date: "2025-07-19",
      home_team: "South Africa",
      away_team: "Georgia",
      competition: "Incoming Test",
      location: "Nelspruit, South Africa",
    },
    {
      date: "2025-08-16",
      home_team: "South Africa",
      away_team: "Australia",
      competition: "Rugby Championship",
      location: "South Africa",
    },
    {
      date: "2025-08-23",
      home_team: "South Africa",
      away_team: "Australia",
      competition: "Rugby Championship",
      location: "South Africa",
    },
    {
      date: "2025-09-06",
      home_team: "New Zealand",
      away_team: "South Africa",
      competition: "Rugby Championship",
      location: "New Zealand",
    },
    {
      date: "2025-09-13",
      home_team: "New Zealand",
      away_team: "South Africa",
      competition: "Rugby Championship",
      location: "New Zealand",
    },
    {
      date: "2025-09-27",
      home_team: "South Africa",
      away_team: "Argentina",
      competition: "Rugby Championship",
      location: "South Africa",
    },
    {
      date: "2025-10-04",
      home_team: "Argentina",
      away_team: "South Africa",
      competition: "Rugby Championship",
      location: "Argentina",
    },
    {
      date: "2025-11-08",
      home_team: "France",
      away_team: "South Africa",
      competition: "Autumn Nations Series",
      location: "France",
    },
    {
      date: "2025-11-15",
      home_team: "Italy",
      away_team: "South Africa",
      competition: "Autumn Nations Series",
      location: "Italy",
    },
    {
      date: "2025-11-22",
      home_team: "Ireland",
      away_team: "South Africa",
      competition: "Autumn Nations Series",
      location: "Ireland",
    },
    {
      date: "2025-11-29",
      home_team: "Wales",
      away_team: "South Africa",
      competition: "Autumn Nations Series",
      location: "Wales",
    },
    {
      date: "2026-07-04",
      home_team: "South Africa",
      away_team: "England",
      competition: "Nations Championship",
      location: "South Africa",
    },
    {
      date: "2026-07-11",
      home_team: "South Africa",
      away_team: "Scotland",
      competition: "Nations Championship",
      location: "South Africa",
    },
    {
      date: "2026-07-18",
      home_team: "South Africa",
      away_team: "Wales",
      competition: "Nations Championship",
      location: "South Africa",
    },
    {
      date: "2026-08-22",
      home_team: "South Africa",
      away_team: "New Zealand",
      competition: "Rugby’s Greatest Rivalry",
      location: "South Africa",
    },
    {
      date: "2026-08-29",
      home_team: "South Africa",
      away_team: "New Zealand",
      competition: "Rugby’s Greatest Rivalry",
      location: "South Africa",
    },
    {
      date: "2026-09-05",
      home_team: "South Africa",
      away_team: "New Zealand",
      competition: "Rugby’s Greatest Rivalry",
      location: "South Africa",
    },
    {
      date: "2026-09-12",
      home_team: "South Africa",
      away_team: "New Zealand",
      competition: "Rugby’s Greatest Rivalry",
      location: "TBD",
    },
    {
      date: "2026-11-06",
      home_team: "Italy",
      away_team: "South Africa",
      competition: "Nations Championship",
      location: "Europe",
    },
    {
      date: "2026-11-13",
      home_team: "France",
      away_team: "South Africa",
      competition: "Nations Championship",
      location: "Europe",
    },
    {
      date: "2026-11-21",
      home_team: "Ireland",
      away_team: "South Africa",
      competition: "Nations Championship",
      location: "Europe",
    },
  ];

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

  const created = [];

  for (const fx of fixtures) {
    const date = String(fx.date);
    const year = date.slice(0, 4);
    const comp = String(fx.competition || "Rugby");

    const cardId = `springboks-${slug(comp)}-${year}`;
    const cardName = comp;

    const home = String(fx.home_team);
    const away = String(fx.away_team);
    const venue = String(fx.location || "");

    const baseIso = toIsoNoonUtc(date);
    const envKey = `SPRINGBOKS_${year}_${date.slice(5, 7)}_${date.slice(8, 10)}_START`;
    const startIso = process.env[envKey] || baseIso;
    const startDate = new Date(startIso);
    if (Number.isNaN(startDate.getTime())) {
      throw new Error(`Invalid ${envKey}: ${startIso}`);
    }

    const closesAtDate = new Date(startDate.getTime() - 5 * 60 * 1000);

    const eventId = `${cardId}_${date}_${slug(home)}_vs_${slug(away)}`;
    const marketId = `${eventId}_ml`;
    const marginMarketId = `${eventId}_margin`;
    const scoreMarketId = `${eventId}_score`;

    const note = typeof fx.note === "string" ? fx.note.trim() : "";

    const eventDoc = {
      sport: "rugby",
      league: "Rugby",
      cardId,
      cardName,
      venue,
      boutType: comp,
      homeTeam: home,
      awayTeam: away,
      name: `${home} vs ${away}`,
      startTime: startDate.toISOString(),
      status: "scheduled",
      note: note || null,
      seededBy: "seedSpringboksRugby.js",
    };

    const options = [home, "Draw", away];
    const marketDoc = {
      eventId,
      question: "Match result?",
      options,
      oddsType: "decimal",
      // Simple placeholder odds.
      oddsDecimal: { [home]: 2.0, Draw: 3.5, [away]: 2.0 },
      closesAt: closesAtDate.toISOString(),
      status: "open",
      winningOption: null,
      settledAt: null,
      seededBy: "seedSpringboksRugby.js",
    };

    // Winning margin bands (points). Lets bettors pick "win by how much".
    const marginBands = ["1-7", "8-14", "15-20", "21+"];
    const marginOptions = [
      ...marginBands.map((b) => `${home} by ${b}`),
      "Draw",
      ...marginBands.map((b) => `${away} by ${b}`),
    ];
    const marginOddsDecimal = {};
    // Placeholder odds: shorter for small margins, longer for big margins/draw.
    for (const b of marginBands) marginOddsDecimal[`${home} by ${b}`] = b === "21+" ? 6.0 : b === "15-20" ? 4.5 : b === "8-14" ? 3.2 : 2.6;
    marginOddsDecimal.Draw = 11.0;
    for (const b of marginBands) marginOddsDecimal[`${away} by ${b}`] = b === "21+" ? 6.0 : b === "15-20" ? 4.5 : b === "8-14" ? 3.2 : 2.6;

    const marginMarketDoc = {
      eventId,
      question: "Winning margin?",
      options: marginOptions,
      oddsType: "decimal",
      oddsDecimal: marginOddsDecimal,
      closesAt: closesAtDate.toISOString(),
      status: "open",
      winningOption: null,
      settledAt: null,
      seededBy: "seedSpringboksRugby.js",
    };

    const scoreMarketDoc = {
      eventId,
      question: "Correct score?",
      kind: "score",
      homeTeam: home,
      awayTeam: away,
      scoreMax: 80,
      oddsType: "decimal",
      oddsDecimal: {}, // score bets are free-form; odds not used in winner-takes-pool
      closesAt: closesAtDate.toISOString(),
      status: "open",
      winningOption: null, // should be like "24-18" when settling
      settledAt: null,
      seededBy: "seedSpringboksRugby.js",
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
      // eslint-disable-next-line no-console
      console.log(`\n[dry-run] markets/${marginMarketId}`);
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(marginMarketDoc, null, 2));
      // eslint-disable-next-line no-console
      console.log(`\n[dry-run] markets/${scoreMarketId}`);
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(scoreMarketDoc, null, 2));
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

      await db.collection("markets").doc(marginMarketId).set(
        {
          ...marginMarketDoc,
          closesAt,
          seededAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );

      await db.collection("markets").doc(scoreMarketId).set(
        {
          ...scoreMarketDoc,
          closesAt,
          seededAt: admin.firestore.FieldValue.serverTimestamp(),
        },
        { merge: true }
      );
    }

    created.push({ eventId, marketId });
    created.push({ eventId, marketId: marginMarketId });
    created.push({ eventId, marketId: scoreMarketId });
  }

  // eslint-disable-next-line no-console
  console.log(`${dryRun ? "Planned" : "Seeded"} Springboks fixtures into project ${projectId}:`);
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

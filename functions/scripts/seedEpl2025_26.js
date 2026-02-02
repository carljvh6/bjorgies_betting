/**
 * One-time Firestore seeding script for EPL (Premier League 2025/26) fixtures.
 *
 * Usage (from repo root):
 *   npm --prefix functions run seed:epl
 *
 * Options:
 *   --dry-run   Print docs that would be written (no Firestore writes)
 *
 * Notes:
 * - `events` collection in this app represents a single match.
 * - This seeds one event + one 1X2 market (home/draw/away) per match.
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

function startIsoForDate(dateStr) {
  // Match dates are provided without kick-off time.
  // Use stable default (12:00 UTC) and allow override per date.
  return `${String(dateStr)}T12:00:00.000Z`;
}

async function main() {
  const args = new Set(process.argv.slice(2));
  if (args.has("--help") || args.has("-h")) {
    // eslint-disable-next-line no-console
    console.log(
      [
        "Seed EPL fixtures (Premier League 2025/26) into Firestore.",
        "",
        "Usage:",
        "  npm --prefix functions run seed:epl",
        "",
        "Options:",
        "  --dry-run   Print docs that would be written (no Firestore writes)",
        "  --help      Show this help",
        "",
        "Env:",
        "  Override default start time per date:",
        "    EPL_2025_12_20_START=2025-12-20T15:00:00.000Z",
      ].join("\n")
    );
    return;
  }

  const dryRun = args.has("--dry-run");

  const leagueName = "Premier League 2025/26";
  const leagueCode = "EPL";
  const baseLeagueId = "epl-2025-26";

  const matches = [
    { date: "2025-12-20", home: "AFC Bournemouth", away: "Burnley" },
    { date: "2025-12-20", home: "Aston Villa", away: "Manchester United" },
    { date: "2025-12-20", home: "Brighton", away: "Sunderland" },
    { date: "2025-12-20", home: "Everton", away: "Arsenal" },
    { date: "2025-12-20", home: "Fulham", away: "Nottingham Forest" },
    { date: "2025-12-20", home: "Leeds United", away: "Crystal Palace" },
    { date: "2025-12-20", home: "Manchester City", away: "West Ham United" },
    { date: "2025-12-20", home: "Newcastle United", away: "Chelsea" },
    { date: "2025-12-20", home: "Tottenham Hotspur", away: "Liverpool" },
    { date: "2025-12-20", home: "Wolves", away: "Brentford" },

    { date: "2025-12-27", home: "Arsenal", away: "Brighton" },
    { date: "2025-12-27", home: "Brentford", away: "AFC Bournemouth" },
    { date: "2025-12-27", home: "Burnley", away: "Everton" },
    { date: "2025-12-27", home: "Chelsea", away: "Aston Villa" },
    { date: "2025-12-27", home: "Crystal Palace", away: "Tottenham Hotspur" },
    { date: "2025-12-27", home: "Liverpool", away: "Wolves" },
    { date: "2025-12-27", home: "Manchester United", away: "Newcastle United" },
    { date: "2025-12-27", home: "Nottingham Forest", away: "Manchester City" },
    { date: "2025-12-27", home: "Sunderland", away: "Leeds United" },
    { date: "2025-12-27", home: "West Ham United", away: "Fulham" },

    { date: "2025-12-30", home: "Arsenal", away: "Aston Villa" },
    { date: "2025-12-30", home: "Brentford", away: "Tottenham Hotspur" },
    { date: "2025-12-30", home: "Burnley", away: "Newcastle United" },
    { date: "2025-12-30", home: "Chelsea", away: "AFC Bournemouth" },
    { date: "2025-12-30", home: "Crystal Palace", away: "Fulham" },
    { date: "2025-12-30", home: "Liverpool", away: "Leeds United" },
    { date: "2025-12-30", home: "Manchester United", away: "Wolves" },
    { date: "2025-12-30", home: "Nottingham Forest", away: "Everton" },
    { date: "2025-12-30", home: "Sunderland", away: "Manchester City" },
    { date: "2025-12-30", home: "West Ham United", away: "Brighton" },

    { date: "2026-01-03", home: "AFC Bournemouth", away: "Arsenal" },
    { date: "2026-01-03", home: "Aston Villa", away: "Nottingham Forest" },
    { date: "2026-01-03", home: "Brighton", away: "Burnley" },
    { date: "2026-01-03", home: "Everton", away: "Brentford" },
    { date: "2026-01-03", home: "Fulham", away: "Liverpool" },
    { date: "2026-01-03", home: "Leeds United", away: "Manchester United" },
    { date: "2026-01-03", home: "Manchester City", away: "Chelsea" },
    { date: "2026-01-03", home: "Newcastle United", away: "Crystal Palace" },
    { date: "2026-01-03", home: "Tottenham Hotspur", away: "Sunderland" },
    { date: "2026-01-03", home: "Wolves", away: "West Ham United" },

    { date: "2026-01-07", home: "AFC Bournemouth", away: "Tottenham Hotspur" },
    { date: "2026-01-07", home: "Arsenal", away: "Liverpool" },
    { date: "2026-01-07", home: "Brentford", away: "Sunderland" },
    { date: "2026-01-07", home: "Burnley", away: "Manchester United" },
    { date: "2026-01-07", home: "Crystal Palace", away: "Aston Villa" },
    { date: "2026-01-07", home: "Everton", away: "Wolves" },
    { date: "2026-01-07", home: "Fulham", away: "Chelsea" },
    { date: "2026-01-07", home: "Manchester City", away: "Brighton" },
    { date: "2026-01-07", home: "Newcastle United", away: "Leeds United" },
    { date: "2026-01-07", home: "West Ham United", away: "Nottingham Forest" },
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

  // Group by date so the dashboard can show a nice "box" per matchday.
  const matchesByDate = new Map();
  for (const m of matches) {
    const d = String(m.date);
    if (!matchesByDate.has(d)) matchesByDate.set(d, []);
    matchesByDate.get(d).push(m);
  }

  const created = [];

  for (const [date, list] of Array.from(matchesByDate.entries()).sort((a, b) => a[0].localeCompare(b[0]))) {
    const [yy, mm, dd] = date.split("-");
    const envKey = `EPL_${yy}_${mm}_${dd}_START`;
    const baseIso = startIsoForDate(date);
    const startIso = process.env[envKey] || baseIso;
    const matchdayStart = new Date(startIso);
    if (Number.isNaN(matchdayStart.getTime())) {
      throw new Error(`Invalid ${envKey}: ${startIso}`);
    }

    const cardId = `${baseLeagueId}_${date}`;
    const cardName = `${leagueName} • ${date}`;

    // Ensure stable ordering inside the matchday by applying a small increment per match.
    const stable = list
      .slice()
      .sort((a, b) => `${a.home} vs ${a.away}`.localeCompare(`${b.home} vs ${b.away}`));

    for (let i = 0; i < stable.length; i++) {
      const m = stable[i];
      const home = String(m.home);
      const away = String(m.away);

      const startDate = new Date(matchdayStart.getTime() + i * 60 * 1000);
      const closesAtDate = new Date(startDate.getTime() - 5 * 60 * 1000);

      const eventId = `${cardId}_${slug(home)}_vs_${slug(away)}`;
      const marketId = `${eventId}_ml`;
      const scoreMarketId = `${eventId}_score`;

      const eventDoc = {
        sport: "soccer",
        league: leagueCode,
        cardId,
        cardName,
        venue: "",
        boutType: leagueName,
        homeTeam: home,
        awayTeam: away,
        name: `${home} vs ${away}`,
        startTime: startDate.toISOString(),
        status: "scheduled",
        seededBy: "seedEpl2025_26.js",
      };

      const options = [home, "Draw", away];
      const marketDoc = {
        eventId,
        question: "Match result?",
        options,
        oddsType: "decimal",
        // Placeholder odds; update later when you have real prices.
        oddsDecimal: { [home]: 2.4, Draw: 3.2, [away]: 2.9 },
        closesAt: closesAtDate.toISOString(),
        status: "open",
        winningOption: null,
        settledAt: null,
        seededBy: "seedEpl2025_26.js",
      };

      const scoreMarketDoc = {
        eventId,
        question: "Correct score?",
        kind: "score",
        homeTeam: home,
        awayTeam: away,
        scoreMax: 20,
        oddsType: "decimal",
        oddsDecimal: {},
        closesAt: closesAtDate.toISOString(),
        status: "open",
        winningOption: null, // should be like "2-1" when settling
        settledAt: null,
        seededBy: "seedEpl2025_26.js",
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
      created.push({ eventId, marketId: scoreMarketId });
    }
  }

  // eslint-disable-next-line no-console
  console.log(`${dryRun ? "Planned" : "Seeded"} EPL fixtures into project ${projectId}:`);
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

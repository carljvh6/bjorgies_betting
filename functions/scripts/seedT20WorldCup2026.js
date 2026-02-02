/**
 * One-time Firestore seeding script for ICC Men's T20 World Cup 2026 (group stage).
 * Fixtures from: https://www.icc-cricket.com/tournaments/mens-t20-world-cup-2026/news/fixtures-groups-released-for-icc-men-s-t20-world-cup-2026
 *
 * Usage (from repo root):
 *   npm --prefix functions run seed:t20wc2026
 *
 * From functions/:
 *   npm run seed:t20wc2026
 *
 * Options:
 *   --dry-run   Print docs that would be written (no Firestore writes)
 *
 * Notes:
 * - Seeds group stage only (40 matches). Super Eights / knockouts use TBD teams.
 * - Times are local (India/Sri Lanka); converted to UTC (IST = UTC+5:30).
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
    .replace(/['']/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/(^-|-$)/g, "");
}

// Local time in India/Sri Lanka (IST = UTC+5:30) -> UTC ISO string
// slot: "11:00 AM" | "3:00 PM" | "7:00 PM"
function localToUtcIso(dateStr, slot) {
  const [y, m, d] = dateStr.split("-").map(Number);
  let hour = 12;
  if (slot === "11:00 AM") hour = 5;   // 11:00 IST -> 05:30 UTC
  else if (slot === "3:00 PM") hour = 9; // 15:00 IST -> 09:30 UTC
  else if (slot === "7:00 PM") hour = 13; // 19:00 IST -> 13:30 UTC
  const minute = 30;
  const utcDate = new Date(Date.UTC(y, m - 1, d, hour, minute, 0, 0));
  return utcDate.toISOString();
}

const TEAMS = {
  PAK: "Pakistan",
  NED: "Netherlands",
  WI: "West Indies",
  BAN: "Bangladesh",
  IND: "India",
  USA: "USA",
  NZ: "New Zealand",
  AFG: "Afghanistan",
  ENG: "England",
  NEP: "Nepal",
  SL: "Sri Lanka",
  IRE: "Ireland",
  ITA: "Italy",
  ZIM: "Zimbabwe",
  OMA: "Oman",
  SA: "South Africa",
  CAN: "Canada",
  NAM: "Namibia",
  UAE: "United Arab Emirates",
  AUS: "Australia",
};

const VENUES = {
  "SSC, Colombo": "Sinhalese Sports Club, Colombo",
  "Premadasa, Colombo": "R. Premadasa Stadium, Colombo",
  Kolkata: "Eden Gardens, Kolkata",
  Mumbai: "Wankhede Stadium, Mumbai",
  Chennai: "MA Chidambaram Stadium, Chennai",
  Delhi: "Arun Jaitley Stadium, New Delhi",
  Ahmedabad: "Narendra Modi Stadium, Ahmedabad",
  Kandy: "Pallekele International Cricket Stadium, Kandy",
};

async function main() {
  const args = new Set(process.argv.slice(2));
  if (args.has("--help") || args.has("-h")) {
    // eslint-disable-next-line no-console
    console.log(
      [
        "Seed ICC Men's T20 World Cup 2026 (group stage) into Firestore.",
        "",
        "Usage:",
        "  npm --prefix functions run seed:t20wc2026",
        "",
        "Options:",
        "  --dry-run   Print docs that would be written (no Firestore writes)",
        "  --help      Show this help",
      ].join("\n")
    );
    return;
  }
  const dryRun = args.has("--dry-run");

  const leagueName = "ICC Men's T20 World Cup 2026";
  const baseCardId = "t20wc-2026";

  // Group stage fixtures: date, time slot, team1 code, team2 code, venue key
  const fixtures = [
    { date: "2026-02-07", slot: "11:00 AM", t1: "PAK", t2: "NED", venue: "SSC, Colombo" },
    { date: "2026-02-07", slot: "3:00 PM", t1: "WI", t2: "BAN", venue: "Kolkata" },
    { date: "2026-02-07", slot: "7:00 PM", t1: "IND", t2: "USA", venue: "Mumbai" },
    { date: "2026-02-08", slot: "11:00 AM", t1: "NZ", t2: "AFG", venue: "Chennai" },
    { date: "2026-02-08", slot: "3:00 PM", t1: "ENG", t2: "NEP", venue: "Mumbai" },
    { date: "2026-02-08", slot: "7:00 PM", t1: "SL", t2: "IRE", venue: "Premadasa, Colombo" },
    { date: "2026-02-09", slot: "11:00 AM", t1: "BAN", t2: "ITA", venue: "Kolkata" },
    { date: "2026-02-09", slot: "3:00 PM", t1: "ZIM", t2: "OMA", venue: "SSC, Colombo" },
    { date: "2026-02-09", slot: "7:00 PM", t1: "SA", t2: "CAN", venue: "Ahmedabad" },
    { date: "2026-02-10", slot: "11:00 AM", t1: "NED", t2: "NAM", venue: "Delhi" },
    { date: "2026-02-10", slot: "3:00 PM", t1: "NZ", t2: "UAE", venue: "Chennai" },
    { date: "2026-02-10", slot: "7:00 PM", t1: "PAK", t2: "USA", venue: "SSC, Colombo" },
    { date: "2026-02-11", slot: "11:00 AM", t1: "SA", t2: "AFG", venue: "Ahmedabad" },
    { date: "2026-02-11", slot: "3:00 PM", t1: "AUS", t2: "IRE", venue: "Premadasa, Colombo" },
    { date: "2026-02-11", slot: "7:00 PM", t1: "ENG", t2: "WI", venue: "Mumbai" },
    { date: "2026-02-12", slot: "11:00 AM", t1: "SL", t2: "OMA", venue: "Kandy" },
    { date: "2026-02-12", slot: "3:00 PM", t1: "NEP", t2: "ITA", venue: "Mumbai" },
    { date: "2026-02-12", slot: "7:00 PM", t1: "IND", t2: "NAM", venue: "Delhi" },
    { date: "2026-02-13", slot: "11:00 AM", t1: "AUS", t2: "ZIM", venue: "Premadasa, Colombo" },
    { date: "2026-02-13", slot: "3:00 PM", t1: "CAN", t2: "UAE", venue: "Delhi" },
    { date: "2026-02-13", slot: "7:00 PM", t1: "USA", t2: "NED", venue: "Chennai" },
    { date: "2026-02-14", slot: "11:00 AM", t1: "IRE", t2: "OMA", venue: "SSC, Colombo" },
    { date: "2026-02-14", slot: "3:00 PM", t1: "ENG", t2: "BAN", venue: "Kolkata" },
    { date: "2026-02-14", slot: "7:00 PM", t1: "NZ", t2: "SA", venue: "Ahmedabad" },
    { date: "2026-02-15", slot: "11:00 AM", t1: "WI", t2: "NEP", venue: "Mumbai" },
    { date: "2026-02-15", slot: "3:00 PM", t1: "USA", t2: "NAM", venue: "Chennai" },
    { date: "2026-02-15", slot: "7:00 PM", t1: "IND", t2: "PAK", venue: "Premadasa, Colombo" },
    { date: "2026-02-16", slot: "11:00 AM", t1: "AFG", t2: "UAE", venue: "Delhi" },
    { date: "2026-02-16", slot: "3:00 PM", t1: "ENG", t2: "ITA", venue: "Kolkata" },
    { date: "2026-02-16", slot: "7:00 PM", t1: "AUS", t2: "SL", venue: "Kandy" },
    { date: "2026-02-17", slot: "11:00 AM", t1: "NZ", t2: "CAN", venue: "Chennai" },
    { date: "2026-02-17", slot: "3:00 PM", t1: "IRE", t2: "ZIM", venue: "Kandy" },
    { date: "2026-02-17", slot: "7:00 PM", t1: "BAN", t2: "NEP", venue: "Mumbai" },
    { date: "2026-02-18", slot: "11:00 AM", t1: "SA", t2: "UAE", venue: "Delhi" },
    { date: "2026-02-18", slot: "3:00 PM", t1: "PAK", t2: "NAM", venue: "SSC, Colombo" },
    { date: "2026-02-18", slot: "7:00 PM", t1: "IND", t2: "NED", venue: "Ahmedabad" },
    { date: "2026-02-19", slot: "11:00 AM", t1: "WI", t2: "ITA", venue: "Kolkata" },
    { date: "2026-02-19", slot: "3:00 PM", t1: "SL", t2: "ZIM", venue: "Premadasa, Colombo" },
    { date: "2026-02-19", slot: "7:00 PM", t1: "AFG", t2: "CAN", venue: "Chennai" },
    { date: "2026-02-20", slot: "7:00 PM", t1: "AUS", t2: "OMA", venue: "Kandy" },
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

  for (const f of fixtures) {
    const team1 = TEAMS[f.t1] || f.t1;
    const team2 = TEAMS[f.t2] || f.t2;
    const venue = VENUES[f.venue] || f.venue;
    const startIso = localToUtcIso(f.date, f.slot);
    const startDate = new Date(startIso);
    const closesAtDate = new Date(startDate.getTime() - 30 * 60 * 1000); // 30 min before start

    const eventId = `${baseCardId}_${slug(team1)}_vs_${slug(team2)}`;
    const marketId = `${eventId}_ml`;

    const eventDoc = {
      sport: "cricket",
      league: leagueName,
      cardId: baseCardId,
      cardName: leagueName,
      venue,
      boutType: "T20 International",
      homeTeam: team1,
      awayTeam: team2,
      name: `${team1} vs ${team2}`,
      startTime: startDate.toISOString(),
      status: "scheduled",
      seededBy: "seedT20WorldCup2026.js",
    };

    const marketDoc = {
      eventId,
      question: "Who wins?",
      options: [team1, team2],
      oddsType: "decimal",
      oddsDecimal: { [team1]: 2.0, [team2]: 2.0 },
      closesAt: closesAtDate.toISOString(),
      status: "open",
      winningOption: null,
      settledAt: null,
      seededBy: "seedT20WorldCup2026.js",
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
  console.log(`${dryRun ? "Planned" : "Seeded"} T20 World Cup 2026 (${created.length} matches) into project ${projectId}:`);
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

/**
 * One-time Firestore seeding script for F1 2026 season.
 * Schedule from: https://www.formula1.com/en/racing/2026
 * Drivers from: https://www.formula1.com/en/latest/article/2026-line-ups-confirmed-in-full
 *
 * Usage (from functions/):
 *   npm run seed:f12026
 *
 * Options:
 *   --dry-run   Print docs that would be written (no Firestore writes)
 *
 * Notes:
 * - One event per race, one market "Who wins?" with all 22 drivers as options.
 * - Race date = Sunday (typical race day). Start time 14:00 UTC.
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

// 2026 F1 drivers (22 drivers, 11 teams)
const F1_2026_DRIVERS = [
  "Alexander Albon",
  "Fernando Alonso",
  "Kimi Antonelli",
  "Oliver Bearman",
  "Gabriel Bortoleto",
  "Valtteri Bottas",
  "Franco Colapinto",
  "Pierre Gasly",
  "Isack Hadjar",
  "Lewis Hamilton",
  "Nico Hulkenberg",
  "Liam Lawson",
  "Charles Leclerc",
  "Arvid Lindblad",
  "Lando Norris",
  "Esteban Ocon",
  "Sergio Perez",
  "Oscar Piastri",
  "George Russell",
  "Carlos Sainz",
  "Lance Stroll",
  "Max Verstappen",
];

// Races: { round, name, country, date (YYYY-MM-DD, Sunday), venue }
const F1_2026_RACES = [
  { round: 1, name: "Australian Grand Prix", country: "Australia", date: "2026-03-08", venue: "Melbourne Grand Prix Circuit" },
  { round: 2, name: "Chinese Grand Prix", country: "China", date: "2026-03-15", venue: "Shanghai International Circuit" },
  { round: 3, name: "Japanese Grand Prix", country: "Japan", date: "2026-03-29", venue: "Suzuka Circuit" },
  { round: 4, name: "Bahrain Grand Prix", country: "Bahrain", date: "2026-04-12", venue: "Bahrain International Circuit" },
  { round: 5, name: "Saudi Arabian Grand Prix", country: "Saudi Arabia", date: "2026-04-19", venue: "Jeddah Corniche Circuit" },
  { round: 6, name: "Miami Grand Prix", country: "USA", date: "2026-05-03", venue: "Miami International Autodrome" },
  { round: 7, name: "Canadian Grand Prix", country: "Canada", date: "2026-05-24", venue: "Circuit Gilles Villeneuve" },
  { round: 8, name: "Monaco Grand Prix", country: "Monaco", date: "2026-06-07", venue: "Circuit de Monaco" },
  { round: 9, name: "Spanish Grand Prix (Barcelona)", country: "Spain", date: "2026-06-14", venue: "Circuit de Barcelona-Catalunya" },
  { round: 10, name: "Austrian Grand Prix", country: "Austria", date: "2026-06-28", venue: "Red Bull Ring" },
  { round: 11, name: "British Grand Prix", country: "Great Britain", date: "2026-07-05", venue: "Silverstone Circuit" },
  { round: 12, name: "Belgian Grand Prix", country: "Belgium", date: "2026-07-19", venue: "Circuit de Spa-Francorchamps" },
  { round: 13, name: "Hungarian Grand Prix", country: "Hungary", date: "2026-07-26", venue: "Hungaroring" },
  { round: 14, name: "Dutch Grand Prix", country: "Netherlands", date: "2026-08-23", venue: "Circuit Zandvoort" },
  { round: 15, name: "Italian Grand Prix", country: "Italy", date: "2026-09-06", venue: "Autodromo Nazionale Monza" },
  { round: 16, name: "Spanish Grand Prix (Madrid)", country: "Spain", date: "2026-09-13", venue: "Madrid Street Circuit" },
  { round: 17, name: "Azerbaijan Grand Prix", country: "Azerbaijan", date: "2026-09-26", venue: "Baku City Circuit" },
  { round: 18, name: "Singapore Grand Prix", country: "Singapore", date: "2026-10-11", venue: "Marina Bay Street Circuit" },
  { round: 19, name: "United States Grand Prix", country: "USA", date: "2026-10-25", venue: "Circuit of the Americas" },
  { round: 20, name: "Mexican Grand Prix", country: "Mexico", date: "2026-11-01", venue: "Autódromo Hermanos Rodríguez" },
  { round: 21, name: "Brazilian Grand Prix", country: "Brazil", date: "2026-11-08", venue: "Interlagos" },
  { round: 22, name: "Las Vegas Grand Prix", country: "USA", date: "2026-11-21", venue: "Las Vegas Street Circuit" },
  { round: 23, name: "Qatar Grand Prix", country: "Qatar", date: "2026-11-29", venue: "Lusail International Circuit" },
  { round: 24, name: "Abu Dhabi Grand Prix", country: "UAE", date: "2026-12-06", venue: "Yas Marina Circuit" },
];

async function main() {
  const args = new Set(process.argv.slice(2));
  if (args.has("--help") || args.has("-h")) {
    // eslint-disable-next-line no-console
    console.log(
      [
        "Seed F1 2026 season into Firestore.",
        "",
        "Usage:",
        "  npm run seed:f12026",
        "",
        "Options:",
        "  --dry-run   Print docs that would be written (no Firestore writes)",
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

  const leagueName = "F1 2026";
  const baseCardId = "f1-2026";
  const created = [];

  // Equal decimal odds for all drivers (placeholder)
  const oddsDecimal = {};
  for (const d of F1_2026_DRIVERS) {
    oddsDecimal[d] = 22; // 1/22 implied probability
  }

  for (const race of F1_2026_RACES) {
    const eventId = `${baseCardId}_r${race.round}_${slug(race.name)}`;
    const marketId = `${eventId}_ml`;
    const cardId = `${baseCardId}_r${race.round}`;

    const startIso = `${race.date}T14:00:00.000Z`;
    const startDate = new Date(startIso);
    const closesAtDate = new Date(startDate.getTime() - 30 * 60 * 1000);

    const eventDoc = {
      sport: "f1",
      league: leagueName,
      cardId,
      cardName: race.name,
      venue: race.venue,
      boutType: "Grand Prix",
      name: race.name,
      startTime: startDate.toISOString(),
      status: "scheduled",
      seededBy: "seedF12026.js",
    };

    const marketDoc = {
      eventId,
      question: "Who wins the race?",
      options: [...F1_2026_DRIVERS],
      oddsType: "decimal",
      oddsDecimal: { ...oddsDecimal },
      closesAt: closesAtDate.toISOString(),
      status: "open",
      winningOption: null,
      settledAt: null,
      seededBy: "seedF12026.js",
    };

    if (dryRun) {
      // eslint-disable-next-line no-console
      console.log(`\n[dry-run] events/${eventId}`);
      // eslint-disable-next-line no-console
      console.log(JSON.stringify(eventDoc, null, 2));
      // eslint-disable-next-line no-console
      console.log(`\n[dry-run] markets/${marketId}`);
      // eslint-disable-next-line no-console
      console.log(JSON.stringify({ ...marketDoc, oddsDecimal: "(22 drivers)" }, null, 2));
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
  console.log(`${dryRun ? "Planned" : "Seeded"} F1 2026 (${created.length} races) into project ${projectId}:`);
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

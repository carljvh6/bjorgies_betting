/**
 * One-time Firestore seeding script for UFC cards (top 3 main card fights).
 *
 * Usage (from repo root):
 *   npm --prefix functions run seed:ufc-top3
 *
 * Auth:
 * - Recommended: `gcloud auth application-default login`
 * - Or set `GOOGLE_APPLICATION_CREDENTIALS=/path/to/service-account.json`
 *
 * Options:
 *   --dry-run   Print docs that would be written (no Firestore writes)
 *
 * Notes:
 * - `events` collection in this app represents an individual fight.
 * - This script seeds one event + one moneyline market per fight.
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

function parseFightNames(fightStr) {
  const raw = String(fightStr || "").trim();
  const parts = raw.split(/\s+vs\.?\s+/i);
  if (parts.length >= 2) {
    const a = parts[0].trim();
    const bRaw = parts.slice(1).join(" vs ").trim();

    // Handle common UFC rematch notation: "Fighter A vs. Fighter B 2"
    // We keep the series number for display/IDs, but don't include it in the fighter name/options.
    const m = bRaw.match(/^(.*?)(?:\s+(\d+))$/);
    if (m) {
      const b = String(m[1] || "").trim();
      const series = Number(m[2]);
      if (b && Number.isInteger(series) && series > 1) return { a, b, series };
    }

    return { a, b: bRaw, series: null };
  }
  return { a: raw, b: "", series: null };
}

function addDays(yyyyMmDd, days) {
  const [y, m, d] = String(yyyyMmDd).split("-").map((x) => Number(x));
  const dt = new Date(Date.UTC(y, (m || 1) - 1, d || 1));
  dt.setUTCDate(dt.getUTCDate() + days);
  const yy = dt.getUTCFullYear();
  const mm = String(dt.getUTCMonth() + 1).padStart(2, "0");
  const dd = String(dt.getUTCDate()).padStart(2, "0");
  return `${yy}-${mm}-${dd}`;
}

function deriveCardId(cardName) {
  const s = String(cardName || "");
  const ppv = s.match(/\bUFC\s+(\d+)\b/i);
  if (ppv) return `ufc-${ppv[1]}`;
  const vegas = s.match(/\bVegas\s+(\d+)\b/i);
  if (vegas) return `ufc-fn-vegas-${vegas[1]}`;
  return slug(s) || "ufc-card";
}

function boutLabel(f) {
  const title = typeof f?.title === "string" ? f.title.trim() : "";
  if (title) return title;
  const wc = typeof f?.weight_class === "string" ? f.weight_class.trim() : "";
  if (wc) return `${wc} Bout`;
  const note = typeof f?.note === "string" ? f.note.trim() : "";
  return note || "Bout";
}

function shouldSkipFight(fightStr, a, b) {
  const t = String(fightStr || "").toUpperCase();
  if (!a || !b) return true;
  if (t.includes("TBA")) return true;
  if (String(a).trim().toUpperCase() === String(b).trim().toUpperCase()) return true;
  return false;
}

async function main() {
  const args = new Set(process.argv.slice(2));
  if (args.has("--help") || args.has("-h")) {
    // eslint-disable-next-line no-console
    console.log(
      [
        "Seed UFC cards (top-3 main card fights) into Firestore.",
        "",
        "Usage:",
        "  npm --prefix functions run seed:ufc-top3",
        "",
        "Options:",
        "  --dry-run   Print docs that would be written (no Firestore writes)",
        "  --help      Show this help",
        "",
        "Env:",
        "  You can override a card start time with e.g.:",
        "    UFC_CARD_UFC_324_START=2026-01-25T04:00:00+02:00",
      ].join("\n")
    );
    return;
  }

  const dryRun = args.has("--dry-run");

  const cards = [
    {
      event: "UFC Fight Night: Royval vs. Kape (Vegas 112)",
      date: "2025-12-13",
      location: "UFC APEX, Las Vegas, NV, USA",
      main_card_top3: [
        { fight: "Brandon Royval vs. Manel Kape", weight_class: "Flyweight" },
        { fight: "Giga Chikadze vs. Kevin Vallejos", weight_class: "Featherweight" },
        { fight: "Cesar Almeida vs. Cezary Oleksiejczuk", weight_class: "Light Heavyweight" },
      ],
    },
    {
      event: "UFC 324: Gaethje vs. Pimblett",
      date: "2026-01-24",
      location: "T-Mobile Arena, Las Vegas, NV, USA",
      main_card_top3: [
        { fight: "Justin Gaethje vs. Paddy Pimblett", title: "Interim Lightweight Championship" },
        { fight: "Kayla Harrison vs. Amanda Nunes", weight_class: "Women’s Bantamweight" },
        // Keep naming consistent with existing seedUfc324 ids.
        { fight: "Sean O'Malley vs. Song Yadong", weight_class: "Bantamweight" },
      ],
    },
    {
      event: "UFC 325: Volkanovski vs. Lopes 2",
      date: "2026-02-01", // 1 Feb in SA when the main card takes place
      location: "Qudos Bank Arena, Sydney Olympic Park, Australia",
      // Bet cutoff: midnight South African time (SAST, UTC+2) on event day
      closesAtIso: "2026-02-01T00:00:00+02:00",
      main_card_top3: [
        { fight: "Alexander Volkanovski vs. Diego Lopes 2", title: "Featherweight Championship", oddsAmerican: { "Alexander Volkanovski": -150, "Diego Lopes": 125 } },
        { fight: "Dan Hooker vs. Benoît Saint Denis", weight_class: "Lightweight", oddsAmerican: { "Dan Hooker": 275, "Benoît Saint Denis": -350 } },
        { fight: "Rafael Fiziev vs. Mauricio Ruffy", weight_class: "Lightweight", oddsAmerican: { "Rafael Fiziev": 100, "Mauricio Ruffy": -125 } },
        { fight: "Tai Tuivasa vs. Tallison Teixeira", weight_class: "Heavyweight", oddsAmerican: { "Tai Tuivasa": 275, "Tallison Teixeira": -350 } },
        { fight: "Quillan Salkilld vs. Jamie Mullarkey", weight_class: "Lightweight", oddsAmerican: { "Quillan Salkilld": -1200, "Jamie Mullarkey": 700 } },
      ],
    },
    {
      event: "UFC Fight Night: Bautista vs. Oliveira (Vegas 113)",
      date: "2026-02-07",
      location: "UFC APEX, Las Vegas, NV, USA",
      main_card_top3: [
        { fight: "Mario Bautista vs. Vinicius Oliveira", weight_class: "Bantamweight" },
        { fight: "Amir Albazi vs. Kyoji Horiguchi", weight_class: "Flyweight" },
        { fight: "Ryan Spann vs. Rizvan Kuniev", weight_class: "Heavyweight" },
      ],
    },
    {
      event: "UFC 326: Holloway vs. Oliveira 2",
      date: "2026-03-07",
      location: "T-Mobile Arena, Las Vegas, NV, USA",
      main_card_top3: [
        { fight: "Max Holloway vs. Charles Oliveira 2", title: "BMF / Lightweight" },
        { fight: "Renato Moicano vs. Brian Ortega", weight_class: "Lightweight" },
        { fight: "TBA vs. TBA", note: "Additional main card bouts not fully announced as of current schedules" },
      ],
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

  for (const card of cards) {
    const cardName = String(card.event);
    const cardId = deriveCardId(cardName);

    // Heuristic: the provided `date` is typically the local US event date; if it's in the USA,
    // shift +1 day to align with SAST-style "main card start" defaults used elsewhere.
    const isUsa = String(card.location || "").toUpperCase().includes("USA");
    const baseDate = isUsa ? addDays(card.date, 1) : String(card.date);

    const envKey = `UFC_CARD_${cardId.toUpperCase().replace(/-/g, "_")}_START`;
    const startIso = process.env[envKey] || `${baseDate}T04:00:00+02:00`;
    const mainCardStartDate = new Date(startIso);
    if (Number.isNaN(mainCardStartDate.getTime())) {
      throw new Error(`Invalid ${envKey}: ${startIso}`);
    }

    const venue = String(card.location || "");
    const fights = Array.isArray(card.main_card_top3) ? card.main_card_top3 : [];

    // Bet cutoff: card-specific closesAtIso (e.g. midnight SAST) or 5 min before main card start
    const closesAtDate = card.closesAtIso
      ? (() => {
          const d = new Date(card.closesAtIso);
          if (Number.isNaN(d.getTime())) throw new Error(`Invalid closesAtIso: ${card.closesAtIso}`);
          return d;
        })()
      : new Date(mainCardStartDate.getTime() - 5 * 60 * 1000);

    for (const f of fights) {
      const fightStr = String(f?.fight || "");
      const { a, b, series } = parseFightNames(fightStr);
      if (shouldSkipFight(fightStr, a, b)) {
        // eslint-disable-next-line no-console
        console.log(`[skip] ${cardId}: ${fightStr || "(missing fight)"}`);
        continue;
      }

      const seriesSuffix = Number.isInteger(series) && series > 1 ? `_${series}` : "";
      const eventId = `${cardId}_${slug(a)}_vs_${slug(b)}${seriesSuffix}`;
      const marketId = `${eventId}_ml`;

      // We don't know exact walkout times; keep all tied to the main card start for now.
      const startTimeDate = mainCardStartDate;

      const eventDoc = {
        sport: "mma",
        league: "UFC",
        cardId,
        cardName,
        venue,
        boutType: boutLabel(f),
        name: `${a} vs ${b}${seriesSuffix ? ` ${series}` : ""}`,
        startTime: startTimeDate.toISOString(),
        status: "scheduled",
        seededBy: "seedUfcTop3Cards.js",
      };

      // Use per-fight odds if provided (e.g. from UFC.com), else even money
      const oddsAmerican = f.oddsAmerican && typeof f.oddsAmerican === "object" && f.oddsAmerican[a] != null && f.oddsAmerican[b] != null
        ? { [a]: f.oddsAmerican[a], [b]: f.oddsAmerican[b] }
        : { [a]: 100, [b]: 100 };

      const marketDoc = {
        eventId,
        question: "Who wins?",
        options: [a, b],
        oddsType: "american",
        oddsAmerican,
        closesAt: closesAtDate.toISOString(),
        status: "open",
        winningOption: null,
        settledAt: null,
        seededBy: "seedUfcTop3Cards.js",
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
  }

  // eslint-disable-next-line no-console
  console.log(`${dryRun ? "Planned" : "Seeded"} UFC top-3 fights into project ${projectId}:`);
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

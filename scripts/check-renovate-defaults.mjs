// Every recorded Renovate manager default still matches the shipped package.
//
//     node scripts/check-renovate-defaults.mjs            # assert
//     node scripts/check-renovate-defaults.mjs --write     # re-record
//
// check-renovate-coverage.py decides whether a pin is watched by matching the
// pin's file against the file patterns of the manager it is attributed to. When
// renovate.json configures none, the manager runs on defaultConfig.managerFilePatterns
// from inside the Renovate package — which a Python gate with no network cannot
// read, so scripts/renovate-manager-defaults.json holds a transcript of it.
//
// A transcript goes stale in silence, and stale here is worse than absent: the
// gate would certify a pin against a pattern Renovate no longer uses and print
// the same success. This re-resolves every entry against the package and fails
// on any difference, so the record cannot drift without a red build. Four
// disagreements, each a different repair: a pattern that moved, a manager
// enabled with nothing recorded for it, a recording that outlived its manager,
// and a record written against a version other than the one installed.
//
// Exit 1 for a record that disagrees with the package. Exit 2 for a package this
// cannot import — that is a run that checked nothing, which is not a pass.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const SCRIPTS = dirname(fileURLToPath(import.meta.url));
const ROOT = join(SCRIPTS, "..");
const RECORD = join(SCRIPTS, "renovate-manager-defaults.json");

const write = process.argv.includes("--write");

const config = JSON.parse(readFileSync(join(ROOT, "renovate.json"), "utf8"));
const enabled = config.enabledManagers ?? [];
if (enabled.length === 0) {
  console.error("Cannot run: renovate.json enables no manager, so there is no default to check.");
  process.exit(2);
}

// `custom.regex` lives under manager/custom/regex; every built-in is its own name.
const modulePath = (m) =>
  `renovate/dist/modules/manager/${m.startsWith("custom.") ? "custom/" + m.slice(7) : m}/index.js`;

// Resolved before anything is compared, and inside the same refusal as the
// manager imports below: a package that is not there is a run that checked
// nothing, and an uncaught resolution error would exit 1 — the status this
// script uses for a record that disagrees with a package it did read.
let installed;
try {
  installed = JSON.parse(
    readFileSync(new URL(import.meta.resolve("renovate/package.json")), "utf8")
  ).version;
} catch (err) {
  console.error(
    `Cannot run: the renovate package is not resolvable from ${SCRIPTS} — ` +
      `${err.message.split("\n")[0]}.`
  );
  console.error("Nothing was compared, which is not the same as a record that matches.");
  process.exit(2);
}

const shipped = {};
// Sorted, so the record's diff shows a default that moved rather than a
// reordering of enabledManagers.
for (const manager of [...enabled].sort()) {
  let mod;
  try {
    mod = await import(modulePath(manager));
  } catch (err) {
    console.error(
      `Cannot run: renovate.json enables the ${manager} manager and ` +
        `${modulePath(manager)} is not importable — ${err.message.split("\n")[0]}.`
    );
    console.error("No default was resolved, which is not the same as one that matches.");
    process.exit(2);
  }
  shipped[manager] = mod.defaultConfig?.managerFilePatterns ?? null;
}

if (write) {
  const existing = JSON.parse(readFileSync(RECORD, "utf8"));
  existing.generated.renovate = installed;
  existing.managers = shipped;
  writeFileSync(RECORD, JSON.stringify(existing, null, 2) + "\n");
  console.log(`recorded ${Object.keys(shipped).length} manager default(s) at renovate ${installed}`);
  process.exit(0);
}

const record = JSON.parse(readFileSync(RECORD, "utf8"));
const recorded = record.managers ?? {};
const problems = [];
const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

// The version the record names is a claim about which package these patterns
// came from, so it is checked rather than carried. A pin raised without
// re-recording leaves the record describing a version nobody resolved — and if
// the defaults happen not to have moved, every other check here still passes.
if (record.generated?.renovate !== installed) {
  problems.push(
    `the record was written against renovate ${record.generated?.renovate} and ` +
      `renovate ${installed} is installed. Re-record with --write.`
  );
}

for (const [manager, patterns] of Object.entries(shipped)) {
  if (!(manager in recorded)) {
    problems.push(
      `${manager} is enabled and absent from the record, so the gate has no ` +
        `default to fall back on for it. Re-record with --write.`
    );
  } else if (!same(recorded[manager], patterns)) {
    problems.push(
      `${manager}: recorded ${JSON.stringify(recorded[manager])}, ` +
        `package ships ${JSON.stringify(patterns)}. Any pin certified against the ` +
        `recorded value was certified against a pattern Renovate does not use.`
    );
  }
}
for (const manager of Object.keys(recorded)) {
  if (!(manager in shipped)) {
    problems.push(
      `${manager} is recorded but renovate.json no longer enables it — the record ` +
        `outlived the manager. Re-record with --write.`
    );
  }
}

if (problems.length > 0) {
  for (const p of problems) console.error(`FAIL  ${p}`);
  process.exit(1);
}
console.log(
  `renovate manager defaults OK: ${Object.keys(shipped).length} enabled manager(s) ` +
    `match scripts/renovate-manager-defaults.json`
);

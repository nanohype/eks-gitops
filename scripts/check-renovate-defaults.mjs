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
//
// WHERE THE ANSWER COMES FROM
//
// Renovate's manager registry, in one import. The package ships no `exports`
// map and documents no API for this, so every answer about a manager's defaults
// comes from inside `dist/` whichever path is taken; what a single entry point
// buys is one place to repair when the layout moves rather than one per enabled
// manager, and the registry's own `isKnownManager` — which separates a manager
// name this repository misspelled from a layout that moved, two failures that
// look identical from a failed import of a per-manager path.
//
// The package also declares `engines.node`, and its own code uses language
// features newer than some runtimes ship. Running it below that floor throws
// inside Renovate rather than in this script, which is why the CI job reads
// .node-version instead of inheriting the runner's Node: no entry point into
// this package avoids the floor, so a supported Node is the precondition and
// not a property of how the import is spelled.

import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const SCRIPTS = dirname(fileURLToPath(import.meta.url));
const ROOT = join(SCRIPTS, "..");
const RECORD = join(SCRIPTS, "renovate-manager-defaults.json");
const NODE_VERSION_FILE = join(ROOT, ".node-version");

// The `engines.node` forms this reads. A range in any other form REFUSES rather
// than being guessed at: misread one way it passes a Node the package cannot
// run on, misread the other it fails one it can, and both answers are worse
// than saying the range was not understood.
const ENGINE_FLOOR = /^(?<op>\^|>=)\s*(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)$/;
const VERSION = /^v?(?<major>\d+)\.(?<minor>\d+)\.(?<patch>\d+)/;

const parseFloor = (range) => {
  const m = ENGINE_FLOOR.exec((range ?? "").trim());
  if (!m) return null;
  return {
    caret: m.groups.op === "^",
    major: +m.groups.major,
    minor: +m.groups.minor,
    patch: +m.groups.patch,
    text: range.trim(),
  };
};

const satisfies = (version, floor) => {
  const m = VERSION.exec((version ?? "").trim());
  if (!m) return false;
  const [major, minor, patch] = [+m.groups.major, +m.groups.minor, +m.groups.patch];
  if (major !== floor.major) return floor.caret ? false : major > floor.major;
  if (minor !== floor.minor) return minor > floor.minor;
  return patch >= floor.patch;
};

const write = process.argv.includes("--write");

const config = JSON.parse(readFileSync(join(ROOT, "renovate.json"), "utf8"));
const enabled = config.enabledManagers ?? [];
if (enabled.length === 0) {
  console.error("Cannot run: renovate.json enables no manager, so there is no default to check.");
  process.exit(2);
}

// The one internal path this script depends on.
const REGISTRY = "renovate/dist/modules/manager/index.js";

// Resolved before anything is compared, and inside the same refusal as the
// manager imports below: a package that is not there is a run that checked
// nothing, and an uncaught resolution error would exit 1 — the status this
// script uses for a record that disagrees with a package it did read.
let installed;
let installedEngines;
try {
  const pkg = JSON.parse(
    readFileSync(new URL(import.meta.resolve("renovate/package.json")), "utf8")
  );
  installed = pkg.version;
  installedEngines = pkg.engines?.node;
} catch (err) {
  console.error(
    `Cannot run: the renovate package is not resolvable from ${SCRIPTS} — ` +
      `${err.message.split("\n")[0]}.`
  );
  console.error("Nothing was compared, which is not the same as a record that matches.");
  process.exit(2);
}

// The package's declared floor, checked against the Node running this and
// against the Node the workflow installs. Both, because they fail differently:
// a run below the floor resolves nothing at all, while a .node-version below it
// is a tree that will fail the next time CI runs even though this machine is
// fine. Checked BEFORE the import, so the answer names the floor and the file to
// raise rather than surfacing as a language error thrown inside the package.
const floor = parseFloor(installedEngines);
if (installedEngines && !floor) {
  console.error(
    `Cannot run: renovate declares engines.node ${JSON.stringify(installedEngines)}, ` +
      `a range form this script does not implement, so whether a given Node ` +
      `satisfies it is unknown here.`
  );
  process.exit(2);
}
if (floor && !satisfies(process.versions.node, floor)) {
  console.error(
    `Cannot run: renovate ${installed} declares engines.node ${floor.text} and this ` +
      `is node ${process.versions.node}. Below that floor the package throws while ` +
      `loading rather than reporting anything.`
  );
  console.error("No default was resolved, which is not the same as one that matches.");
  process.exit(2);
}

let pinnedNode = null;
try {
  pinnedNode = readFileSync(NODE_VERSION_FILE, "utf8").trim();
} catch {
  pinnedNode = null;
}

let registry;
try {
  registry = await import(REGISTRY);
} catch (err) {
  console.error(
    `Cannot run: ${REGISTRY} is not importable — ${err.message.split("\n")[0]}.`
  );
  console.error(
    `This node (${process.versions.node}) satisfies the package's declared ` +
      `engines.node ${installedEngines ?? "unknown"}, so the module layout moved ` +
      `rather than the runtime being too old.`
  );
  console.error("No default was resolved, which is not the same as one that matches.");
  process.exit(2);
}

const shipped = {};
// Sorted, so the record's diff shows a default that moved rather than a
// reordering of enabledManagers.
for (const manager of [...enabled].sort()) {
  if (!registry.isKnownManager?.(manager)) {
    console.error(
      `Cannot run: renovate.json enables the ${manager} manager and this Renovate ` +
        `does not know that name — it is misspelled here, or the manager was removed.`
    );
    console.error("No default was resolved, which is not the same as one that matches.");
    process.exit(2);
  }
  shipped[manager] = registry.get(manager, "defaultConfig")?.managerFilePatterns ?? null;
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
if (floor && pinnedNode !== null && !satisfies(pinnedNode, floor)) {
  problems.push(
    `.node-version pins node ${pinnedNode} and renovate ${installed} declares ` +
      `engines.node ${floor.text}. The job that installs from that file would run ` +
      `the package below its floor, where it throws while loading — so this check ` +
      `and the config validator beside it would resolve nothing.`
  );
}
if (floor && pinnedNode === null) {
  problems.push(
    `renovate ${installed} declares engines.node ${floor.text} and .node-version ` +
      `does not exist, so the job installs whatever Node the runner ships and the ` +
      `floor is satisfied by luck rather than by a pin.`
  );
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
if (floor) {
  console.log(
    `node OK: .node-version pins ${pinnedNode}, which satisfies the engines.node ` +
      `${floor.text} renovate ${installed} declares`
  );
}

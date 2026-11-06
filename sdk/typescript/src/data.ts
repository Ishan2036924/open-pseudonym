// Loads the shared data files (fake-value pools, detection patterns, starter profiles).
//
// The canonical copies live in the repository's top-level data/ folder. tools/sync_data.py copies them into each SDK
// so the published package carries them too; CI fails if the copies drift.

import * as fs from "node:fs";
import * as path from "node:path";
import { fileURLToPath } from "node:url";
import { pyRepr } from "./util.ts";

// src/ and dist/ sit at the same depth, so one relative path serves both.
const DATA_DIR = fileURLToPath(new URL("../data/", import.meta.url));

export interface Pools {
  version: number;
  first_names: { f: string[]; m: string[]; n: string[] };
  last_names: string[];
  cities: string[];
  orgs: string[];
  streets: string[];
  street_suffixes: string[];
  domain_words: string[];
  // a Map, so a name like "constructor" is never mistaken for an inherited property
  name_gender: Map<string, string>;
  name_stopwords: string[];
  webmail_domains: string[];
  test_cards: string[];
  advertising_ssns: string[];
  public_suffixes: string[];
}

export interface PatternSpec {
  type: string;
  pattern: string;
  group?: number;
  flags?: string;
  check?: string | null;
  priority?: number;
  note?: string;
}

function readJson(file: string): any {
  return JSON.parse(fs.readFileSync(path.join(DATA_DIR, file), "utf-8"));
}

let poolsCache: Pools | null = null;
let patternsCache: PatternSpec[] | null = null;

export function pools(): Pools {
  if (poolsCache === null) {
    const raw = readJson("pools.json");
    poolsCache = { ...raw, name_gender: new Map(Object.entries(raw.name_gender)) };
  }
  return poolsCache!;
}

export function patterns(): PatternSpec[] {
  if (patternsCache === null) patternsCache = readJson("patterns.json").patterns;
  return patternsCache!;
}

export function profileNames(): string[] {
  return fs
    .readdirSync(path.join(DATA_DIR, "profiles"))
    .filter((f) => f.endsWith(".json"))
    .map((f) => f.slice(0, -".json".length))
    .sort();
}

export function profileDoc(name: string): any {
  // names are plain words; refusing anything else keeps a caller from reaching outside the profiles folder
  if (!/^[A-Za-z0-9_-]+$/.test(name) || !fs.existsSync(path.join(DATA_DIR, "profiles", `${name}.json`))) {
    throw new Error(`no built-in profile called ${pyRepr(name)}; try one of ${pyRepr(profileNames())}`);
  }
  return readJson(path.join("profiles", `${name}.json`));
}

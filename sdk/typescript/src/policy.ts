// Policies: for one kind of task, what happens to each type of personal data.
//
// A policy is a small JSON document (see spec section 5). The important property is direction: code may always make a
// policy stricter, but nothing in this library lets a model's output loosen it. Each action has a strength, and
// `tighten` and `withRules` refuse to lower it.

import * as data from "./data.ts";
import { canonical, digest } from "./jcs.ts";
import { isPublicSuffix } from "./fakes.ts";
import { checkTypeName, DIGIT_TYPES } from "./types.ts";
import { cmpCodePoints, isPlainObject, pyRepr, truthy } from "./util.ts";

// How much each action hides. "keep" hides nothing; "refuse" stops the request.
export const STRENGTH: ReadonlyMap<string, number> = new Map(Object.entries({
  keep: 0,
  shift: 1,
  generalize: 1,
  fake: 2,
  tag: 2,
  token: 2,
  fpe: 2,
  handle: 3,
  drop: 4,
  refuse: 5,
}));
export const ACTIONS = [...STRENGTH.keys()];

// Options each action understands. Anything else is a typo we would rather catch early.
const OPTIONS: ReadonlyMap<string, ReadonlySet<string>> = new Map([
  ["fake", new Set(["keep_gender", "keep_region"])],
  ["handle", new Set(["uses", "ttl_s", "ask", "tools", "sites"])],
]);

export class PolicyError extends Error {
  constructor(message: string) {
    super(message);
    this.name = "PolicyError";
  }
}

export class Rule {
  readonly action: string;
  readonly options: Readonly<Record<string, any>>;

  constructor(action: string, options: Record<string, any> = {}) {
    this.action = action;
    this.options = options;
  }

  get strength(): number {
    return STRENGTH.get(this.action)!;
  }

  toDict(): Record<string, any> {
    return { action: this.action, ...this.options };
  }

  static fromDict(type: string, doc: any): Rule {
    if (!isPlainObject(doc) || !("action" in doc)) throw new PolicyError(`${type}: a rule is an object with an 'action'`);
    const action = doc.action;
    if (typeof action !== "string" || !STRENGTH.has(action)) throw new PolicyError(`${type}: unknown action ${pyRepr(action)}`);
    if (action === "shift" && type !== "DATE" && type !== "*") throw new PolicyError(`${type}: only dates can be shifted`);
    if (action === "fpe" && !DIGIT_TYPES.has(type) && type !== "*") {
      throw new PolicyError(`${type}: format-preserving encryption is for digit types only`);
    }
    const options: Record<string, any> = {};
    for (const [k, v] of Object.entries(doc)) if (k !== "action") options[k] = v;
    const sites = truthy(options.sites) ? (Array.isArray(options.sites) ? options.sites : isPlainObject(options.sites) ? Object.keys(options.sites) : []) : [];
    for (const site of sites) {
      // *.com or *.github.io would let anyone's site match; a wildcard needs a real domain under it
      if (typeof site === "string" && site.startsWith("*.") && (!site.slice(2).includes(".") || isPublicSuffix(site.slice(2)))) {
        throw new PolicyError(`${type}: ${pyRepr(site)} covers a whole public suffix`);
      }
    }
    const allowed = OPTIONS.get(action) ?? new Set<string>();
    const unknown = Object.keys(options).filter((k) => !allowed.has(k)).sort(cmpCodePoints);
    if (unknown.length > 0) throw new PolicyError(`${type}: option(s) ${pyRepr(unknown)} do not apply to ${pyRepr(action)}`);
    return new Rule(action, options);
  }
}

/** The smaller of two optional limits; null or undefined means no limit. */
function minOpt(a: number | null | undefined, b: number | null | undefined): number | null | undefined {
  if (a == null) return b;
  if (b == null) return a;
  return Math.min(a, b);
}

/** Two optional allow-lists combined so the result allows only what both allow. Null when neither is set, an empty
 * list when they have nothing in common. */
function narrow(a: string[] | null | undefined, b: string[] | null | undefined): string[] | null {
  if (!truthy(a)) return truthy(b) ? [...b!] : null;
  if (!truthy(b)) return [...a!];
  return a!.filter((x) => b!.includes(x));
}

/**
 * The stricter of two rules. When both are the same action, their limits combine, so tightening can never drop a
 * handle's `uses`, `ttl_s`, `ask`, `sites` or `tools`. Ties between different actions keep `a`.
 */
export function stricter(a: Rule, b: Rule): Rule {
  if (a.strength !== b.strength) return a.strength > b.strength ? a : b;
  if (a.action !== b.action || a.action !== "handle") return a;
  const opts: Record<string, any> = {};
  const uses = minOpt(a.options.uses, b.options.uses);
  const ttl = minOpt(a.options.ttl_s, b.options.ttl_s);
  const sites = narrow(a.options.sites, b.options.sites);
  const tools = narrow(a.options.tools, b.options.tools);
  if ((sites !== null && sites.length === 0) || (tools !== null && tools.length === 0)) {
    return new Rule("drop"); // the two sides allow no common place, so nothing may ever be filled
  }
  if (uses != null) opts.uses = uses;
  if (ttl != null) opts.ttl_s = ttl;
  if (truthy(a.options.ask) || truthy(b.options.ask)) opts.ask = true;
  if (sites !== null) opts.sites = sites;
  if (tools !== null) opts.tools = tools;
  return new Rule("handle", opts);
}

export class Policy {
  readonly id: string;
  readonly rules: ReadonlyMap<string, Rule>;
  readonly default: Rule;
  readonly description: string;
  readonly allow: readonly string[];

  constructor(id: string, rules: ReadonlyMap<string, Rule>, defaultRule: Rule, description = "", allow: readonly string[] = []) {
    this.id = id;
    this.rules = rules;
    this.default = defaultRule;
    this.description = description;
    this.allow = allow;
  }

  static fromDict(doc: any): Policy {
    if (!isPlainObject(doc) || doc.type !== "policy") throw new PolicyError("not a policy document (type must be 'policy')");
    if (typeof doc.id !== "string" || doc.id === "") throw new PolicyError("a policy needs an id");
    const rules = new Map<string, Rule>();
    for (const [type, rule] of Object.entries(truthy(doc.rules) ? doc.rules : {})) {
      rules.set(checkTypeName(type), Rule.fromDict(type, rule));
    }
    const defaultRule = Rule.fromDict("*", truthy(doc.default) ? doc.default : { action: "tag" });
    if (defaultRule.action === "shift" || defaultRule.action === "fpe") {
      throw new PolicyError("the default action cannot be shift or fpe");
    }
    const allow = truthy(doc.allow) ? [...doc.allow] : [];
    return new Policy(doc.id, rules, defaultRule, doc.description ?? "", allow);
  }

  toDict(): Record<string, any> {
    const rules: Record<string, any> = {};
    for (const t of [...this.rules.keys()].sort(cmpCodePoints)) rules[t] = this.rules.get(t)!.toDict();
    return {
      opn: "0.1",
      type: "policy",
      id: this.id,
      description: this.description,
      rules,
      default: this.default.toDict(),
      allow: [...this.allow],
    };
  }

  get digest(): string {
    return digest(canonical(this.toDict()));
  }

  ruleFor(type: string): Rule {
    return this.rules.get(type) ?? this.default;
  }

  /** The stricter of two policies, type by type. Ties keep this policy's rule. */
  tighten(other: Policy): Policy {
    const types = new Set([...this.rules.keys(), ...other.rules.keys()]);
    const rules = new Map<string, Rule>();
    for (const t of types) rules.set(t, stricter(this.ruleFor(t), other.ruleFor(t)));
    const defaultRule = stricter(this.default, other.default);
    const allow = this.allow.filter((v) => other.allow.includes(v)); // only values both policies allow stay visible
    return new Policy(`${this.id}+${other.id}`, rules, defaultRule, this.description, allow);
  }

  /** Apply rule overrides that may only make things stricter. Throws PolicyError on any loosening. */
  withRules(overrides: Record<string, any>): Policy {
    const rules = new Map(this.rules);
    for (const [type, doc] of Object.entries(overrides)) {
      checkTypeName(type);
      const next = Rule.fromDict(type, doc);
      const old = this.ruleFor(type);
      if (next.strength < old.strength) {
        throw new PolicyError(`${type}: ${pyRepr(old.action)} cannot be loosened to ${pyRepr(next.action)}`);
      }
      rules.set(type, stricter(next, old)); // same action: the old limits still apply
    }
    return new Policy(this.id, rules, this.default, this.description, this.allow);
  }
}

/**
 * A simple switch for products: how much the person wants hidden. Secrets (codes, passwords, cards, bank numbers,
 * SSNs, keys) are hidden at every level, as handles the model can still use, so nothing breaks for the task.
 */
export const LEVELS: Readonly<Record<1 | 2 | 3, { profile: string; label: string; description: string }>> = {
  1: { profile: "secrets_only", label: "Secrets", description: "Codes, passwords, cards, bank numbers and keys are hidden. Everything else is visible." },
  2: { profile: "contacts", label: "Contacts", description: "Secrets, plus emails, phone numbers, street addresses and IPs. Names stay visible." },
  3: { profile: "strict", label: "Everything", description: "Secrets, contacts, names, companies and places are replaced; dates shift together." },
};

/** The policy behind a privacy level (1, 2 or 3); show LEVELS[n].label and .description to the person. */
export function loadLevel(level: number): Policy {
  const entry = (LEVELS as Record<number, { profile: string }>)[level];
  if (!entry) throw new PolicyError(`levels are 1, 2 and 3, got ${level}`);
  return loadProfile(entry.profile);
}

/** One of the starter profiles shipped with the library (see `profileNames()`). */
export function loadProfile(name: string): Policy {
  return Policy.fromDict(data.profileDoc(name));
}

export function profileNames(): string[] {
  return data.profileNames();
}

// Tool names that hint at the kind of task. Only a suggestion: the app decides.
const HINTS: [string, string[]][] = [
  ["browse_and_fill", ["browser", "navigate", "click", "type_text", "fill", "login", "sign_in", "checkout"]],
  ["schedule", ["calendar", "event", "meeting", "schedule", "availability", "invite"]],
  ["draft_reply", ["send_email", "reply", "draft", "send_message", "compose"]],
  ["money_math", ["invoice", "budget", "expense", "payment", "transaction", "ledger"]],
  ["web_research", ["search", "web", "browse_url", "fetch_url", "lookup"]],
  ["summarize", ["summar", "read_file", "read_document", "retrieve", "rag"]],
];

/** Guess a starter profile from the tools an agent has. The app should confirm; the model never chooses. */
export function suggestProfile(toolNames: string[]): string {
  const names = toolNames.map((t) => t.toLowerCase());
  for (const [profile, hints] of HINTS) {
    if (names.some((n) => hints.some((h) => n.includes(h)))) return profile;
  }
  return "strict";
}

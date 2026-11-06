// Policies: for one kind of task, what happens to each type of personal data.
//
// A policy is a small JSON document (see spec section 5). The important property is direction: code may always make a
// policy stricter, but nothing in this library lets a model's output loosen it. Each action has a strength, and
// `tighten` and `withRules` refuse to lower it.

import * as data from "./data.ts";
import { canonical, digest } from "./jcs.ts";
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
    const allowed = OPTIONS.get(action) ?? new Set<string>();
    const unknown = Object.keys(options).filter((k) => !allowed.has(k)).sort(cmpCodePoints);
    if (unknown.length > 0) throw new PolicyError(`${type}: option(s) ${pyRepr(unknown)} do not apply to ${pyRepr(action)}`);
    return new Rule(action, options);
  }
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
    for (const t of types) {
      const mine = this.ruleFor(t);
      const theirs = other.ruleFor(t);
      rules.set(t, theirs.strength > mine.strength ? theirs : mine);
    }
    const defaultRule = other.default.strength > this.default.strength ? other.default : this.default;
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
      rules.set(type, next);
    }
    return new Policy(this.id, rules, this.default, this.description, this.allow);
  }
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

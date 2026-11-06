import { test } from "node:test";
import assert from "node:assert/strict";
import { generateText, isStepCount, jsonSchema, streamText, tool, wrapLanguageModel } from "ai";
import { MockLanguageModelV4 } from "ai/test";
import { EgressLeak, Session, Sink, Source, Vault } from "../src/index.ts";
import { pseudonymMiddleware } from "../src/vercel-ai/index.ts";

const NOW = 1793836800;
const usage = { inputTokens: { total: 1, noCache: 1, cacheRead: 0, cacheWrite: 0 }, outputTokens: { total: 1, text: 1, reasoning: 0 } };
const stop = { unified: "stop", raw: undefined } as any;
const toolCalls = { unified: "tool-calls", raw: undefined } as any;

// Names are only found next to a cue ("From:", "Hi"), so the app lists the people it knows.
function session(profile = "strict") {
  return new Session(profile, {
    vault: new Vault(Buffer.alloc(32, 1), NOW), clock: () => NOW, known: { PERSON: ["Dana Reyes"] },
  });
}

// The stand-in for a real value, learned by masking it the same way the middleware will.
function standIn(s: Session, real: string): string {
  return s.mask(real).text;
}

// Everything the provider was sent, as text, so a test can look for real values in it.
function sentText(model: MockLanguageModelV4): string {
  return JSON.stringify([...model.doGenerateCalls, ...model.doStreamCalls].map((c) => c.prompt));
}

test("generateText: the provider sees stand-ins, the caller reads real values", async () => {
  const s = session();
  const fake = standIn(s, "Dana Reyes");
  const fakeMail = standIn(s, "dana.reyes@gmail.com");
  const mock = new MockLanguageModelV4({
    doGenerate: { content: [{ type: "text", text: `Hello ${fake}, I will write to ${fakeMail}.` }], finishReason: stop, usage, warnings: [] } as any,
  });
  const model = wrapLanguageModel({ model: mock, middleware: pseudonymMiddleware({ session: s }) });
  const { text } = await generateText({
    model,
    system: "You help Dana Reyes.",
    messages: [{ role: "user", content: "Write to Dana Reyes at dana.reyes@gmail.com" }],
  });
  assert.equal(text, "Hello Dana Reyes, I will write to dana.reyes@gmail.com.");
  const sent = sentText(mock);
  assert.ok(!sent.includes("Dana") && !sent.includes("dana.reyes"), sent);
  assert.ok(sent.includes(fake));
});

test("streamText: text restored across chunk boundaries", async () => {
  const s = session();
  const fake = standIn(s, "Dana Reyes");
  const full = `Sure, ${fake} will get it. Thanks, ${fake}!`;
  const chunks: any[] = [{ type: "stream-start", warnings: [] }, { type: "text-start", id: "t" }];
  for (let i = 0; i < full.length; i += 3) chunks.push({ type: "text-delta", id: "t", delta: full.slice(i, i + 3) });
  chunks.push({ type: "text-end", id: "t" }, { type: "finish", finishReason: stop, usage });
  const mock = new MockLanguageModelV4({
    doStream: { stream: new ReadableStream({ start(c) { for (const p of chunks) c.enqueue(p); c.close(); } }) } as any,
  });
  const model = wrapLanguageModel({ model: mock, middleware: pseudonymMiddleware({ session: s }) });
  const result = streamText({ model, messages: [{ role: "user", content: "Tell Dana Reyes hi" }] });
  const deltas: string[] = [];
  for await (const d of result.textStream) deltas.push(d);
  assert.equal(deltas.join(""), "Sure, Dana Reyes will get it. Thanks, Dana Reyes!");
  assert.ok(!sentText(mock).includes("Dana"));
});

test("tool calls: the tool runs on real values, and the history is masked on the next step", async () => {
  const s = session();
  const fakeMail = standIn(s, "dana.reyes@gmail.com");
  const sent: any[] = [];
  const send = tool({
    description: "Send an email",
    inputSchema: jsonSchema<{ to: string }>({ type: "object", properties: { to: { type: "string" } }, required: ["to"] }),
    execute: async (input: { to: string }) => { sent.push(input); return `sent to ${input.to}`; },
  });
  const mock = new MockLanguageModelV4({
    doGenerate: [
      { content: [{ type: "tool-call", toolCallId: "c1", toolName: "send", input: JSON.stringify({ to: fakeMail }) }], finishReason: toolCalls, usage, warnings: [] },
      { content: [{ type: "text", text: "done" }], finishReason: stop, usage, warnings: [] },
    ] as any,
  });
  const model = wrapLanguageModel({ model: mock, middleware: pseudonymMiddleware({ session: s }) });
  const result = await generateText({
    model, tools: { send }, stopWhen: isStepCount(3),
    messages: [{ role: "user", content: "Email dana.reyes@gmail.com" }],
  });
  assert.deepEqual(sent, [{ to: "dana.reyes@gmail.com" }]);
  assert.equal(result.text, "done");
  // the second request carried the tool call and its result, and neither held the real address
  assert.equal(mock.doGenerateCalls.length, 2);
  assert.ok(!sentText(mock).includes("dana.reyes@gmail.com"));
  assert.ok(sentText(mock).includes(fakeMail));
});

test("tool calls: a handle is filled only where the app's sink says it belongs", async () => {
  const run = async (site: string) => {
    const s = session("draft_reply");
    const masked = s.mask("Your Acme verification code is 482913.", new Source({ sender: "no-reply@acme.com" }));
    const handle = /\{\{OTP_1\}\}/.exec(masked.text)![0];
    const typed: any[] = [];
    const typeCode = tool({
      description: "Type text into the page",
      inputSchema: jsonSchema<{ text: string }>({ type: "object", properties: { text: { type: "string" } }, required: ["text"] }),
      execute: async (input: { text: string }) => { typed.push(input.text); return "typed"; },
    });
    const mock = new MockLanguageModelV4({
      doGenerate: { content: [{ type: "tool-call", toolCallId: "c1", toolName: "type", input: JSON.stringify({ text: handle }) }], finishReason: toolCalls, usage, warnings: [] } as any,
    });
    const model = wrapLanguageModel({
      model: mock,
      middleware: pseudonymMiddleware({ session: s, sink: (toolName) => new Sink({ tool: toolName, site }), source: { sender: "no-reply@acme.com" } }),
    });
    const attempt = () => generateText({
      model, tools: { type: typeCode },
      messages: [{ role: "user", content: "Your Acme verification code is 482913. Please log in." }],
    });
    return { attempt, typed, mock };
  };
  const ok = await run("https://acme.com/verify");
  await ok.attempt();
  assert.deepEqual(ok.typed, ["482913"]);
  assert.ok(!sentText(ok.mock).includes("482913"));
  assert.ok(sentText(ok.mock).includes("{{OTP_1}} is a 6-digit one-time code"), "the model is told what the handle is");

  const bad = await run("https://evil.example/login");
  await assert.rejects(bad.attempt(), /bound to a different site/);
  assert.deepEqual(bad.typed, [], "the code never reached the tool");
});

test("the egress check is on by default and stops a request that would carry a known real value", async () => {
  const s = session();
  s.mask("Dana Reyes");
  const mock = new MockLanguageModelV4({ doGenerate: { content: [{ type: "text", text: "hi" }], finishReason: stop, usage, warnings: [] } as any });
  // provider options are not rewritten, so a real value placed there reaches the check
  const model = wrapLanguageModel({ model: mock, middleware: pseudonymMiddleware({ session: s }) });
  await assert.rejects(
    generateText({ model, messages: [{ role: "user", content: [{ type: "text", text: "hello" }], providerOptions: { x: { who: "Dana Reyes" } } }] }),
    EgressLeak,
  );
  assert.equal(mock.doGenerateCalls.length, 0);
  // the check can be turned off
  const open = wrapLanguageModel({ model: mock, middleware: pseudonymMiddleware({ session: s, checkEgress: false }) });
  await generateText({ model: open, messages: [{ role: "user", content: [{ type: "text", text: "hello" }], providerOptions: { x: { who: "Dana Reyes" } } }] });
  assert.equal(mock.doGenerateCalls.length, 1);
});

test("masking runs twice: a name learned from a later message is masked in an earlier one", async () => {
  const s = new Session("strict", { vault: new Vault(Buffer.alloc(32, 1), NOW), clock: () => NOW });
  const mock = new MockLanguageModelV4({
    doGenerate: { content: [{ type: "text", text: "ok" }], finishReason: stop, usage, warnings: [] } as any,
  });
  const model = wrapLanguageModel({ model: mock, middleware: pseudonymMiddleware({ session: s }) });
  // "Dana" has no cue in the first message; the second one introduces her with a cue
  await generateText({
    model,
    messages: [
      { role: "user", content: "Is Dana free on Thursday?" },
      { role: "assistant", content: "Not sure." },
      { role: "user", content: "Hi Dana Reyes, please confirm." },
    ],
  });
  const sent = sentText(mock);
  assert.ok(!sent.includes("Dana") && !sent.includes("Reyes"), sent);
});

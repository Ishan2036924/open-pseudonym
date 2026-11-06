// Open Pseudonym for the Vercel AI SDK (v7): a language-model middleware.
//
//     import { wrapLanguageModel, generateText } from "ai";
//     import { Session } from "open-pseudonym";
//     import { pseudonymMiddleware } from "open-pseudonym/vercel-ai";
//
//     const session = new Session("draft_reply");
//     const model = wrapLanguageModel({ model: yourModel, middleware: pseudonymMiddleware({ session }) });
//     const { text } = await generateText({ model, prompt: "Reply to Dana Reyes at dana@gmail.com" });
//
// The prompt is masked on its way to the provider; the answer, the streamed text and the tool-call inputs are
// restored on their way back. Your tools run on real values, the provider only ever sees stand-ins.
//
// What is not covered: files and images (they are binary and cannot be masked), tool definitions, and provider
// options. Reasoning parts are left alone, since some providers sign them and reject edited copies.

import type { LanguageModelMiddleware } from "ai";
import { EgressLeak, Sink, type Session, type SinkLike, type SourceLike } from "../index.ts";
import type { StreamRestorer } from "../restore.ts";

type Middleware = LanguageModelMiddleware;
type CallOptions = Parameters<NonNullable<Middleware["transformParams"]>>[0]["params"];
type Prompt = CallOptions["prompt"];

export interface SourceInfo {
  role: string;
  toolName?: string;
}

export interface PseudonymMiddlewareOptions {
  session: Session;
  /**
   * Where a tool's arguments are about to go. The app answers this from facts it trusts (the tool's fixed target, the
   * browser's real URL), never from the model. Without it a tool call has no site, so a handle bound to a site is
   * refused: the safe default.
   */
  sink?: (toolName: string) => SinkLike;
  /** Show real secrets in restored text. Off by default: a handle then reads as a short description. */
  revealHandles?: boolean;
  /** Where the prompt text came from, so handles can be bound to a site. A function can tell roles and tools apart. */
  source?: SourceLike | ((info: SourceInfo) => SourceLike | null | undefined);
  /** Look for known real values in the masked prompt before it goes out and throw EgressLeak if one is left. */
  checkEgress?: boolean;
}

export function pseudonymMiddleware(options: PseudonymMiddlewareOptions): Middleware {
  const { session } = options;
  const revealHandles = options.revealHandles ?? false;
  const sinkFor = options.sink ?? ((toolName: string) => new Sink({ tool: toolName }));
  const sourceFor = (info: SourceInfo): SourceLike | null => {
    const s = options.source;
    return (typeof s === "function" ? s(info) : s) ?? null;
  };

  // The arguments of a tool call, with stand-ins turned back into real values and handles filled in where allowed.
  function resolveInput(toolName: string, input: string): string {
    const sink = sinkFor(toolName);
    let value: unknown;
    try {
      value = JSON.parse(input);
    } catch {
      return session.resolveArgs(input, sink).args;
    }
    return JSON.stringify(session.resolveArgs(value, sink).args);
  }

  function restoreContent(content: any[]): any[] {
    return content.map((part) => {
      if (part.type === "text") return { ...part, text: session.restore(part.text, revealHandles) };
      // a tool the provider runs itself saw stand-ins only, so there is nothing to put back
      if (part.type === "tool-call" && !part.providerExecuted) {
        return { ...part, input: resolveInput(part.toolName, part.input) };
      }
      return part;
    });
  }

  return {
    specificationVersion: "v4",

    async transformParams({ params }) {
      const prompt = maskPrompt(session, params.prompt, sourceFor);
      if (options.checkEgress) {
        const leaks = session.checkEgress(JSON.stringify(prompt));
        if (leaks.length > 0) throw new EgressLeak(leaks);
      }
      return { ...params, prompt };
    },

    async wrapGenerate({ doGenerate }) {
      const result = await doGenerate();
      return { ...result, content: restoreContent(result.content) };
    },

    async wrapStream({ doStream }) {
      const { stream, ...rest } = await doStream();
      // one restorer per text block, because a block's text may be cut anywhere between chunks
      const blocks = new Map<string, StreamRestorer>();
      const restorerFor = (id: string): StreamRestorer => {
        let r = blocks.get(id);
        if (r === undefined) {
          r = session.stream(revealHandles);
          blocks.set(id, r);
        }
        return r;
      };
      const transform = new TransformStream<any, any>({
        transform(part, controller) {
          switch (part.type) {
            case "text-delta": {
              const delta = restorerFor(part.id).feed(part.delta);
              if (delta !== "") controller.enqueue({ ...part, delta });
              return;
            }
            case "text-end": {
              const rest = restorerFor(part.id).flush();
              blocks.delete(part.id);
              if (rest !== "") controller.enqueue({ type: "text-delta", id: part.id, delta: rest });
              controller.enqueue(part);
              return;
            }
            case "tool-call": {
              if (part.providerExecuted) {
                controller.enqueue(part);
                return;
              }
              try {
                controller.enqueue({ ...part, input: resolveInput(part.toolName, part.input) });
              } catch (error) {
                // the call is dropped and the refusal is reported, so a refused secret is never sent to the tool
                controller.enqueue({ type: "error", error });
              }
              return;
            }
            default:
              controller.enqueue(part);
          }
        },
        flush(controller) {
          // a stream that ends without closing its blocks still gets what it was holding back
          for (const [id, r] of blocks) {
            const rest = r.flush();
            if (rest !== "") controller.enqueue({ type: "text-delta", id, delta: rest });
          }
          blocks.clear();
        },
      });
      return { stream: stream.pipeThrough(transform), ...rest };
    },
  };
}

// Masking the prompt


function maskPrompt(session: Session, prompt: Prompt, sourceFor: (info: SourceInfo) => SourceLike | null): Prompt {
  const seen = new Set<string>(); // a note goes with the first message that mentions its handle
  return prompt.map((msg: any) => {
    const notes: string[] = [];
    const take = (more: string[]) => {
      for (const n of more) if (!notes.includes(n)) notes.push(n);
    };
    const text = (value: string, info: SourceInfo): string => {
      const m = session.mask(value, sourceFor(info));
      take(m.notes);
      return m.text;
    };
    const json = (value: unknown, info: SourceInfo): any => {
      const [masked, more] = session.maskJson(value, sourceFor(info));
      take(more);
      return masked;
    };
    const output = (out: any, info: SourceInfo): any => {
      switch (out.type) {
        case "text":
        case "error-text":
          return { ...out, value: text(out.value, info) };
        case "json":
        case "error-json":
          return { ...out, value: json(out.value, info) };
        case "content":
          return { ...out, value: out.value.map((item: any) => (item.type === "text" ? { ...item, text: text(item.text, info) } : item)) };
        default:
          return out;
      }
    };
    const part = (p: any): any => {
      switch (p.type) {
        case "text":
          return { ...p, text: text(p.text, { role: msg.role }) };
        case "tool-call":
          return { ...p, input: json(p.input, { role: msg.role, toolName: p.toolName }) };
        case "tool-result":
          return { ...p, output: output(p.output, { role: msg.role, toolName: p.toolName }) };
        default:
          return p;
      }
    };
    const masked = typeof msg.content === "string"
      ? { ...msg, content: text(msg.content, { role: msg.role }) }
      : { ...msg, content: msg.content.map(part) };
    const fresh = notes.filter((n) => !seen.has(n) && !JSON.stringify(masked).includes(n));
    for (const n of notes) seen.add(n);
    return fresh.length > 0 ? withNotes(masked, fresh) : masked;
  });
}

/** The message with the notes added where the model will read them. */
function withNotes(msg: any, notes: string[]): any {
  const text = notes.map((n) => `Note: ${n}`).join("\n");
  if (typeof msg.content === "string") return { ...msg, content: msg.content + "\n\n" + text };
  if (msg.role !== "tool") return { ...msg, content: [...msg.content, { type: "text", text }] };
  // a tool message may only hold tool results, so the note rides along inside one of them
  const content = [...msg.content];
  const i = content.findIndex((p: any) => p.type === "tool-result");
  if (i < 0) return msg;
  const out = content[i].output;
  if (out.type === "text" || out.type === "error-text") {
    content[i] = { ...content[i], output: { ...out, value: out.value + "\n\n" + text } };
  } else if (out.type === "content") {
    content[i] = { ...content[i], output: { ...out, value: [...out.value, { type: "text", text }] } };
  } else if (out.type === "json" || out.type === "error-json") {
    content[i] = { ...content[i], output: { type: out.type === "json" ? "text" : "error-text", value: JSON.stringify(out.value) + "\n\n" + text } };
  }
  return { ...msg, content };
}

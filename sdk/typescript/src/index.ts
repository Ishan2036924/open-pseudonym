// Open Pseudonym: keep personal data away from AI models without making them worse at the task.
//
// The short version:
//
//     import { Session, Source } from "open-pseudonym";
//     const s = new Session("draft_reply");
//     const masked = s.mask(text);           // what the model may see
//     const reply = s.restore(modelReply);   // what the person reads

export { Drbg } from "./drbg.ts";
export { EgressLeak, EgressLog, verifyLog, type Leak, type LogReport } from "./egress.ts";
export { FF1 } from "./fpe.ts";
export { HandleRefused, Sink, Source, type SinkLike, type SourceLike } from "./handles.ts";
export { canonical, digest } from "./jcs.ts";
export { Signer, SignatureError, publicKeyFromPem, publicPem, verify } from "./jws.ts";
export { LEVELS, Policy, PolicyError, Rule, loadLevel, loadProfile, profileNames, suggestProfile } from "./policy.ts";
export {
  RefusedData, Session, type Approve, type Masked, type Replacement, type Resolved, type SessionOptions,
} from "./session.ts";
export { StreamRestorer } from "./restore.ts";
export { Vault, VaultError } from "./vault.ts";
export type { Detector, Span } from "./detect.ts";

export const VERSION = "0.1.0";

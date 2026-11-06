# Changelog

## 0.1.0 (unreleased)

- Specification v0.1: detection, task policies, stand-ins, the vault, restoring, secret handles, egress receipts,
  HTTP proxy and MCP bindings, conformance levels.
- Python SDK: core, local proxy (OpenAI Chat Completions, OpenAI Responses, Anthropic Messages, streaming), MCP
  middleware and gateway, Playwright handle filler, ML detector adapters (GLiNER, spaCy, Presidio), `opn` command.
- TypeScript SDK: core and Vercel AI SDK middleware.
- Shared test vectors, JSON schemas, offline benchmark.

### Fixed before the first release (two independent security reviews)

- Secret handles fail closed: a handle with no site or tool binding is never filled. Handles bind to the exact host
  of their source (a `*.example.com` policy entry opts in to subdomains); cards and bank details ask the person first.
- Tightening a policy keeps every handle limit (uses, ttl, ask, sites, tools). Text can only shorten a code's
  lifetime, never extend it; "expires in 0 minutes" is expired.
- The proxy masks the whole request body (documents, names, metadata, tool descriptions), twice, and leaves signed
  reasoning untouched. The egress check also re-runs detection over every string and key, so data in a field masking
  skipped stops the request. MCP masks resources and prompts and checks every result.
- Known names match in any case and across any whitespace; short codes are hidden again when history is re-sent; a
  real value that equals an earlier fake is masked; name slugs in links are hidden.
- `verify` reports missing payloads, payloads without receipts, missing logs and receipts from another session, never
  crashes on a bad line, and accepts an outside anchor (`--expect-count`, `--expect-last`) for cut-off tails.
- Shared hosting suffixes (github.io and others) are never a binding; URLs are read the way browsers read them.
- Fake-name pools no longer contain ordinary words; the email pattern is length-bounded (no slow inputs).
- Levels 1 to 3 (`load_level`, `LEVELS`) for products that offer people a simple switch.

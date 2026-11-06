# Contributing

Thank you for helping. The rule that keeps this project honest: every behaviour is written down in the spec, pinned
by a vector, and implemented the same way in both SDKs.

## Run everything

```
tools/check_all.sh            # PYTHON=/path/to/python to choose an interpreter
```

Python needs `cryptography` and `pytest` (plus `jsonschema`, and the extras for the parts you touch). TypeScript needs
Node 23.6 or newer.

## How a change lands

1. **Spec first.** Say in `spec/open-pseudonym.md` what an implementation must do.
2. **Data next.** Patterns live in `tools/make_patterns.py` (it writes `data/patterns.json`); pools and profiles in
   `data/`. Run `python tools/sync_data.py` to copy them into both SDKs.
3. **Vectors.** Add cases to `tools/make_vectors.py`. Hand-write the expected answer wherever a person can work it
   out; for recorded cases, add an assertion that a person checked. Run it.
4. **Both SDKs.** Implement in `sdk/python` and `sdk/typescript`; both must pass every vector.
5. **Prove the check matters.** A new safety check needs a test with a planted defect that the check catches (a real
   value slipped into a payload, a handle aimed at the wrong site).
6. **Changelog.** One line in `CHANGELOG.md`.

## Rules of thumb

- Fakes come from reserved or fictional ranges and are drawn at random, never computed from the real value.
- Nothing the model writes may set a policy, a source, a sink, or approve a handle.
- Never log a real value. Errors name types, not values.
- Keep the core free of new dependencies (Python: `cryptography` only; TypeScript: none).
- Test data is fictional. Use neutral, varied names and never real people, schools or employers.
- Write for people: plain words, comments that say why, no decorative punctuation.

By contributing you agree that code is licensed under Apache-2.0 and spec text under CC BY 4.0 (see `NOTICE`).
Be kind and constructive; we follow the [Contributor Covenant 2.1](https://www.contributor-covenant.org/version/2/1/code_of_conduct/).

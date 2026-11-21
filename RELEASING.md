# Releasing

Pushing a tag `vX.Y.Z` runs `.github/workflows/release.yml`, which publishes one package per registry, both named
`open-pseudonym`:

| Registry | Install | Parts |
|---|---|---|
| PyPI | `pip install open-pseudonym` | core; `[proxy]`, `[mcp]`, `[browser]`, `[openai]`, `[anthropic]`, `[all]` |
| npm | `npm install open-pseudonym` | core; `open-pseudonym/vercel-ai` |

No password or token is stored anywhere. PyPI and npm trust this repository's `release.yml` directly ("trusted
publishing"). PyPI publishes at once; npm only stages the version, and it goes live when a maintainer approves it.

## One-time setup (maintainer)

1. PyPI: at <https://pypi.org/manage/account/publishing/> add a pending publisher: project `open-pseudonym`, owner
   `Ishan2036924`, repository `open-pseudonym`, workflow `release.yml`, environment `pypi`.
2. npm: publish the first version by hand from `sdk/typescript` (`npm login`, `npm ci --ignore-scripts`,
   `npm run build`, `npm publish --access public --provenance=false`), then on npmjs.com set Settings, Trusted
   Publisher, GitHub Actions: user `Ishan2036924`, repository `open-pseudonym`, workflow `release.yml`, environment
   `npm`, with publishing left to staging only.
3. GitHub: give the `pypi` and `npm` environments a required reviewer.

## Each release

1. Bump the version in `sdk/python/pyproject.toml`, `open_pseudonym.__version__`, `sdk/typescript/package.json` and
   the TypeScript `VERSION`; date the changelog section.
2. Push to `main` and wait for CI to pass.
3. `git tag vX.Y.Z && git push origin vX.Y.Z`
4. Approve the staged npm version on npmjs.com.
5. Publish the GitHub release page for the tag (its notes are the version's changelog section). Publishing it runs
   `.github/workflows/sign-release.yml`, which attaches the exact published files (PyPI wheel and sdist, npm tarball)
   to the page, each with a Sigstore bundle (`<file>.sigstore.json`). It downloads them from PyPI and npm and checks
   them against the registries' own digests first (`tools/fetch_published.py`); nothing is rebuilt. If npm was not
   approved yet, it signs the PyPI files and warns: after approving, open **Actions → sign-release → Run workflow** with
   the tag (for example `v0.3.0`). The same button backfills an older release.

## Checking a signed file

```
python -m pip install sigstore
python -m sigstore verify github --cert-identity \
  https://github.com/Ishan2036924/open-pseudonym/.github/workflows/sign-release.yml@refs/tags/vX.Y.Z \
  open_pseudonym-X.Y.Z-py3-none-any.whl
```

For a file signed by a hand run of sign-release, the identity ends in `@refs/heads/main` instead.

## CI dependencies

CI and the release build install Python packages only from hash-locked files in `ci/` (`pip install --require-hashes`),
and the SDK itself from a locally built wheel with `--no-deps`. Each `ci/*.in` names what a job needs; its `.txt` is the
lock, made with the command in the `.in` header (`uv pip compile --universal --python-version 3.10 --generate-hashes`,
so one file serves Python 3.10 to 3.13). Dependabot keeps them current. `tools/check_ci_locks.py` fails CI when a lock
lacks hashes, when a `.in` misses an SDK dependency or extra its job tests, or when a workflow installs anything else.

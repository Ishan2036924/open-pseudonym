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

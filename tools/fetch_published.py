"""Download the exact files a release published to PyPI and npm, and check each against the registry's own digest.

Used by .github/workflows/sign-release.yml, which signs these bytes (never a rebuild) and attaches them to the
GitHub release. Standard library only.

    python tools/fetch_published.py 0.5.1 OUT_DIR           # PyPI wheel + sdist, and the npm tarball
    python tools/fetch_published.py 0.5.1 OUT_DIR --pypi-only

Exit 0: every file downloaded and matched. Exit 1: a digest mismatch, a missing file or an unexpected host.
Exit 3: the npm version is not live yet (staged, waiting for approval); the PyPI files are still in OUT_DIR.
"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

PACKAGE = "open-pseudonym"
PYPI_JSON = "https://pypi.org/pypi/{name}/{version}/json"
NPM_JSON = "https://registry.npmjs.org/{name}/{version}"
PYPI_FILES_HOST = "https://files.pythonhosted.org/"
NPM_TARBALL_PREFIX = "https://registry.npmjs.org/{name}/-/"
NOT_LIVE = 3


class FetchError(Exception):
    pass


class NotLive(FetchError):
    pass


def _get(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "release-signing"})
    with urllib.request.urlopen(req, timeout=60) as resp:  # noqa: S310 (https URLs built above)
        return resp.read()


def _get_json(url: str, *, attempts: int = 6, wait: float = 10.0) -> dict | None:
    """The registry's JSON for one version; None after `attempts` 404s (a fresh upload can lag behind the CDN)."""
    for i in range(attempts):
        try:
            return json.loads(_get(url))
        except urllib.error.HTTPError as e:
            if e.code != 404:
                raise
            if i + 1 < attempts:
                time.sleep(wait)
    return None


def _safe_name(name: str) -> str:
    if not name or "/" in name or "\\" in name or name.startswith("."):
        raise FetchError(f"unsafe file name from the registry: {name!r}")
    return name


def pypi_files(meta: dict, name: str, version: str) -> list[tuple[str, str, str]]:
    """(filename, url, sha256) for every file of this version; refuses anything off files.pythonhosted.org."""
    if meta.get("info", {}).get("version") != version:
        raise FetchError(f"PyPI answered for {meta.get('info', {}).get('version')!r}, not {version!r}")
    out = []
    for u in meta.get("urls", []):
        url, sha = u.get("url", ""), u.get("digests", {}).get("sha256", "")
        if not url.startswith(PYPI_FILES_HOST):
            raise FetchError(f"PyPI file outside {PYPI_FILES_HOST}: {url}")
        if len(sha) != 64:
            raise FetchError(f"PyPI gave no sha256 for {u.get('filename')}")
        out.append((_safe_name(u["filename"]), url, sha))
    kinds = {f.rsplit(".", 1)[-1] for f, _, _ in out}
    if not out or "whl" not in kinds or "gz" not in kinds:
        raise FetchError(f"PyPI {name} {version}: expected a wheel and an sdist, got {[f for f, _, _ in out]}")
    return out


def npm_file(meta: dict, name: str, version: str) -> tuple[str, str, str, str]:
    """(filename, url, sha512 integrity, sha1 shasum) of the published tarball."""
    if meta.get("version") != version or meta.get("name") != name:
        raise FetchError(f"npm answered for {meta.get('name')}@{meta.get('version')}, not {name}@{version}")
    dist = meta.get("dist", {})
    url, integrity, shasum = dist.get("tarball", ""), dist.get("integrity", ""), dist.get("shasum", "")
    if not url.startswith(NPM_TARBALL_PREFIX.format(name=name)):
        raise FetchError(f"npm tarball outside the registry: {url}")
    if not integrity.startswith("sha512-") or len(shasum) != 40:
        raise FetchError(f"npm gave no sha512 integrity or sha1 shasum for {name}@{version}")
    return _safe_name(url.rsplit("/", 1)[-1]), url, integrity, shasum


def check_pypi(data: bytes, sha256: str, filename: str) -> None:
    got = hashlib.sha256(data).hexdigest()
    if got != sha256:
        raise FetchError(f"{filename}: sha256 {got} does not match PyPI's {sha256}")


def check_npm(data: bytes, integrity: str, shasum: str, filename: str) -> None:
    got512 = "sha512-" + base64.b64encode(hashlib.sha512(data).digest()).decode()
    if got512 != integrity:
        raise FetchError(f"{filename}: {got512} does not match npm's integrity {integrity}")
    got1 = hashlib.sha1(data).hexdigest()  # noqa: S324 (npm's own shasum field; sha512 above is the real check)
    if got1 != shasum:
        raise FetchError(f"{filename}: sha1 {got1} does not match npm's shasum {shasum}")


def fetch(
    version: str, out: Path, *, name: str = PACKAGE, npm: bool = True, get=_get, get_json=_get_json, log=print
) -> list[Path]:
    out.mkdir(parents=True, exist_ok=True)
    written: list[Path] = []

    meta = get_json(PYPI_JSON.format(name=name, version=version))
    if meta is None:
        raise FetchError(f"{name} {version} is not on PyPI")
    for filename, url, sha in pypi_files(meta, name, version):
        data = get(url)
        check_pypi(data, sha, filename)
        (out / filename).write_bytes(data)
        written.append(out / filename)
        log(f"ok  {filename}  sha256 {sha}")

    if npm:
        meta = get_json(NPM_JSON.format(name=name, version=version), attempts=1)
        if meta is None:
            raise NotLive(f"{name}@{version} is not live on npm yet (approve the staged version, then run again)")
        filename, url, integrity, shasum = npm_file(meta, name, version)
        data = get(url)
        check_npm(data, integrity, shasum, filename)
        (out / filename).write_bytes(data)
        written.append(out / filename)
        log(f"ok  {filename}  {integrity}  sha256 {hashlib.sha256(data).hexdigest()}")
    return written


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    p.add_argument("version", help="X.Y.Z (a leading v is dropped)")
    p.add_argument("out", type=Path)
    p.add_argument("--pypi-only", action="store_true")
    a = p.parse_args(argv)
    try:
        fetch(a.version.removeprefix("v"), a.out, npm=not a.pypi_only)
    except NotLive as e:
        print(f"not live: {e}", file=sys.stderr)
        return NOT_LIVE
    except FetchError as e:
        print(f"refused: {e}", file=sys.stderr)
        return 1
    except (urllib.error.URLError, OSError, ValueError) as e:  # network, disk, or JSON the registry should not send
        print(f"failed: {type(e).__name__}: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

"""Tests for tools/fetch_published.py (offline, fake registry): python tools/test_fetch_published.py"""

from __future__ import annotations

import base64
import hashlib
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tools"))
import fetch_published as fp  # noqa: E402

NAME, VERSION = fp.PACKAGE, "1.2.3"
WHEEL, SDIST, TGZ = b"wheel bytes", b"sdist bytes", b"npm tarball bytes"
WHEEL_URL = "https://files.pythonhosted.org/packages/aa/x.whl"
SDIST_URL = "https://files.pythonhosted.org/packages/bb/x.tar.gz"
TGZ_NAME = f"{NAME}-{VERSION}.tgz"
TGZ_URL = f"https://registry.npmjs.org/{NAME}/-/{TGZ_NAME}"


def pypi_meta(**over):
    files = [
        {"filename": f"x-{VERSION}-py3-none-any.whl", "url": WHEEL_URL, "digests": {"sha256": hashlib.sha256(WHEEL).hexdigest()}},
        {"filename": f"x-{VERSION}.tar.gz", "url": SDIST_URL, "digests": {"sha256": hashlib.sha256(SDIST).hexdigest()}},
    ]
    meta = {"info": {"version": VERSION}, "urls": files}
    meta.update(over)
    return meta


def npm_meta(**dist_over):
    dist = {
        "tarball": TGZ_URL,
        "integrity": "sha512-" + base64.b64encode(hashlib.sha512(TGZ).digest()).decode(),
        "shasum": hashlib.sha1(TGZ).hexdigest(),  # noqa: S324
    }
    dist.update(dist_over)
    return {"name": NAME, "version": VERSION, "dist": dist}


class Registry:
    def __init__(self, pypi=None, npm=None, blobs=None):
        self.pypi = pypi_meta() if pypi is None else pypi
        self.npm = npm_meta() if npm is None else npm
        self.blobs = {WHEEL_URL: WHEEL, SDIST_URL: SDIST, TGZ_URL: TGZ} if blobs is None else blobs

    def get_json(self, url, **_):
        if url.startswith("https://pypi.org/"):
            return self.pypi
        return self.npm or None

    def get(self, url):
        return self.blobs[url]


class FetchTests(unittest.TestCase):
    def run_fetch(self, reg, **kw):
        out = Path(tempfile.mkdtemp())
        return out, fp.fetch(VERSION, out, get=reg.get, get_json=reg.get_json, log=lambda _: None, **kw)

    def test_all_three_files_written_byte_for_byte(self):
        out, written = self.run_fetch(Registry())
        self.assertEqual(sorted(p.read_bytes() for p in written), sorted([WHEEL, SDIST, TGZ]))
        self.assertTrue((out / TGZ_NAME).exists())

    def test_tampered_pypi_file_is_refused(self):
        reg = Registry(blobs={WHEEL_URL: b"evil", SDIST_URL: SDIST, TGZ_URL: TGZ})
        with self.assertRaisesRegex(fp.FetchError, "sha256"):
            self.run_fetch(reg)

    def test_tampered_npm_tarball_is_refused(self):
        reg = Registry(blobs={WHEEL_URL: WHEEL, SDIST_URL: SDIST, TGZ_URL: b"evil"})
        with self.assertRaisesRegex(fp.FetchError, "integrity"):
            self.run_fetch(reg)

    def test_npm_sha1_mismatch_is_refused(self):
        with self.assertRaisesRegex(fp.FetchError, "shasum"):
            self.run_fetch(Registry(npm=npm_meta(shasum="0" * 40)))

    def test_files_off_the_registry_hosts_are_refused(self):
        meta = pypi_meta()
        meta["urls"][0]["url"] = "https://evil.example/x.whl"
        with self.assertRaisesRegex(fp.FetchError, "outside"):
            self.run_fetch(Registry(pypi=meta))
        with self.assertRaisesRegex(fp.FetchError, "outside"):
            self.run_fetch(Registry(npm=npm_meta(tarball="https://evil.example/x.tgz")))

    def test_path_in_a_file_name_is_refused(self):
        meta = pypi_meta()
        meta["urls"][0]["filename"] = "../x.whl"
        with self.assertRaisesRegex(fp.FetchError, "unsafe"):
            self.run_fetch(Registry(pypi=meta))

    def test_wrong_version_or_missing_sdist_is_refused(self):
        with self.assertRaisesRegex(fp.FetchError, "not"):
            self.run_fetch(Registry(pypi=pypi_meta(info={"version": "9.9.9"})))
        meta = pypi_meta()
        meta["urls"] = meta["urls"][:1]
        with self.assertRaisesRegex(fp.FetchError, "wheel and an sdist"):
            self.run_fetch(Registry(pypi=meta))

    def test_staged_npm_version_is_not_live_but_pypi_files_stay(self):
        reg = Registry(npm={})
        out = Path(tempfile.mkdtemp())
        with self.assertRaises(fp.NotLive):
            fp.fetch(VERSION, out, get=reg.get, get_json=reg.get_json, log=lambda _: None)
        self.assertEqual(len(list(out.iterdir())), 2)

    def test_pypi_only_skips_npm(self):
        _, written = self.run_fetch(Registry(npm={}), npm=False)
        self.assertEqual(len(written), 2)


if __name__ == "__main__":
    unittest.main()

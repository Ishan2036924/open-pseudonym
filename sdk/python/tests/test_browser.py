"""The browser filler against real Chromium and a local test site on *.localhost names."""

import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

pytest.importorskip("playwright")

from playwright.async_api import async_playwright  # noqa: E402

from open_pseudonym import HandleRefused, Session, Source, Vault  # noqa: E402
from open_pseudonym.browser import HandleFiller  # noqa: E402

PAGES = {
    "/mail": "<p>From: no-reply@acme.localhost</p><p>Your Acme verification code is 482913.</p>",
    "/login": "<form><input id='code' name='code'><button>Go</button></form>",
    "/echo": "<input id='code' oninput=\"document.getElementById('out').textContent=this.value\"><p id='out'></p>",
}


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        body = PAGES.get(self.path.split("?")[0], "not found").encode()
        self.send_response(200)
        self.send_header("content-type", "text/html")
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


@pytest.fixture(scope="module")
def port():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


@pytest.fixture
async def browser():
    async with async_playwright() as p:
        try:
            b = await p.chromium.launch(args=["--host-resolver-rules=MAP *.localhost 127.0.0.1"])
        except Exception as exc:  # no browser installed on this machine
            pytest.skip(f"chromium not available: {exc}")
        yield b
        await b.close()


async def otp_on_page(browser, port, s):
    page = await browser.new_page()
    await page.goto(f"http://mail.localhost:{port}/mail")
    text = await HandleFiller(s).read(page, Source(sender="no-reply@acme.localhost"))
    assert "482913" not in text and "{{OTP_1}}" in text
    return page


@pytest.mark.anyio
async def test_fills_on_the_right_site(browser, port):
    s = Session("browse_and_fill", Vault(seed=bytes(32)))
    await otp_on_page(browser, port, s)
    page = await browser.new_page()
    await page.goto(f"http://acme.localhost:{port}/login")
    filler = HandleFiller(s)
    await filler.fill(page.locator("#code"), "{{OTP_1}}")
    assert await page.locator("#code").input_value() == "482913"
    shot = await filler.screenshot(page)
    assert shot[:8] == b"\x89PNG\r\n\x1a\n"


@pytest.mark.anyio
async def test_refuses_another_site_and_types_nothing(browser, port):
    s = Session("browse_and_fill", Vault(seed=bytes(32)))
    await otp_on_page(browser, port, s)
    page = await browser.new_page()
    await page.goto(f"http://evil.localhost:{port}/login")
    with pytest.raises(HandleRefused, match="bound to a different site"):
        await HandleFiller(s).fill(page.locator("#code"), "{{OTP_1}}")
    assert await page.locator("#code").input_value() == ""


@pytest.mark.anyio
async def test_a_page_that_echoes_the_value_gets_it_cleared(browser, port):
    s = Session("browse_and_fill", Vault(seed=bytes(32)))
    await otp_on_page(browser, port, s)
    page = await browser.new_page()
    await page.goto(f"http://acme.localhost:{port}/echo")
    with pytest.raises(HandleRefused, match="visible"):
        await HandleFiller(s).fill(page.locator("#code"), "{{OTP_1}}")
    assert await page.locator("#code").input_value() == ""

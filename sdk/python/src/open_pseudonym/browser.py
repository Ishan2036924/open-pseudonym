"""Filling secret handles in a real browser (Playwright), only on the site they belong to.

    filler = HandleFiller(session)
    text = await filler.read(page)                 # what the model may see of this page
    await filler.fill(page.locator("#code"), "{{OTP_1}}")
    shot = await filler.screenshot(page)           # filled fields are blacked out

The site check uses the URL of the frame that holds the field, read from the browser itself, so an injected
instruction cannot talk its way past it. After filling we check that the value is not showing anywhere in the page
text; if it is, the field is cleared and the fill is refused. Needs the [browser] extra.
"""

from __future__ import annotations

try:
    from playwright.async_api import Locator, Page
except ImportError as e:  # the optional dependency is not installed
    raise ImportError('open_pseudonym.browser needs Playwright: pip install "open-pseudonym[browser]"') from e

from .handles import HandleRefused, Sink, Source
from .session import Session

TOOL = "browser_type"


class HandleFiller:
    def __init__(self, session: Session, tool: str = TOOL):
        self.session = session
        self.tool = tool
        self._filled: list[Locator] = []

    async def read(self, page: Page, source: Source | None = None) -> str:
        """The page's visible text, masked. Secrets found on the page get handles bound to the page's own site."""
        text = await page.inner_text("body")
        return self.session.mask(text, source or Source(site=page.url)).text

    async def fill(self, field: Locator, handle: str) -> None:
        """Put the real value behind `handle` into `field`, if the field's frame is on an allowed site."""
        frame_url = await field.evaluate("el => el.ownerDocument.location.href")
        real = self.session.resolve_args({"value": handle}, Sink(tool=self.tool, site=frame_url)).args["value"]
        await field.fill(real)
        if await self._showing(field.page, real):
            await field.fill("")
            raise HandleRefused(handle, "the value became visible on the page")
        self._filled.append(field)

    @staticmethod
    async def _showing(page: Page, real: str) -> bool:
        for frame in page.frames:
            try:
                if real in await frame.inner_text("body"):
                    return True
            except Exception:  # a frame that went away or has no body cannot be showing anything
                continue
        return False

    async def screenshot(self, page: Page, **kw) -> bytes:
        """A screenshot with every field we filled covered, so a vision model never sees the value."""
        return await page.screenshot(mask=list(self._filled), **kw)


__all__ = ["HandleFiller", "HandleRefused"]

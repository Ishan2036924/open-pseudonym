"""Just enough Server-Sent Events to read a provider's stream and write our own."""

from __future__ import annotations

from dataclasses import dataclass


@dataclass
class Event:
    data: str
    event: str | None = None

    def encode(self) -> bytes:
        head = f"event: {self.event}\n" if self.event else ""
        body = "".join(f"data: {line}\n" for line in self.data.split("\n"))
        return (head + body + "\n").encode("utf-8")


class Parser:
    """Feed it raw bytes as they arrive; it yields whole events."""

    def __init__(self):
        self._buf = ""
        self._event: str | None = None
        self._data: list[str] = []

    def feed(self, chunk: bytes) -> list[Event]:
        self._buf += chunk.decode("utf-8", errors="replace")
        out = []
        while "\n" in self._buf:
            line, self._buf = self._buf.split("\n", 1)
            line = line.rstrip("\r")
            if line == "":
                if self._data or self._event:
                    out.append(Event("\n".join(self._data), self._event))
                self._event, self._data = None, []
            elif line.startswith(":"):
                continue  # a comment, often a keep-alive
            elif line.startswith("event:"):
                self._event = line[6:].strip()
            elif line.startswith("data:"):
                self._data.append(line[5:].lstrip(" ") if line[5:6] == " " else line[5:])
        return out

    def close(self) -> list[Event]:
        if self._data or self._event:
            ev = Event("\n".join(self._data), self._event)
            self._event, self._data = None, []
            return [ev]
        return []

"""Optional ML detectors. Patterns are good at shapes (cards, emails); names need a model or a list.

Each adapter turns a model's output into our Spans. The libraries are imported only when you build an adapter, so
the core stays at one dependency. Priority 30 means a pattern or a known value wins when they overlap.

    from gliner import GLiNER
    s = Session("strict", detectors=[GlinerDetector(GLiNER.from_pretrained("urchade/gliner_multi_pii-v1"))])

Licences differ between models (urchade/gliner_multi_pii-v1 is Apache-2.0; check any other model before shipping).
"""

from __future__ import annotations

from typing import Any, Iterable

from .detect import Span

ML_PRIORITY = 30

# Model labels -> our types. Anything not listed is ignored rather than guessed.
LABELS = {
    "person": "PERSON", "per": "PERSON", "name": "PERSON", "full name": "PERSON",
    "organization": "ORG", "org": "ORG", "company": "ORG",
    "location": "LOCATION", "loc": "LOCATION", "gpe": "LOCATION", "city": "LOCATION", "country": "LOCATION",
    "address": "ADDRESS", "street address": "ADDRESS",
    "email": "EMAIL", "email address": "EMAIL", "email_address": "EMAIL",
    "phone number": "PHONE", "phone_number": "PHONE", "phone": "PHONE",
    "date": "DATE", "date of birth": "DATE", "date_time": "DATE",
    "credit card number": "CARD", "credit_card": "CARD",
    "iban": "IBAN", "iban_code": "IBAN", "bank account number": "BANK_ACCOUNT",
    "social security number": "SSN", "us_ssn": "SSN", "ssn": "SSN",
    "ip address": "IP_ADDRESS", "ip_address": "IP_ADDRESS",
    "url": "URL", "password": "PASSWORD", "api key": "API_KEY",
}


def _span(text: str, start: int, end: int, label: str, source: str) -> Span | None:
    key = label.lower()
    type_ = LABELS.get(key) or LABELS.get(key.replace("_", " "))
    if type_ is None or start >= end:
        return None
    return Span(start, end, type_, text[start:end], source, ML_PRIORITY)


class GlinerDetector:
    """GLiNER zero-shot NER (pip install gliner). `labels` are the entity names asked of the model."""

    name = "gliner"

    def __init__(self, model: Any, labels: Iterable[str] = ("person", "organization", "location", "address"),
                 threshold: float = 0.5):
        self.model, self.labels, self.threshold = model, list(labels), threshold

    def detect(self, text: str) -> list[Span]:
        out = []
        for e in self.model.predict_entities(text, self.labels, threshold=self.threshold):
            s = _span(text, int(e["start"]), int(e["end"]), e["label"], self.name)
            if s:
                out.append(s)
        return out


class SpacyDetector:
    """A spaCy pipeline with an NER component (pip install spacy, then a model such as en_core_web_sm)."""

    name = "spacy"

    def __init__(self, nlp: Any, labels: Iterable[str] = ("PERSON", "ORG", "GPE", "LOC")):
        self.nlp, self.labels = nlp, {lab.upper() for lab in labels}

    def detect(self, text: str) -> list[Span]:
        out = []
        for ent in self.nlp(text).ents:
            if ent.label_.upper() in self.labels:
                s = _span(text, ent.start_char, ent.end_char, ent.label_, self.name)
                if s:
                    out.append(s)
        return out


class PresidioDetector:
    """Microsoft Presidio's AnalyzerEngine (pip install presidio-analyzer)."""

    name = "presidio"

    def __init__(self, analyzer: Any, language: str = "en", score_threshold: float = 0.5):
        self.analyzer, self.language, self.threshold = analyzer, language, score_threshold

    def detect(self, text: str) -> list[Span]:
        out = []
        for r in self.analyzer.analyze(text=text, language=self.language, score_threshold=self.threshold):
            s = _span(text, r.start, r.end, r.entity_type, self.name)
            if s:
                out.append(s)
        return out


__all__ = ["GlinerDetector", "PresidioDetector", "SpacyDetector", "LABELS", "ML_PRIORITY"]

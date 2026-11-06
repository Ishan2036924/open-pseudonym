"""The ML adapters, with small stand-in models that answer the way the real libraries do."""

from types import SimpleNamespace

from open_pseudonym import Session, Vault
from open_pseudonym.ml import GlinerDetector, PresidioDetector, SpacyDetector

TEXT = "lunch with priya raman at the Lisbon office of Northwind next week"


class FakeGliner:
    def predict_entities(self, text, labels, threshold=0.5):
        out = []
        for word, label in [("priya raman", "person"), ("Lisbon", "location"), ("Northwind", "organization")]:
            i = text.find(word)
            out.append({"start": i, "end": i + len(word), "text": word, "label": label, "score": 0.9})
        return out


class FakeSpacy:
    def __call__(self, text):
        i = text.find("priya raman")
        return SimpleNamespace(ents=[SimpleNamespace(start_char=i, end_char=i + 11, label_="PERSON")])


class FakePresidio:
    def analyze(self, text, language, score_threshold):
        i = text.find("Lisbon")
        return [SimpleNamespace(entity_type="LOCATION", start=i, end=i + 6, score=0.8)]


def test_gliner_finds_lower_case_names_the_patterns_miss():
    plain = Session("strict", Vault(seed=bytes(32)))
    assert not plain.detect(TEXT)
    s = Session("strict", Vault(seed=bytes(32)), detectors=[GlinerDetector(FakeGliner())])
    assert [(sp.type, sp.text) for sp in s.detect(TEXT)] == [
        ("PERSON", "priya raman"), ("LOCATION", "Lisbon"), ("ORG", "Northwind")]
    masked = s.mask(TEXT).text
    assert "priya" not in masked and "Lisbon" not in masked
    assert s.restore(masked) == TEXT
    assert "gliner" in s.detector_names()


def test_spacy_and_presidio_adapters():
    s = Session("strict", detectors=[SpacyDetector(FakeSpacy()), PresidioDetector(FakePresidio())])
    assert {(sp.type, sp.text) for sp in s.detect(TEXT)} == {("PERSON", "priya raman"), ("LOCATION", "Lisbon")}

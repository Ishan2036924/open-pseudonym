"""The opn command: keys, batch masking with one vault across files, restore, verify."""

import os
import stat

from open_pseudonym import EgressLog, Session, Signer, Vault
from open_pseudonym.cli import main


def test_keygen_mask_restore_verify(tmp_path, capsys):
    keys = tmp_path / "keys"
    assert main(["--key-dir", str(keys), "keygen"]) == 0
    assert stat.S_IMODE(os.stat(keys / "vault.key").st_mode) == 0o600
    assert stat.S_IMODE(os.stat(keys / "signing.pem").st_mode) == 0o600
    out = capsys.readouterr().out
    assert "created" in out and "BEGIN" not in out  # keys are never printed

    a, b = tmp_path / "a.txt", tmp_path / "b.txt"
    a.write_text("Patient: Elena Ortiz, elena.ortiz@example.org")
    b.write_text("Follow-up for Elena Ortiz next week.")
    vault = tmp_path / "data.vault"
    masked = tmp_path / "masked"
    assert main(["--key-dir", str(keys), "mask", "--vault", str(vault), "--out-dir", str(masked), str(a), str(b)]) == 0
    ma, mb = (masked / "a.txt").read_text(), (masked / "b.txt").read_text()
    fake = ma.split("Patient: ")[1].split(",")[0]
    assert "Elena" not in ma + mb and fake in mb  # the same person gets the same fake in both files

    capsys.readouterr()
    assert main(["--key-dir", str(keys), "restore", "--vault", str(vault), str(masked / "b.txt")]) == 0
    assert capsys.readouterr().out == "Follow-up for Elena Ortiz next week."

    signer = Signer.from_pem((keys / "signing.pem").read_bytes())
    s = Session("strict", Vault.load(vault, (keys / "vault.key").read_bytes()))
    log = EgressLog(tmp_path / "log", signer)
    s.record_egress(log, s.mask("Elena Ortiz says hi").text.encode(), "api.example.com")
    assert main(["--key-dir", str(keys), "verify", str(tmp_path / "log"), "--vault", str(vault)]) == 0
    (tmp_path / "log" / "payloads" / "000001.bin").write_bytes(b"Elena Ortiz says hi")
    assert main(["--key-dir", str(keys), "verify", str(tmp_path / "log"), "--vault", str(vault)]) == 1
    assert "does not match its digest" in capsys.readouterr().out

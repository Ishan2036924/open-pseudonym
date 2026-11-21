"""The opn command: keys, batch masking with one vault across files, restore, verify."""

import json
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


def test_checkpoint_and_verify_with_an_anchor(tmp_path, capsys):
    writer_keys, anchor_keys = tmp_path / "writer", tmp_path / "anchor"
    assert main(["--key-dir", str(writer_keys), "keygen"]) == 0
    assert main(["--key-dir", str(anchor_keys), "keygen"]) == 0
    signer = Signer.from_pem((writer_keys / "signing.pem").read_bytes())
    log = EgressLog(tmp_path / "log", signer, store_payloads=False)
    for n in range(3):
        log.record_release(session="s1", now=1793836800 + n, handle="{{OTP_1}}", data="OTP", source="acme.com",
                           sink={"tool": "type", "site": "acme.com"}, call="sha-256:" + "A" * 43, decision="allow",
                           authority={"kind": "binding"})
    capsys.readouterr()
    pub = str(writer_keys / "signing.pub.pem")
    assert main(["--key-dir", str(anchor_keys), "checkpoint", str(tmp_path / "log"), "--pub", pub]) == 0
    token = capsys.readouterr().out.strip()
    (tmp_path / "cp.txt").write_text(token + "\n")
    args = ["--key-dir", str(writer_keys), "verify", str(tmp_path / "log"), "--anchor", str(tmp_path / "cp.txt"),
            "--anchor-pub", str(anchor_keys / "signing.pub.pem")]
    assert main(args) == 0
    assert "up to record 3: complete" in capsys.readouterr().out
    lines = (tmp_path / "log" / "receipts.jsonl").read_text().splitlines()
    (tmp_path / "log" / "receipts.jsonl").write_text("\n".join(lines[:2]) + "\n")
    assert main(args) == 1
    assert "cut off after seq 2" in capsys.readouterr().out


def test_verify_checks_each_records_standing_against_the_policies_given(tmp_path, capsys):
    from open_pseudonym import load_profile

    keys = tmp_path / "keys"
    assert main(["--key-dir", str(keys), "keygen"]) == 0
    signer = Signer.from_pem((keys / "signing.pem").read_bytes())
    log = EgressLog(tmp_path / "log", signer, store_payloads=False)
    log.record_release(session="s1", now=1793836800, handle="{{OTP_1}}", data="OTP", source="acme.com",
                       sink={"tool": "type", "site": "acme.com"}, call="sha-256:" + "A" * 43, decision="allow",
                       authority={"kind": "binding", "rule": "/rules/OTP",
                                  "policy": load_profile("browse_and_fill").digest})
    base = ["--key-dir", str(keys), "verify", str(tmp_path / "log")]
    assert main(base + ["--policy", "browse_and_fill"]) == 0
    (tmp_path / "p.json").write_text(json.dumps(load_profile("browse_and_fill").to_dict()))
    assert main(base + ["--policy", str(tmp_path / "p.json")]) == 0
    capsys.readouterr()
    assert main(base + ["--policy", "strict"]) == 1
    assert "authority.policy is not the digest of any policy given" in capsys.readouterr().out

"""The `opn` command.

  opn profiles                                  list the starter profiles
  opn keygen                                    make a vault key and a receipt signing key (owner-only files)
  opn mask --profile training_data a.txt b.txt  mask files with one shared vault (fakes stay consistent)
  opn restore masked.txt                        put real values back (needs the same vault and key)
  opn verify LOGDIR                             check a folder of receipts: signatures, chain, digests, leaks
  opn proxy --profile draft_reply               run the local proxy on 127.0.0.1:8787
  opn mcp-gateway --profile browse_and_fill --source-site acme.com --tool-site type=https://acme.com -- <command>
  opn demo                                      see what the model would see for a sample email
  opn conformance vectors/                      run the shared test vectors

Keys live in ~/.config/open-pseudonym unless you say otherwise. They are never printed.
"""

from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

from . import __version__
from .handles import Source
from .jws import Signer, public_key_from_pem, public_pem
from .policy import LEVELS, load_profile, profile_names
from .session import Session
from .vault import Vault

DEMO = """From: Dana Reyes <dana.reyes@gmail.com>
Hi Sam,

Can we move Thursday's call to March 12, 2026? Call me at (617) 555-0142.
Your Acme verification code is 482913. It expires in 10 minutes.

Thanks,
Dana"""


def key_dir(args) -> Path:
    if getattr(args, "key_dir", None):
        return Path(args.key_dir)
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.join(os.path.expanduser("~"), ".config")
    return Path(base) / "open-pseudonym"


def _write_private(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(data)


def cmd_keygen(args) -> int:
    d = key_dir(args)
    made = []
    if not (d / "vault.key").exists():
        _write_private(d / "vault.key", os.urandom(32))
        made.append("vault.key")
    if not (d / "signing.pem").exists():
        signer = Signer.generate()
        _write_private(d / "signing.pem", signer.to_pem())
        (d / "signing.pub.pem").write_bytes(public_pem(signer.public_key))
        made.append("signing.pem")
    print(f"keys in {d}: " + (", ".join(made) + " created" if made else "already there, nothing changed"))
    return 0


def load_vault_key(args) -> bytes:
    path = Path(args.key_file) if args.key_file else key_dir(args) / "vault.key"
    if not path.exists():
        sys.exit(f"no vault key at {path}; run `opn keygen` first")
    key = path.read_bytes()
    if len(key) != 32:
        sys.exit(f"{path} is not a 32-byte key")
    return key


def load_signer(args) -> Signer:
    path = key_dir(args) / "signing.pem"
    if not path.exists():
        sys.exit(f"no signing key at {path}; run `opn keygen` first")
    return Signer.from_pem(path.read_bytes())


def _session(args, vault: Vault | None) -> Session:
    return Session(args.profile, vault)


def _inputs(files: list[str]):
    if not files:
        yield "-", sys.stdin.read()
    for f in files:
        yield f, Path(f).read_text(encoding="utf-8")


def cmd_mask(args) -> int:
    key = load_vault_key(args)
    vault_path = Path(args.vault)
    vault = Vault.load(vault_path, key) if vault_path.exists() else Vault()
    s = _session(args, vault)
    source = Source(sender=args.source_sender, site=args.source_site) if (args.source_sender or args.source_site) else None
    for name, text in _inputs(args.files):
        m = s.mask(text, source)
        if args.out_dir and name != "-":
            out = Path(args.out_dir) / Path(name).name
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(m.text, encoding="utf-8")
        else:
            sys.stdout.write(m.text)
        for n in m.notes:
            print("note: " + n, file=sys.stderr)
    s.vault.save(vault_path, key)
    return 0


def cmd_restore(args) -> int:
    s = Session("strict", Vault.load(args.vault, load_vault_key(args)))
    for _, text in _inputs(args.files):
        sys.stdout.write(s.restore(text, reveal_handles=args.reveal))
    return 0


def cmd_verify(args) -> int:
    from .egress import verify_log

    pub_path = Path(args.pub) if args.pub else key_dir(args) / "signing.pub.pem"
    pub = public_key_from_pem(pub_path.read_bytes())
    vault = Vault.load(args.vault, load_vault_key(args)) if args.vault else None
    report = verify_log(args.logdir, pub, vault, expect_count=args.expect_count, expect_last=args.expect_last,
                        expect_session=args.expect_session)
    print(f"receipts: {report['receipts']} (last: {report['last']})")
    if vault is not None:
        print(f"payloads re-checked against the vault: {report['rechecked']}, known values found: {report['leaks']}")
    if report["problems"]:
        print("problems:")
        for p in report["problems"]:
            print("  " + p)
        return 1
    print("every receipt is signed and chained, and every stored payload matches its digest")
    if args.expect_count is None and args.expect_last is None:
        print("note: without --expect-count or --expect-last a log cut short at the end cannot be told apart")
    return 0


def cmd_proxy(args) -> int:
    try:
        import uvicorn

        from .proxy import ProxyConfig, create_app
    except ImportError:
        sys.exit('the proxy needs extra packages: pip install "open-pseudonym[proxy]"')
    fill = dict(item.split("=", 1) for item in args.fill_tool)
    cfg = ProxyConfig(
        profile=args.profile, allowed_profiles=tuple(args.allow_profile), openai_upstream=args.openai_upstream,
        anthropic_upstream=args.anthropic_upstream, log_dir=args.log_dir, signer=load_signer(args),
        vault_dir=args.vault_dir, vault_key=load_vault_key(args) if args.vault_dir else None, fill_tools=fill,
    )
    if args.host not in ("127.0.0.1", "localhost", "::1"):
        print("warning: the proxy has no login; anyone who can reach it and guess a session id can read that "
              "session's restores. Keep it on 127.0.0.1 unless something in front of it checks who is calling.",
              file=sys.stderr)
    print(f"open-pseudonym proxy on http://{args.host}:{args.port} (profile {args.profile}); "
          + (f"receipts in {args.log_dir}" if args.log_dir else "no receipts (add --log-dir to keep them)"),
          file=sys.stderr)
    uvicorn.run(create_app(cfg), host=args.host, port=args.port, log_level="warning")
    return 0


def cmd_mcp_gateway(args) -> int:
    import anyio

    try:
        from mcp import StdioServerParameters

        from .mcp import run_gateway
    except ImportError:
        sys.exit('the MCP gateway needs the MCP SDK: pip install "open-pseudonym[mcp]"')
    if not args.command:
        sys.exit("give the upstream server's command after --, for example: opn mcp-gateway -- npx some-server")
    vault = None
    if args.vault:
        key = load_vault_key(args)
        vault = Vault.load(args.vault, key) if Path(args.vault).exists() else Vault()
    s = Session(args.profile, vault)
    params = StdioServerParameters(command=args.command[0], args=args.command[1:])
    tool_sites = dict(item.split("=", 1) for item in args.tool_site)
    source = Source(site=args.source_site) if args.source_site else None
    try:
        anyio.run(lambda: run_gateway(params, s, tool_sites=tool_sites,
                                      source_for=(lambda tool, result: source) if source else None))
    finally:
        if args.vault:
            s.vault.save(args.vault, load_vault_key(args))
    return 0


def cmd_demo(args) -> int:
    s = Session(args.profile)
    m = s.mask(DEMO, Source(sender="no-reply@acme.com"))
    print("You typed:\n" + DEMO + "\n")
    print("The model sees:\n" + m.text + "\n")
    for n in m.notes:
        print("Note to the model: " + n)
    first = m.text.split("Hi ")[1].split(",")[0]
    reply = f"Sure {first}, Thursday works. I'll use {{{{OTP_1}}}} to sign in."
    print("\nThe model answers:\n" + reply)
    print("\nYou read:\n" + s.restore(reply))
    print("\nEgress check on what the model saw: " + ("clean" if not s.check_egress(m.text) else "LEAK"))
    return 0


def cmd_profiles(args) -> int:
    print("Levels (a simple switch for people):")
    for n, (name, label, text) in LEVELS.items():
        print(f"  {n}  {label:10} ({name}): {text}")
    print("\nTask profiles:")
    for name in profile_names():
        print(f"  {name:16} {load_profile(name).description}")
    return 0


def cmd_conformance(args) -> int:
    from .conformance import main as run

    return run([args.vectors])


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(prog="opn", description="Open Pseudonym: protect personal data sent to AI models.")
    p.add_argument("--version", action="version", version=f"open-pseudonym {__version__}")
    p.add_argument("--key-dir", help="where keys live (default ~/.config/open-pseudonym)")
    sub = p.add_subparsers(dest="cmd", required=True)

    sub.add_parser("profiles", help="list the starter profiles").set_defaults(fn=cmd_profiles)
    sub.add_parser("keygen", help="create a vault key and a signing key").set_defaults(fn=cmd_keygen)

    m = sub.add_parser("mask", help="mask files or stdin")
    m.add_argument("files", nargs="*")
    m.add_argument("--profile", default="training_data")
    m.add_argument("--vault", default="opn.vault", help="vault file, created if missing (default opn.vault)")
    m.add_argument("--key-file")
    m.add_argument("--out-dir")
    m.add_argument("--source-sender")
    m.add_argument("--source-site")
    m.set_defaults(fn=cmd_mask)

    r = sub.add_parser("restore", help="restore files or stdin")
    r.add_argument("files", nargs="*")
    r.add_argument("--vault", default="opn.vault")
    r.add_argument("--key-file")
    r.add_argument("--reveal", action="store_true", help="show secrets behind handles too")
    r.set_defaults(fn=cmd_restore)

    v = sub.add_parser("verify", help="verify a receipts folder")
    v.add_argument("logdir")
    v.add_argument("--pub", help="public key PEM (default: signing.pub.pem in the key folder)")
    v.add_argument("--vault", help="also re-run the egress check on stored payloads with this vault")
    v.add_argument("--key-file")
    v.add_argument("--expect-count", type=int, help="the number of requests you know were sent")
    v.add_argument("--expect-last", help="the digest of the last receipt you kept (sha-256:...)")
    v.add_argument("--expect-session", help="the session id every receipt must belong to")
    v.set_defaults(fn=cmd_verify)

    x = sub.add_parser("proxy", help="run the local proxy")
    x.add_argument("--profile", default="strict")
    x.add_argument("--allow-profile", action="append", default=[], help="profile apps may pick with x-opn-profile")
    x.add_argument("--host", default="127.0.0.1")
    x.add_argument("--port", type=int, default=8787)
    x.add_argument("--openai-upstream", default="https://api.openai.com")
    x.add_argument("--anthropic-upstream", default="https://api.anthropic.com")
    x.add_argument("--log-dir", help="write receipts (and payloads) here")
    x.add_argument("--vault-dir", help="persist session vaults here, encrypted")
    x.add_argument("--key-file")
    x.add_argument("--fill-tool", action="append", default=[], metavar="TOOL=SITE",
                   help="let the proxy fill handles for this tool, which acts on SITE")
    x.set_defaults(fn=cmd_proxy)

    g = sub.add_parser("mcp-gateway", help="put an MCP server behind Open Pseudonym (stdio)")
    g.add_argument("--profile", default="strict")
    g.add_argument("--source-site", help="secrets read through this server belong to this site (binds handles)")
    g.add_argument("--tool-site", action="append", default=[], metavar="TOOL=SITE",
                   help="this tool acts on SITE, so handles bound to SITE may be filled into it")
    g.add_argument("--vault", help="keep the vault in this file between runs")
    g.add_argument("--key-file")
    g.add_argument("command", nargs=argparse.REMAINDER)
    g.set_defaults(fn=cmd_mcp_gateway)

    d = sub.add_parser("demo", help="show masking on a sample email")
    d.add_argument("--profile", default="draft_reply")
    d.set_defaults(fn=cmd_demo)

    c = sub.add_parser("conformance", help="run the shared test vectors")
    c.add_argument("vectors")
    c.set_defaults(fn=cmd_conformance)

    args = p.parse_args(argv)
    if getattr(args, "command", None) and args.command[:1] == ["--"]:
        args.command = args.command[1:]
    return args.fn(args) or 0


if __name__ == "__main__":
    sys.exit(main())

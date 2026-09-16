"""pqcheck command line."""
import argparse
import sys

from . import __version__
from .report import render_text, render_json, exit_code


def main(argv=None):
    ap = argparse.ArgumentParser(prog="pqcheck",
                                 description="Inventory cryptographic algorithms in files, code, TLS and SSH endpoints and grade them for quantum resistance.")
    ap.add_argument("--version", action="version", version="pqcheck " + __version__)
    ap.add_argument("--json", action="store_true", help="machine-readable output")
    ap.add_argument("--no-color", action="store_true")
    ap.add_argument("--timeout", type=float, default=5.0, help="network timeout in seconds")
    ap.add_argument("--fail-on", choices=["vulnerable", "weak", "never"], default="vulnerable",
                    help="exit non-zero when the overall verdict is at least this bad (default: vulnerable)")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p = sub.add_parser("file", help="analyse cryptographic container files (PEM/DER, PGP, SSH keys, age, ZIP, 7z, LUKS, KDBX, PDF, JWT/JWK)")
    p.add_argument("paths", nargs="+")

    p = sub.add_parser("scan", help="recursive CBOM-light scan of a directory: containers + algorithm names in code/config")
    p.add_argument("paths", nargs="+")
    p.add_argument("--no-code", action="store_true", help="only look at container files, skip text grep")

    p = sub.add_parser("tls", help="probe TLS servers for ML-KEM hybrid key exchange (host[:port], default 443)")
    p.add_argument("hosts", nargs="+")

    p = sub.add_parser("ssh", help="read SSH server KEXINIT and grade kex/hostkey/cipher/MAC (host[:port], default 22)")
    p.add_argument("hosts", nargs="+")

    args = ap.parse_args(argv)
    findings = []
    if args.cmd == "file":
        from .formats import analyze_file
        for pth in args.paths:
            findings.extend(analyze_file(pth))
    elif args.cmd == "scan":
        from .codescan import scan_path
        for pth in args.paths:
            findings.extend(scan_path(pth, include_code=not args.no_code))
    elif args.cmd == "tls":
        from .tlsprobe import probe_tls
        for h in args.hosts:
            findings.extend(probe_tls(h, args.timeout))
    elif args.cmd == "ssh":
        from .sshprobe import probe_ssh
        for h in args.hosts:
            findings.extend(probe_ssh(h, args.timeout))

    if args.json:
        print(render_json(findings))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print(render_text(findings, color=color))
    return exit_code(findings, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())

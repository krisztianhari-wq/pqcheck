"""pqcheck command line."""
import argparse
import json
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
    ap.add_argument("--no-save", action="store_true", help="do not record this run in the history database")
    ap.add_argument("--db", default=None, help="history database path (default: $PQCHECK_DB or ~/.pqcheck/history.db)")
    sub = ap.add_subparsers(dest="cmd", required=True, metavar="{file,scan,tls,ssh,web,history,export,gui}")

    p = sub.add_parser("file", help="analyse cryptographic container files (PEM/DER, PGP, SSH keys, age, ZIP, 7z, LUKS, KDBX, PDF, JWT/JWK)")
    p.add_argument("paths", nargs="+")

    p = sub.add_parser("scan", help="recursive CBOM-light scan of a directory: containers + algorithm names in code/config")
    p.add_argument("paths", nargs="+")
    p.add_argument("--no-code", action="store_true", help="only look at container files, skip text grep")

    p = sub.add_parser("tls", help="probe TLS servers for ML-KEM hybrid key exchange (host[:port]; without port every open well-known TLS port is probed: 443, 8443, 465, 993, 995, 636, 4443, 9443)")
    p.add_argument("hosts", nargs="+")

    p = sub.add_parser("ssh", help="read SSH server KEXINIT and grade kex/hostkey/cipher/MAC (host[:port]; without port 22, 2222, 2200, 22222 are tried)")
    p.add_argument("hosts", nargs="+")

    p = sub.add_parser("web", help="check a website: TLS versions, forward secrecy, PQC groups, certificate chain, HSTS, third-party hosts")
    p.add_argument("urls", nargs="+")

    p = sub.add_parser("batch", help="probe every target listed in a CSV / TSV / TXT / XLSX file (columns: kind, host, port, note; see --template)")
    p.add_argument("files", nargs="*")
    p.add_argument("--template", action="store_true", help="print a template CSV and exit")
    p.add_argument("--limit", type=int, default=200, help="max rows to process (default 200)")

    p = sub.add_parser("history", help="list recorded runs (or show one with --show ID)")
    p.add_argument("--limit", type=int, default=30)
    p.add_argument("--target", help="filter runs by target substring")
    p.add_argument("--show", type=int, metavar="ID", help="print the findings of one run")
    p.add_argument("--inventory", action="store_true", help="newest verdict per target")
    p.add_argument("--delete", type=int, metavar="ID", help="delete one run")

    p = sub.add_parser("export", help="export recorded findings as CSV (default) or JSON")
    p.add_argument("--format", choices=["csv", "json"], default="csv")
    p.add_argument("--run", type=int, metavar="ID", help="only this run")
    p.add_argument("-o", "--output", help="write to file instead of stdout")

    p = sub.add_parser("gui", help="open the local web interface (127.0.0.1 only)")
    p.add_argument("--port", type=int, default=None, help="port (default 8765, falls back to a free port; 0 = random)")
    p.add_argument("--no-browser", action="store_true")
    p.add_argument("--verbose", action="store_true", help="log HTTP requests")

    argv = sys.argv[1:] if argv is None else list(argv)
    if not argv or (len(argv) == 1 and argv[0].startswith("-psn_")):   # double-clicked app bundle: no args (macOS adds -psn_)
        argv = ["gui"]
    args = ap.parse_args(argv)
    if args.cmd == "gui":
        from .gui import serve
        return serve(8765 if args.port is None else args.port, not args.no_browser, args.timeout, args.verbose,
                     port_explicit=args.port is not None, db_path=args.db)
    if args.cmd in ("history", "export"):
        from .store import Store
        st = Store(args.db)
        try:
            if args.cmd == "export":
                data = st.export(args.format, args.run)
                if args.output:
                    with open(args.output, "w", encoding="utf-8") as fh:
                        fh.write(data)
                    print("wrote %s" % args.output)
                else:
                    sys.stdout.write(data)
                return 0
            if args.delete:
                st.delete_run(args.delete)
                print("deleted run %d" % args.delete)
                return 0
            if args.show:
                findings = st.findings(args.show)
                if not findings:
                    print("no such run")
                    return 1
                print(render_json(findings) if args.json else render_text(findings, color=sys.stdout.isatty() and not args.no_color))
                return 0
            if args.inventory:
                rows = st.latest_per_target()
                if args.json:
                    print(json.dumps(rows, indent=2, ensure_ascii=False))
                else:
                    for r in rows:
                        print("%-20s %-19s run %-5d %s" % (r["overall"], r["ts"], r["run_id"], r["target"]))
                return 0
            rows = st.runs(args.limit, args.target)
            if args.json:
                print(json.dumps(rows, indent=2, ensure_ascii=False))
            else:
                print("%-5s %-19s %-8s %-20s %-5s %-5s %s" % ("ID", "TIME", "CMD", "OVERALL", "VULN", "WEAK", "TARGETS"))
                for r in rows:
                    print("%-5d %-19s %-8s %-20s %-5d %-5d %s" % (r["id"], r["ts"], r["command"], r["overall"] or "-",
                                                                 r["n_vulnerable"], r["n_weak"], " ".join(r["targets"])[:70]))
            return 0
        finally:
            st.close()
    findings = []
    targets = []
    if args.cmd == "batch":
        from .batch import parse_list, run_rows, TEMPLATE_CSV
        if args.template or not args.files:
            sys.stdout.write(TEMPLATE_CSV)
            return 0
        for fn in args.files:
            try:
                with open(fn, "rb") as fh:
                    data = fh.read()
            except OSError as e:
                print("cannot read %s: %s" % (fn, e), file=sys.stderr)
                return 1
            rows, errors = parse_list(data, fn)
            for e in errors:
                print("%s line %d skipped: %s (%s)" % (fn, e.line, e.error, e.host), file=sys.stderr)
            if not rows:
                print("%s: no usable rows" % fn, file=sys.stderr)
                continue
            print("%s: %d target(s)%s" % (fn, min(len(rows), args.limit), "" if len(rows) <= args.limit else " (limited from %d)" % len(rows)), file=sys.stderr)
            targets.append(fn)
            for row, fs in run_rows(rows[:args.limit], args.timeout):
                targets.append(row.target)
                findings.extend(fs)
    elif args.cmd == "file":
        from .formats import analyze_file
        targets = args.paths
        for pth in args.paths:
            findings.extend(analyze_file(pth))
    elif args.cmd == "web":
        from .webprobe import probe_web
        targets = args.urls
        for u in args.urls:
            findings.extend(probe_web(u, args.timeout))
    elif args.cmd == "scan":
        from .codescan import scan_path
        targets = args.paths
        for pth in args.paths:
            findings.extend(scan_path(pth, include_code=not args.no_code))
    elif args.cmd == "tls":
        from .tlsprobe import probe_tls
        targets = args.hosts
        for h in args.hosts:
            findings.extend(probe_tls(h, args.timeout))
    elif args.cmd == "ssh":
        from .sshprobe import probe_ssh
        targets = args.hosts
        for h in args.hosts:
            findings.extend(probe_ssh(h, args.timeout))

    if not args.no_save:
        try:
            from .store import Store
            st = Store(args.db)
            run_id = st.save_run(args.cmd, targets, findings)
            st.close()
        except Exception as e:  # history must never break a scan
            print("warning: could not save history: %s" % e, file=sys.stderr)
            run_id = None
    else:
        run_id = None
    if args.json:
        print(render_json(findings))
    else:
        color = sys.stdout.isatty() and not args.no_color
        print(render_text(findings, color=color))
        if run_id:
            print("Saved as run %d (pqcheck history --show %d)" % (run_id, run_id))
    return exit_code(findings, args.fail_on)


if __name__ == "__main__":
    sys.exit(main())

# pqcheck – quantum-readiness crypto inventory

pqcheck inventories the cryptographic algorithms found in files, source code, websites, TLS and
SSH endpoints and grades every finding for quantum resistance. It is pure Python 3.9+ standard
library with no dependencies: it ships its own ASN.1, OpenPGP, SSH and TLS parsers, so it works
regardless of the OpenSSL/LibreSSL version on the machine. Desktop apps for macOS and Windows and
single-file binaries are published on the [Releases](https://github.com/krisztianhari-wq/pqcheck/releases) page.

> Quantum safety cannot be "tested" empirically – there is no cryptographically relevant quantum
> computer. What you can do is an **inventory and compliance check**: which primitives does a
> file or service use, and are they on the list of algorithms that Shor's algorithm breaks?

## Verdicts

| Verdict | Meaning | Examples |
|---|---|---|
| `QUANTUM_VULNERABLE` | public-key crypto breakable with Shor's algorithm | RSA, ECDSA, ECDH, X25519, Ed25519, DH, DSA |
| `WEAK` | classically weak or deprecated | 3DES, RC4, MD5, SHA-1, ZipCrypto, 1024-bit RSA, TLS 1.0/1.1, static RSA key exchange |
| `QUANTUM_SAFE` | symmetric / hash (Grover only halves the exponent) or PQC | AES-256, SHA-256, ChaCha20, ML-KEM, ML-DSA |
| `HYBRID_PQC` | classical + PQC combined (recommended transition form) | X25519MLKEM768, sntrup761x25519 |
| `UNKNOWN` | recognised container, unknown algorithm | |

Notes quote the NIST IR 8547 timeline (RSA/ECC deprecated after 2030, disallowed after 2035).

## Desktop app

Download from Releases and double-click. The app starts a local server on 127.0.0.1 and opens the
interface in your browser (Yettel brand colours, Nostromo/MU-TH-UR terminal styling).

| Platform | Asset | Notes |
|---|---|---|
| macOS (Apple Silicon) | `PQCheck-Desktop-macos-arm64.zip` | unzip, drag `PQCheck.app` to Applications. First launch is blocked by Gatekeeper, see the section below |
| Windows | `PQCheck-Desktop-windows-x86_64.exe` | windowed, no console. SmartScreen warning on first run, see below |
| Linux | `PQCheck-Desktop-linux-x86_64` | `chmod +x`, then run |

Quit the app from the Dock / task bar; it is a background server with no window of its own.

### macOS says "PQCheck is damaged and can't be opened. You should move it to the Trash."

This is Gatekeeper, not a broken download. The app is not signed with an Apple Developer ID and not
notarized, and macOS 15 (Sequoia) no longer offers the right-click → Open shortcut for such apps.
The message appears for every unsigned app downloaded with a browser. Fix it once per download:

1. Click **Cancel** (do not move it to the Trash). If you already did, drag it back out of the Trash.
2. Unzip, then remove the quarantine flag from the whole bundle (note the `-r`, the flag is on every file inside):

   ```bash
   xattr -dr com.apple.quarantine ~/Downloads/PQCheck.app
   ```

3. Move it to Applications and start it:

   ```bash
   mv ~/Downloads/PQCheck.app /Applications/ && open /Applications/PQCheck.app
   ```

Alternative without Terminal: try to open the app, click **Done**, then go to
**System Settings → Privacy & Security**, scroll down to the "PQCheck was blocked" line and click
**Open Anyway**, then confirm with Touch ID / password.

If it still refuses, the ad-hoc signature inside the zip may have been invalidated by the unzip tool;
re-sign it locally and try again:

```bash
codesign --force --deep --sign - /Applications/PQCheck.app && open /Applications/PQCheck.app
```

Verify the download first if you like: `shasum -a 256 ~/Downloads/PQCheck-Desktop-macos-arm64.zip`
must match the line in `SHA256SUMS.txt` on the release page.

Permanent fix for company-wide rollout: sign with a Developer ID certificate and notarize in the
release workflow (needs an Apple Developer Program membership). Until then the steps above are required
once per downloaded copy; an app built locally with `sh build_app.sh` is never quarantined.

### Windows says "Windows protected your PC"

SmartScreen shows this for executables without a code-signing certificate. Click **More info**, then
**Run anyway**. Some corporate AV policies block unsigned executables entirely; in that case use the
Python-based `pqcheck.pyz` (`py pqcheck.pyz gui`) or ask IT to allow-list the SHA-256 from `SHA256SUMS.txt`.

## Which release file do I need?

| I want to… | Download | Notes |
|---|---|---|
| double-click an app (macOS, Apple Silicon) | `PQCheck-Desktop-macos-arm64.zip` | unzip, drag `PQCheck.app` to Applications; first launch see Gatekeeper section |
| double-click an app (Windows) | `PQCheck-Desktop-windows-x86_64.exe` | SmartScreen → More info → Run anyway |
| double-click an app (Linux) | `PQCheck-Desktop-linux-x86_64` | `chmod +x`, run |
| use the command line | `pqcheck-cli-<os>-<arch>` | e.g. `pqcheck-cli-macos-arm64`, `pqcheck-cli-windows-x86_64.exe` |
| run with Python (any OS) | `pqcheck-cli-any-python3.pyz` | `python3 pqcheck-cli-any-python3.pyz gui` |

The desktop app and the CLI are the same program; the app just runs `pqcheck gui`. Do not
double-click the `pqcheck-cli-…` files in Finder / Explorer – they are terminal programs.

## Command line

Binaries `pqcheck-cli-<os>-<arch>` on Releases, or `python3 -m pqcheck` from source, or
`python3 pqcheck-cli-any-python3.pyz`.

```bash
pqcheck file secret.gpg cert.pem bundle.p12 archive.zip
pqcheck scan ~/project                 # recursive: containers + algorithm names in code/config
pqcheck tls example.com api.corp:8443
pqcheck ssh bastion.corp
pqcheck web https://www.example.com    # whole-website check, see below
pqcheck --json tls example.com > report.json
pqcheck --fail-on weak scan .          # CI: exit 1 on WEAK, 2 on VULNERABLE
pqcheck gui                            # local web interface (what the desktop app runs)
```

Typing a URL or host name in the GUI switches the mode automatically (WEB / TLS / SSH).

**No port given? The well-known ports are tried.** `pqcheck tls host` checks 443, 8443, 465 (SMTPS),
993 (IMAPS), 995 (POP3S), 636 (LDAPS), 4443 and 9443 in parallel and probes every one that accepts a
connection (up to four); `pqcheck ssh host` tries 22, 2222, 2200, 22222; `pqcheck web host` uses 443,
then 8443. The report starts with a "port discovery" line listing what was tried and what was open.
An explicit `host:port` disables discovery and probes only that port.

### Bulk target lists (CSV / XLSX)

```bash
pqcheck batch --template > targets.csv     # header: kind,host,port,note
pqcheck batch targets.csv hosts.xlsx       # every row becomes one probe; saved as one "batch" run
```

Rules (also shown behind the ⓘ button next to *Import target list* in the GUI):

| Column | Accepted header names | Values |
|---|---|---|
| purpose of the check | `kind`, `type`, `check`, `purpose` | `tls`, `ssh`, `web`, `file`, `scan`; empty = auto-detect (URL → web, port 22 → ssh, otherwise tls) |
| IP or domain | `host`, `target`, `ip`, `domain`, `address`, `url` | host name, IPv4, full URL for web checks; `host:port` in one cell also works |
| port | `port` | 1–65535, optional; empty = well-known ports are tried |
| note | `note`, `comment` | free text, kept in the report |

CSV may be comma, semicolon or tab separated; `.xlsx` uses the first sheet; `#` starts a comment;
duplicates are dropped. Without a header row: 1 column = target, 2 = `target,port` or `kind,target`,
3 = `kind,target,port`. Invalid rows are reported with their line number and skipped.

### Result history

Every run is stored in a local SQLite database (`~/.pqcheck/history.db`, overridable with
`PQCHECK_DB` or `--db`). Disable with `--no-save`.

```bash
pqcheck history                        # list runs
pqcheck history --target yettel        # filter by target
pqcheck history --show 12              # findings of one run
pqcheck history --inventory            # newest verdict per target
pqcheck export -o findings.csv         # all findings as CSV (--format json)
pqcheck export --run 12 --format json
```

The GUI's History panel shows the same: runs, per-target inventory, click to recall a run,
CSV/JSON export.

## What it recognises

**Files (`file`, `scan`)**
- PEM/DER: X.509 certificates and CSRs, PKCS#1/#8 keys (encrypted too), SEC1 EC keys, DH/DSA
  parameters (PKCS#3 and X9.42), CMS/PKCS#7 (envelopedData, signedData, KEMRecipientInfo), PKCS#12,
  SubjectPublicKeyInfo. Key sizes for RSA/DH/DSA, curves for EC, PQC OIDs (ML-KEM, ML-DSA, SLH-DSA, Falcon).
- OpenPGP binary and ASCII armor: PKESK/SKESK, key and signature packets, SEIPD v1/v2, the
  draft-ietf-openpgp-pqc code points (ML-KEM-768+X25519 etc.).
- OpenSSH private keys (cipher, KDF, warning for unprotected keys), `authorized_keys` / `.pub` lines.
- age, ZIP (ZipCrypto vs AES-128/192/256), 7z (7zAES), LUKS1/2, KeePass KDBX, encrypted PDF,
  JWT/JWE headers, JWK/JWKS, `openssl enc` (Salted__).

**Code and config (`scan`)** – CBOM-light: regexes for the usual algorithm names (sshd_config,
nginx `ssl_ecdh_curve`, Java/Python/Go crypto calls, TLS cipher strings). Hybrid names are masked
first so `X25519MLKEM768` is not reported as a bare `X25519` hit.

**TLS (`tls`)** – sends its own TLS 1.3 ClientHello with an empty `key_share` (RFC 8446 §4.2.8), so
the server's HelloRetryRequest reveals which groups it supports: X25519MLKEM768, SecP256r1MLKEM768,
SecP384r1MLKEM1024, pure ML-KEM, Kyber draft. Reports server preference, classical fallback, leaf
certificate algorithm, and separate verdicts for key exchange (harvest-now-decrypt-later exposure)
and authentication.

**Website (`web`)** – starting from a URL, the whole HTTPS site:
- key exchange: ML-KEM hybrid groups (as `tls`), TLS 1.0/1.1/1.2/1.3 support (1.0/1.1 = WEAK)
- TLS 1.2 cipher families: **static RSA key exchange** (no forward secrecy – the worst case for
  harvest-now-decrypt-later, since one broken server key decrypts every recorded session),
  ECDHE/DHE, weak suites (3DES, RC4, NULL)
- the full **certificate chain** (leaf, intermediates, root) signature algorithm and key size – read
  raw from the TLS 1.2 handshake, where the Certificate message is still plaintext
- HTTP layer: HSTS header and max-age, http→https redirect
- **third parties**: preferred TLS 1.3 group of the external script/CSS/image/iframe hosts referenced
  by the HTML (up to 8), so you can see whether the site's dependencies are PQC-ready

**SSH (`ssh`)** – reads the server's plaintext KEXINIT: kex (mlkem768x25519, sntrup761x25519 hybrids),
host keys, ciphers, MACs. Separate verdicts for key exchange and host authentication.

## Limitations

- Symmetrically encrypted content is only graded if the format records the algorithm
  (`openssl enc` does not).
- Encrypted PKCS#12 bags are opaque; only the protecting PBE is graded.
- The code scan is heuristic: it shows where an algorithm is *mentioned*, not whether it runs.
- In TLS the server's CertificateVerify algorithm is encrypted; verdicts come from the certificate.
- No password-strength or implementation testing – this is an inventory, not a pentest.
- Binaries are not code-signed or notarized; see the Gatekeeper / SmartScreen notes above.

## Building

```bash
sh build_pyz.sh                 # dist/pqcheck.pyz (published as pqcheck-cli-any-python3.pyz)
pip install pyinstaller
sh build_app.sh                 # desktop app: dist/app/PQCheck.app (macOS), PQCheck.exe (Windows)
python3 tools/make_icon.py assets/icon_1024.png   # regenerate the icon (pure stdlib)
```

Tagging `v*` runs the release workflow, which builds the CLI binaries, the desktop apps and the
`.pyz` on Linux, macOS and Windows and attaches them with `SHA256SUMS.txt`.

## Development

```bash
sh tests/fixtures/generate.sh   # test material (throwaway keys, not committed)
python3 -m unittest discover -s tests -v
```

## References

- NIST IR 8547 – Transition to Post-Quantum Cryptography Standards
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- NSA CNSA 2.0, BSI TR-02102, EU Coordinated Implementation Roadmap for PQC (2025)
- draft-ietf-tls-ecdhe-mlkem, draft-ietf-tls-mlkem, draft-ietf-openpgp-pqc, RFC 8996

## Changelog

See [CHANGELOG.md](CHANGELOG.md). The section for each version is copied into the GitHub release notes
under "What's new", above the auto-generated commit list.

## License

MIT

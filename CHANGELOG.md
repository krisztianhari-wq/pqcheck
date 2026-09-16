# Changelog

All notable changes to pqcheck are listed here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versions follow SemVer.
The section matching the tag is copied into the GitHub release notes automatically.

## [Unreleased]

## [0.4.0] - 2026-09-16

### Added
- **Bulk target lists**: `pqcheck batch list.csv hosts.xlsx` and an *Import target list* button in
  the GUI. CSV (comma / semicolon / tab), TXT (one target per line) and Excel `.xlsx` (first sheet)
  are read with the standard library only. Columns `kind`, `host`, `port`, `note` (header optional,
  any order, Hungarian names accepted); `kind` left empty is auto-detected.
- ⓘ info dialog next to the import button describing the file rules (purpose of the check,
  IP/domain, port), plus a downloadable template CSV (`pqcheck batch --template`).
- Invalid rows are reported with line number and reason and skipped; the whole list is stored as one
  `batch` run in the history.

## [0.3.2] - 2026-09-16

### Added
- **Well-known port discovery**: a target without a port now probes every open well-known port for
  the purpose. TLS: 443, 8443, 465, 993, 995, 636, 4443, 9443; SSH: 22, 2222, 2200, 22222;
  web: 443 then 8443. The report starts with a *port discovery* line.

## [0.3.1] - 2026-09-16

### Changed
- Unambiguous release asset names: `PQCheck-Desktop-*` for the double-click apps,
  `pqcheck-cli-*` for the command-line binaries, `pqcheck-cli-any-python3.pyz` for the Python build.
- Every GitHub release starts with a "Which file do I need?" table.

## [0.3.0] - 2026-09-16

### Added
- **Desktop apps**: `PQCheck.app` (macOS, arm64) and `PQCheck.exe` (Windows) built with PyInstaller
  in windowed mode; double-clicking starts the local server and opens the GUI in the browser.
  Launching the CLI without arguments does the same.
- App icon generated with the standard library only (`tools/make_icon.py`, Yettel navy/lime).
- README sections for Gatekeeper ("damaged, move to Trash") and SmartScreen warnings.

### Changed
- GUI and README are in English.
- Release publishing switched to the `gh` CLI (leftover draft releases broke the previous action).

## [0.2.1] - 2026-09-16

### Fixed
- GUI: a URL or host name typed while FILE/SCAN mode is selected switches to WEB/TLS/SSH
  automatically instead of failing with "no such file".

## [0.2.0] - 2026-09-16

### Added
- **Website check** (`pqcheck web https://…`): TLS 1.0–1.3 support, TLS 1.2 cipher families
  (static RSA without forward secrecy vs. ECDHE/DHE vs. weak suites), the full certificate chain
  read from the plaintext TLS 1.2 handshake, HSTS and http→https redirect, and the preferred
  TLS 1.3 group of third-party resource hosts referenced by the page.
- **Result history**: every run is saved to a local SQLite database (`~/.pqcheck/history.db`);
  `pqcheck history`, `history --inventory`, `history --show ID`, `export` (CSV/JSON); History panel
  in the GUI with runs, per-target inventory, recall and export.
- Generalised ClientHello builder (legacy versions, custom cipher suites).

## [0.1.1] - 2026-09-16

### Fixed
- GUI falls back to a free port when 8765 is busy.
- X9.42 DH parameters and dotted PEM labels are recognised (macOS CI with OpenSSL 3).

## [0.1.0] - 2026-09-16

### Added
- First release. Pure-stdlib quantum-readiness inventory: `file` (PEM/DER, CMS, PKCS#12, OpenPGP,
  OpenSSH, age, ZIP, 7z, LUKS, KDBX, PDF, JOSE), `scan` (containers + algorithm names in code and
  config), `tls` (ML-KEM hybrid group probing via empty key_share / HelloRetryRequest), `ssh`
  (KEXINIT grading), `gui` (local web interface in Yettel colours, Nostromo terminal style).
- Verdicts QUANTUM_VULNERABLE / WEAK / QUANTUM_SAFE / HYBRID_PQC / UNKNOWN with NIST IR 8547 notes.
- JSON output, CI-friendly exit codes, single-file `.pyz`, PyInstaller binaries for Linux, macOS,
  Windows via GitHub Actions.

[Unreleased]: https://github.com/krisztianhari-wq/pqcheck/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/krisztianhari-wq/pqcheck/compare/v0.3.2...v0.4.0
[0.3.2]: https://github.com/krisztianhari-wq/pqcheck/compare/v0.3.1...v0.3.2
[0.3.1]: https://github.com/krisztianhari-wq/pqcheck/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/krisztianhari-wq/pqcheck/compare/v0.2.1...v0.3.0
[0.2.1]: https://github.com/krisztianhari-wq/pqcheck/compare/v0.2.0...v0.2.1
[0.2.0]: https://github.com/krisztianhari-wq/pqcheck/compare/v0.1.1...v0.2.0
[0.1.1]: https://github.com/krisztianhari-wq/pqcheck/compare/v0.1.0...v0.1.1
[0.1.0]: https://github.com/krisztianhari-wq/pqcheck/releases/tag/v0.1.0

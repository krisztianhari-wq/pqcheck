# pqcheck – fejlesztői jegyzet

Kvantumérettségi kripto-leltár: fájlokban, kódban, TLS-, SSH- és webes végpontokon talált algoritmusok minősítése. Tiszta Python 3.9+ stdlib, CLI + helyi webes GUI + asztali app. Felhasználói leírás (angol): README.md; változásnapló: CHANGELOG.md.

## Indítás és teszt
- CLI: `python3 -m pqcheck <file|scan|tls|ssh|web|batch|history|export|gui>`; argumentum nélkül a GUI indul. Előzmény-DB: `$PQCHECK_DB` vagy `~/.pqcheck/history.db` (`--db` felülírja).
- GUI: helyi HTTP-szerver a 127.0.0.1:8765 címen, foglalt port esetén szabad portra vált.
- Dev preview: launch.json `pqcheck-gui` (`~/Claude_code/.claude/launch.json`), port 8766, `/tmp/pqcheck-dev.db` – nem piszkálja a valódi előzményt.
- Tesztek: `sh tests/fixtures/generate.sh && python3 -m unittest discover -s tests` (42 teszt). A fixture-ök generáltak és gitignored-ok (eldobható privát kulcsokat tartalmaznak); úgy rögzítettek, hogy OpenSSL 3 és LibreSSL is ugyanazt adja.
- CI: `.github/workflows/ci.yml` – ubuntu/macos/windows × Python 3.9 és 3.12.

## Felépítés
- `pqcheck/knowledge.py` – algoritmus-táblák és ítéletek; bővítés ITT, táblákon keresztül.
- Ítéletek: QUANTUM_VULNERABLE / WEAK / QUANTUM_SAFE / HYBRID_PQC / UNKNOWN.
- `formats.py`, `asn1.py`, `codescan.py` – fájl- és kódelemzés; `tlsprobe.py`, `sshprobe.py`, `webprobe.py` – végpontok (web: TLS-verziók, forward secrecy, láncok, HSTS, harmadik felek).
- `ports.py` – port nélküli célnál ismert portok: tls 443/8443/465/993/995/636/4443/9443, ssh 22/2222/2200/22222, web 443/8443.
- `batch.py` – CSV/TSV/TXT/XLSX céllisták (saját stdlib xlsx-olvasó). `store.py` – SQLite előzmény. `gui.py` – webes GUI. `report.py` – kimenet.
- `tools/make_icon.py` – ikonok az `assets/`-be. `build_app.sh` (PyInstaller, `--windowed`), `build_pyz.sh` (`dist/pqcheck.pyz`).

## Telepítés / kiadás
- Verzió: `pqcheck/__init__.py` és `pyproject.toml` (jelenleg 0.4.0) együtt + CHANGELOG-szakasz. Kiadás: /release skill; `v*` tag push → `.github/workflows/release.yml`.
- A release-notes a CHANGELOG adott verziójú szakaszát „What's new” alá másolja.
- Assetek (0.3.1 óta): `PQCheck-Desktop-{macos-arm64.zip,windows-x86_64.exe,linux-x86_64}`, `pqcheck-cli-{macos-arm64,linux-x86_64,windows-x86_64.exe}`, `pqcheck-cli-any-python3.pyz`, `SHA256SUMS.txt`.

## Döntések
1. Csak stdlib, Python 3.9-ig visszafelé – bárhol fusson telepítés nélkül (pyz is).
2. MIT licenc, angol UI és README (publikus eszköz).
3. GUI-arculat: Yettel navy/lime + Alien/MU-TH-UR retro terminál (a tulajdonos kérésére).
4. A release `gh release create`-tel publikál (a softprops action-gh-release a bennmaradt draftok miatt eltört); a régi release-t előbb törli.
5. A desktop és CLI assetnevek csak kis-nagybetűben nem különbözhetnek (ütköztek a feltöltésnél) → `PQCheck-Desktop-*` vs `pqcheck-cli-*`.

## Buktatók
- Nincs Intel-mac build (a macos-13 runnert kivezették).
- Nincs kódaláírás: a README-ben Gatekeeper („damaged, move to Trash” → `xattr -dr com.apple.quarantine`) és SmartScreen útmutató.
- GitHub: az SSH 22-es port ismételt próbálkozás után rate-limitelt lehet → `GIT_SSH_COMMAND="ssh -o HostKeyAlias=github.com" git push ssh://git@ssh.github.com:443/krisztianhari-wq/pqcheck.git`. A hitelesítetlen API 60 kérés/óra – release-állapotot inkább a letöltési URL-ek / badge SVG-k pollozásával ellenőrizz.

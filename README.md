# pqcheck – kvantumbiztonsági kripto-leltár

Fájlokban, forráskódban, TLS- és SSH-végpontokon talált kriptográfiai algoritmusokat
leltároz, és mindegyikre kvantum-verdiktet ad. Tisztán Python 3.9+ standard library,
nincs függősége: a saját ASN.1-, OpenPGP-, SSH- és TLS-parsereivel dolgozik, ezért a
gép OpenSSL/LibreSSL verziójától függetlenül működik.

> Kvantumbiztonságot nem lehet "kipróbálni" – nincs támadóképes kvantumszámítógép.
> A teszt valójában **leltár + megfelelés**: milyen primitívet használ a fájl vagy a
> szolgáltatás, és az szerepel-e az ismert törhető (Shor) listán.

## Verdiktek

| Verdikt | Jelentés | Példa |
|---|---|---|
| `QUANTUM_VULNERABLE` | Shor-algoritmussal törhető aszimmetrikus kripto | RSA, ECDSA, ECDH, X25519, Ed25519, DH, DSA |
| `WEAK` | klasszikusan is gyenge / elavult | 3DES, RC4, MD5, SHA-1, ZipCrypto, 1024-bit RSA |
| `QUANTUM_SAFE` | szimmetrikus/hash (Grover csak felez) vagy PQC | AES-256, SHA-256, ChaCha20, ML-KEM, ML-DSA |
| `HYBRID_PQC` | klasszikus + PQC kombináció (ajánlott átmeneti forma) | X25519MLKEM768, sntrup761x25519 |
| `UNKNOWN` | felismert fájl, de ismeretlen algoritmus | |

A megjegyzések a NIST IR 8547 ütemtervét idézik (RSA/ECC 2030-tól elavult, 2035-től tilos).

## Használat

```bash
python3 -m pqcheck file titkos.gpg tanusitvany.pem bundle.p12 archiv.zip
python3 -m pqcheck scan ~/projekt              # rekurzív: konténerfájlok + algoritmusnevek kódban/configban
python3 -m pqcheck tls example.com api.ceg.hu:8443
python3 -m pqcheck ssh bastion.ceg.hu
python3 -m pqcheck web https://www.example.com  # teljes weboldal-ellenőrzés (lásd lent)
python3 -m pqcheck --json tls example.com > report.json
python3 -m pqcheck --fail-on weak scan .        # CI: exit 1 WEAK-nél, 2 VULNERABLE-nél
```

### Eredmények gyűjtése

Minden futás automatikusan egy helyi SQLite-adatbázisba kerül (`~/.pqcheck/history.db`, vagy a
`PQCHECK_DB` környezeti változó / `--db` kapcsoló szerinti útvonal). Kikapcsolás: `--no-save`.

```bash
python3 -m pqcheck history                     # futások listája
python3 -m pqcheck history --target yettel     # szűrés célra
python3 -m pqcheck history --show 12           # egy futás találatai
python3 -m pqcheck history --inventory         # célonként a legutóbbi verdikt (leltár-nézet)
python3 -m pqcheck export -o findings.csv      # minden találat CSV-ben (--format json is)
python3 -m pqcheck export --run 12 --format json
```

A GUI Előzmények-panelje ugyanezt mutatja: futások, célonkénti leltár, kattintásra visszatölthető
eredmény, CSV/JSON export.

## Grafikus felület

```bash
python3 -m pqcheck gui          # megnyitja: http://127.0.0.1:8765/
```

Helyi webes felület Yettel-arculattal, a Nostromo/MU-TH-UR terminálok stílusában (lime "foszfor" navy CRT-n,
scanline, monospace). Fájl-útvonal, könyvtár, TLS/SSH host és weboldal-URL megadható, titkosított fájlok drag&drop-pal is
elemezhetők; a fájl nem hagyja el a gépet. A szerver csak a 127.0.0.1-en hallgat, és minden API-hívás
oldalba ágyazott véletlen tokent igényel, így más weboldal nem tudja meghívni.

## Futtatható változatok

Három forma, választhatsz a célgép szerint:

| Forma | Mit igényel | Hogyan |
|---|---|---|
| Natív bináris (`pqcheck`, `pqcheck.exe`) | semmit | a [Releases](https://github.com/krisztianhari-wq/pqcheck/releases) oldalról: Linux x86_64, macOS arm64, Windows x86_64 |
| Egyfájlos `pqcheck.pyz` | Python 3.9+ | `sh build_pyz.sh`, majd `./dist/pqcheck.pyz tls example.com` (vagy `python3 pqcheck.pyz ...`) |
| Forrásból | Python 3.9+ | `python3 -m pqcheck ...` vagy `pip install -e .` → `pqcheck ...` |

A binárisokat a `release.yml` workflow gyártja PyInstallerrel, amikor `v*` taget pusholsz:

```bash
git tag v0.1.0 && git push origin v0.1.0
```

Helyi natív build (a saját platformodra):

```bash
python3 -m venv .venv && .venv/bin/pip install pyinstaller
printf 'import sys\nfrom pqcheck.cli import main\nsys.exit(main())\n' > build/entry.py
.venv/bin/pyinstaller --onefile --name pqcheck --paths . --distpath dist --workpath build/pyi --specpath build build/entry.py
```

## Mit ismer fel

**Fájlok (`file`, `scan`)**
- PEM/DER: X.509 tanúsítvány, PKCS#1/#8 kulcs (titkosított is), SEC1 EC kulcs, DH/DSA paraméter,
  CMS/PKCS#7 (envelopedData, signedData, KEMRecipientInfo), PKCS#12, SubjectPublicKeyInfo.
  Kulcsméret RSA/DH/DSA-nál, görbe EC-nél, PQC OID-ok (ML-KEM, ML-DSA, SLH-DSA, Falcon).
- OpenPGP bináris és ASCII-armor: PKESK/SKESK, kulcs- és aláírás-csomagok, SEIPD v1/v2,
  a draft-ietf-openpgp-pqc kódpontjai (ML-KEM-768+X25519 stb.).
- OpenSSH privát kulcs (cipher, KDF, jelszó nélküli kulcs figyelmeztetés), `authorized_keys`/`.pub` sorok.
- age, ZIP (ZipCrypto vs. AES-128/192/256), 7z (7zAES), LUKS1/2, KeePass KDBX, titkosított PDF,
  JWT/JWE fejléc, JWK/JWKS, `openssl enc` (Salted__).

**Kód és config (`scan`)** – CBOM-light: regex a szokásos algoritmusnevekre (sshd_config, nginx
`ssl_ecdh_curve`, Java/Python/Go kripto hívások, TLS cipher stringek). A hibrid nevek maszkolva
vannak, hogy az `X25519MLKEM768` ne jelenjen meg tévesen `X25519` találatként.

**TLS (`tls`)** – saját TLS 1.3 ClientHello-t küld üres `key_share`-rel (RFC 8446 4.2.8), így a
szerver HelloRetryRequest-tel elárulja, mely csoportokat támogatja: X25519MLKEM768,
SecP256r1MLKEM768, SecP384r1MLKEM1024, tiszta ML-KEM, Kyber draft. Jelenti a szerver
preferenciáját, a klasszikus fallbackot, a levéltanúsítvány algoritmusát, és külön verdiktet ad a
kulcscserére (harvest-now-decrypt-later kitettség) és a hitelesítésre.

**Weboldal (`web`)** – URL-ből kiindulva a teljes HTTPS-oldal:
- kulcscsere: ML-KEM hibrid csoportok (mint a `tls`), TLS 1.0/1.1/1.2/1.3 támogatás (1.0/1.1 = WEAK)
- TLS 1.2 cipher-családok: **statikus RSA kulcscsere** (nincs forward secrecy – ez a "harvest now,
  decrypt later" legrosszabb esete, mert egy feltört szerverkulccsal minden rögzített session visszafejthető),
  ECDHE/DHE, gyenge suite-ok (3DES, RC4, NULL)
- teljes **tanúsítványlánc** (leaf, közbülső, root) aláírás-algoritmusa és kulcsmérete – a TLS 1.2
  kézfogásból nyersen kiolvasva, ahol a Certificate üzenet még titkosítatlan
- HTTP-réteg: HSTS fejléc és max-age, http→https átirányítás
- **harmadik felek**: a HTML-ből kiszedett külső script/CSS/kép/iframe hostok preferált TLS 1.3 csoportja
  (max. 8 host), így látszik, hogy az oldal függőségei PQC-készek-e

**SSH (`ssh`)** – kiolvassa a szerver nyílt KEXINIT-jét: kex (mlkem768x25519, sntrup761x25519
hibridek), hostkey, cipher, MAC. Külön verdikt kulcscserére és host-hitelesítésre.

## Korlátok

- Szimmetrikusan titkosított tartalom algoritmusát csak akkor tudja, ha a formátum tárolja
  (pl. `openssl enc` nem tárolja).
- Titkosított PKCS#12 táskák belsejét nem látja, csak a védő PBE-t.
- A kód-scan heurisztikus: azt jelzi, hol *említenek* egy algoritmust, nem azt, hogy fut-e.
- TLS-nél a szerver CertificateVerify aláírás-algoritmusát nem látja (titkosított), a tanúsítványból következtet.
- Nem tesztel jelszóerősséget vagy implementációs hibákat – ez leltár, nem pentest.

## Fejlesztés

```bash
python3 -m unittest discover -s tests -v
```

A tesztanyag nincs a repóban (privát kulcsokat tartalmaz); első futtatás előtt generáld:

```bash
sh tests/fixtures/generate.sh
```

## Hivatkozások

- NIST IR 8547 – Transition to Post-Quantum Cryptography Standards
- FIPS 203 (ML-KEM), FIPS 204 (ML-DSA), FIPS 205 (SLH-DSA)
- NSA CNSA 2.0, BSI TR-02102, EU Coordinated Implementation Roadmap for PQC (2025)
- draft-ietf-tls-ecdhe-mlkem, draft-ietf-tls-mlkem, draft-ietf-openpgp-pqc

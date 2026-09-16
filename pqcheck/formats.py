"""File format detectors. Each detector returns a list of Findings or None."""
import base64
import binascii
import json
import re
import struct
from typing import List, Optional

from . import asn1
from .knowledge import (OIDS, STRUCT_OIDS, PGP_PUBKEY_ALGOS, PGP_SYM_ALGOS, PGP_HASH_ALGOS,
                        PGP_AEAD, JOSE_ALGS, SSH_HOSTKEY, SSH_CIPHERS, Verdict)
from .report import Finding

MAX_READ = 64 * 1024 * 1024


# ============================================================ helpers ======
def _u32(b, o):
    return struct.unpack(">I", b[o:o + 4])[0]


def _ssh_string(b, o):
    n = _u32(b, o)
    return b[o + 4:o + 4 + n], o + 4 + n


def _mpint_bits(b):
    i = 0
    while i < len(b) and b[i] == 0:
        i += 1
    if i >= len(b):
        return 0
    return (len(b) - i - 1) * 8 + b[i].bit_length()


# ============================================================ ASN.1 / DER ==
def analyze_der(target: str, data: bytes, label: str = "DER") -> Optional[List[Finding]]:
    nodes = asn1.try_parse(data)
    if nodes is None:
        return None
    findings = []
    seen = set()
    structs = []
    handled = set()   # id() of OID nodes already consumed by an AlgorithmIdentifier

    def add(name, loc, bits=None, role=None):
        key = (name, loc, bits, role)
        if key in seen:
            return
        seen.add(key)
        f = Finding.make(target, loc, name, bits=bits, role=role)
        if "SMIMECapabilities" in loc:
            f.verdict = Verdict.INFO
            f.note = "advertised capability only"
        findings.append(f)

    def rsa_bits_from_pkcs1(blob):
        inner = asn1.try_parse(blob)
        if inner and inner[0].is_seq and len(inner[0].children) >= 2:
            ints = [c for c in inner[0].children if c.is_int]
            if len(ints) >= 8:      # private key: version, n, e, d, ...
                return ints[1].int_bits()
            if len(ints) >= 2:      # public key: n, e
                return ints[0].int_bits()
        return None

    def handle_alg_id(seq, container, loc):
        """seq = AlgorithmIdentifier SEQUENCE{OID, params}; container = its parent."""
        oid = seq.children[0].oid()
        if oid not in OIDS:
            return
        for c in seq.children:
            if c.is_oid:
                handled.add(id(c))
        name, role = OIDS[oid]
        if "PRIVATE" in label.upper() and role.startswith("public key"):
            role = role.replace("public key", "private key")
        bits = None
        # curve parameters
        if oid == "1.2.840.10045.2.1" and len(seq.children) > 1 and seq.children[1].is_oid:
            curve = seq.children[1].oid()
            if curve in OIDS:
                cname = OIDS[curve][0]
                add(cname, loc, role="curve")
                name = "ECDH/ECDSA"
                add("ECDH", loc, role="public key on " + cname)
                return
        if oid in ("1.2.840.10040.4.1", "1.2.840.10046.2.1") and len(seq.children) > 1:
            p = [c for c in seq.children[1].children if c.is_int]
            if p:
                bits = p[0].int_bits()
        if oid == "1.2.840.113549.1.1.1":
            # find key material next to this algId
            sibs = container.children
            idx = sibs.index(seq)
            if idx + 1 < len(sibs):
                nxt = sibs[idx + 1]
                blob = nxt.value[1:] if nxt.is_bits else nxt.value
                bits = rsa_bits_from_pkcs1(blob)
        add(name, loc, bits=bits, role=role)

    def visit(nodes, path):
        for n in nodes:
            loc = label + path
            if n.is_oid:
                oid = n.oid()
                if id(n) in handled:
                    continue
                if oid in STRUCT_OIDS:
                    if STRUCT_OIDS[oid] not in structs:
                        structs.append(STRUCT_OIDS[oid])
                elif oid in OIDS:
                    # OID not inside an AlgorithmIdentifier we handled (e.g. SEC1 [0] curve)
                    name, role = OIDS[oid]
                    add(name, loc, role=role)
                elif oid.startswith("2.16.840.1.101.3.4.4."):
                    add("ML-KEM", loc, role="KEM")
                elif oid.startswith("1.3.9999.") or oid.startswith("1.3.6.1.4.1.2.267."):
                    findings.append(Finding.info(target, loc, "OQS / experimental PQC OID %s" % oid, Verdict.UNKNOWN))
            elif n.is_seq and n.children and n.children[0].is_oid and len(n.children) <= 2:
                oid = n.children[0].oid()
                if oid == "1.2.840.113549.1.9.15":
                    _visit_with_parent(n.children, path + "/SMIMECapabilities", n)
                    continue
                if oid in OIDS:
                    handle_alg_id(n, _parent, loc)
            # context-specific [0] holding a curve OID (SEC1 EC private key)
            if n.cls == 2 and n.constructed and n.children and n.children[0].is_oid:
                oid = n.children[0].oid()
                if oid in OIDS:
                    add(OIDS[oid][0], loc, role="curve")
                    continue
            # nested DER inside OCTET STRING / BIT STRING (PKCS#8 key blob, eContent, SPKI)
            if (n.is_octets or n.is_bits) and not n.constructed and len(n.value) > 8:
                blob = n.value[1:] if n.is_bits else n.value
                if blob[:1] == b"\x30":
                    inner = asn1.try_parse(blob)
                    if inner:
                        _visit_with_parent(inner, path + "/nested", n)
            if n.children:
                _visit_with_parent(n.children, path, n)

    _parent = None

    def _visit_with_parent(nodes, path, parent):
        nonlocal _parent
        saved = _parent
        _parent = parent
        visit(nodes, path)
        _parent = saved

    root = asn1.Node(0x30, 0, True, 16, 0, data, nodes)
    _visit_with_parent(nodes, "", root)

    # PKCS#1 at top level (RSA PRIVATE KEY / RSA PUBLIC KEY PEM)
    if nodes[0].is_seq and nodes[0].children and all(c.is_int for c in nodes[0].children):
        ints = nodes[0].children
        if len(ints) >= 8:
            add("RSA", label, bits=ints[1].int_bits(), role="private key (PKCS#1)")
        elif "DH" in label.upper() and len(ints) in (2, 3, 4, 5):
            # PKCS#3 {p, g[, l]} or X9.42 {p, g, q[, j, validation]}
            add("DH", label, bits=ints[0].int_bits(), role="parameters")
        elif len(ints) == 2:
            add("RSA", label, bits=ints[0].int_bits(), role="public key (PKCS#1)")
        elif len(ints) == 3 and label.startswith("DSA"):
            add("DSA", label, bits=ints[0].int_bits(), role="parameters")
    if structs:
        findings.insert(0, Finding.info(target, label, "structure: " + " > ".join(structs)))
    if not [f for f in findings if f.algorithm != "-"]:
        findings.append(Finding.info(target, label, "valid ASN.1 but no known algorithm OIDs", Verdict.UNKNOWN))
    return findings


# ============================================================ PEM ==========
PEM_RE = re.compile(rb"-----BEGIN ([A-Z0-9 .#-]+)-----\r?\n(.*?)-----END \1-----", re.S)


def analyze_pem(target: str, data: bytes) -> Optional[List[Finding]]:
    blocks = PEM_RE.findall(data)
    if not blocks:
        return None
    findings = []
    for i, (label, body) in enumerate(blocks):
        label = label.decode()
        loc = "%s #%d" % (label, i + 1)
        lines = body.split(b"\n")
        headers = {}
        b64 = []
        in_hdr = True
        for ln in lines:
            ln = ln.strip()
            if in_hdr and b":" in ln:
                k, v = ln.split(b":", 1)
                headers[k.strip().decode(errors="replace")] = v.strip().decode(errors="replace")
                continue
            in_hdr = False
            if ln.startswith(b"=") and label.startswith("PGP"):
                continue  # armor CRC
            b64.append(ln)
        try:
            raw = base64.b64decode(b"".join(b64), validate=False)
        except (binascii.Error, ValueError):
            findings.append(Finding.info(target, loc, "undecodable PEM body", Verdict.UNKNOWN))
            continue
        if "DEK-Info" in headers:
            cipher = headers["DEK-Info"].split(",")[0]
            m = re.match(r"(AES|DES-EDE3|DES)-?(\d+)?", cipher)
            if m:
                name = "AES-%s" % m.group(2) if m.group(1) == "AES" else ("3DES" if "EDE3" in cipher else "DES")
                findings.append(Finding.make(target, loc, name, role="legacy PEM encryption (MD5 KDF)"))
        if label.startswith("PGP"):
            r = analyze_pgp(target, raw, loc)
        elif label == "OPENSSH PRIVATE KEY":
            r = analyze_openssh_private(target, raw, loc)
        elif label in ("SSH2 PUBLIC KEY",):
            r = _ssh_pubkey_blob(target, raw, loc)
        else:
            r = analyze_der(target, raw, loc)
        if r:
            findings.extend(r)
        else:
            findings.append(Finding.info(target, loc, "unparsed PEM block", Verdict.UNKNOWN))
    return findings


# ============================================================ OpenPGP ======
def _pgp_packets(data: bytes):
    pos = 0
    n = len(data)
    while pos < n:
        ctb = data[pos]
        if not ctb & 0x80:
            raise ValueError("bad CTB at %d" % pos)
        pos += 1
        if ctb & 0x40:
            tag = ctb & 0x3F
            body = bytearray()
            while True:
                if pos >= n:
                    raise ValueError("truncated")
                b1 = data[pos]
                pos += 1
                if b1 < 192:
                    ln, partial = b1, False
                elif b1 < 224:
                    ln = ((b1 - 192) << 8) + data[pos] + 192
                    pos += 1
                    partial = False
                elif b1 == 255:
                    ln = _u32(data, pos)
                    pos += 4
                    partial = False
                else:
                    ln = 1 << (b1 & 0x1F)
                    partial = True
                body += data[pos:pos + ln]
                pos += ln
                if not partial:
                    break
            yield tag, bytes(body)
        else:
            tag = (ctb >> 2) & 0x0F
            lt = ctb & 3
            if lt == 0:
                ln = data[pos]; pos += 1
            elif lt == 1:
                ln = struct.unpack(">H", data[pos:pos + 2])[0]; pos += 2
            elif lt == 2:
                ln = _u32(data, pos); pos += 4
            else:
                ln = n - pos
            yield tag, data[pos:pos + ln]
            pos += ln


def _pgp_mpi(b, o):
    bits = struct.unpack(">H", b[o:o + 2])[0]
    return bits, o + 2 + (bits + 7) // 8


def _pgp_key_material(body, target, loc, findings, algo, o):
    name = PGP_PUBKEY_ALGOS.get(algo, "unknown(%d)" % algo)
    bits = None
    role = "public key"
    if algo in (1, 2, 3, 16, 17):
        bits, _ = _pgp_mpi(body, o)
    elif algo in (18, 19, 22):
        ln = body[o]
        curve = asn1.decode_oid(body[o + 1:o + 1 + ln])
        cname = OIDS.get(curve, (curve, ""))[0]
        findings.append(Finding.make(target, loc, cname, role="curve"))
        role = "public key on " + cname
    findings.append(Finding.make(target, loc, name, bits=bits, role=role))


def analyze_pgp(target: str, data: bytes, label: str = "OpenPGP") -> Optional[List[Finding]]:
    if not data or not data[0] & 0x80:
        return None
    findings = []
    try:
        pkts = list(_pgp_packets(data))
    except (ValueError, IndexError, struct.error):
        return None
    if not pkts:
        return None
    known = {1, 2, 3, 5, 6, 7, 8, 9, 11, 13, 14, 17, 18, 19, 20}
    if not all(t in known for t, _ in pkts):
        return None
    for i, (tag, body) in enumerate(pkts):
        loc = "%s pkt%d" % (label, i + 1)
        try:
            if tag == 1:   # PKESK
                ver = body[0]
                if ver == 3:
                    algo = body[9]
                elif ver == 6:
                    kl = body[1]
                    algo = body[2 + kl]
                else:
                    continue
                name = PGP_PUBKEY_ALGOS.get(algo, "unknown(%d)" % algo)
                findings.append(Finding.make(target, loc + " PKESK", name, role="session key encryption"))
            elif tag == 3:  # SKESK
                ver = body[0]
                if ver == 4:
                    sym = body[1]
                    findings.append(Finding.make(target, loc + " SKESK", PGP_SYM_ALGOS.get(sym, "unknown"), role="password-based (S2K)"))
                    if body[2] == 3 and body[3] in PGP_HASH_ALGOS:
                        findings.append(Finding.make(target, loc + " SKESK", PGP_HASH_ALGOS[body[3]], role="S2K hash"))
                else:
                    sym = body[2]
                    aead = PGP_AEAD.get(body[3], "?")
                    findings.append(Finding.make(target, loc + " SKESK v%d" % ver, PGP_SYM_ALGOS.get(sym, "unknown"), role="password-based, AEAD " + aead))
            elif tag in (5, 6, 7, 14):
                kind = {5: "secret key", 6: "public key", 7: "secret subkey", 14: "public subkey"}[tag]
                ver = body[0]
                if ver in (2, 3):
                    algo, o = body[7], 8
                elif ver == 4:
                    algo, o = body[5], 6
                elif ver == 6:
                    algo, o = body[5], 10
                else:
                    continue
                _pgp_key_material(body, target, loc + " " + kind, findings, algo, o)
            elif tag == 2:  # signature
                ver = body[0]
                if ver in (2, 3):
                    pk, h = body[15], body[16]
                else:
                    pk, h = body[2], body[3]
                findings.append(Finding.make(target, loc + " signature", PGP_PUBKEY_ALGOS.get(pk, "unknown(%d)" % pk), role="signature"))
                findings.append(Finding.make(target, loc + " signature", PGP_HASH_ALGOS.get(h, "unknown(%d)" % h), role="hash"))
            elif tag == 9:
                findings.append(Finding.info(target, loc, "Symmetrically Encrypted Data without integrity protection (tag 9): legacy, malleable", Verdict.WEAK))
            elif tag == 18:
                ver = body[0]
                if ver == 1:
                    findings.append(Finding.info(target, loc, "SEIPD v1 (CFB + MDC); cipher set by the ESK packets"))
                else:
                    sym = body[1]
                    findings.append(Finding.make(target, loc + " SEIPD v2", PGP_SYM_ALGOS.get(sym, "unknown"), role="AEAD " + PGP_AEAD.get(body[2], "?")))
            elif tag == 20:
                sym = body[1]
                findings.append(Finding.make(target, loc + " AEAD(tag20)", PGP_SYM_ALGOS.get(sym, "unknown"), role="deprecated AEAD packet"))
        except (IndexError, struct.error):
            findings.append(Finding.info(target, loc, "truncated packet", Verdict.UNKNOWN))
    return findings or None


# ============================================================ SSH keys =====
def _ssh_pubkey_blob(target, blob, loc):
    findings = []
    try:
        ktype, o = _ssh_string(blob, 0)
        ktype = ktype.decode()
    except (struct.error, UnicodeDecodeError):
        return None
    if ktype not in SSH_HOSTKEY:
        return [Finding.info(target, loc, "unknown ssh key type %s" % ktype, Verdict.UNKNOWN)]
    name, bits = SSH_HOSTKEY[ktype]
    if ktype == "ssh-rsa":
        name = "RSA"
        e, o = _ssh_string(blob, o)
        n, o = _ssh_string(blob, o)
        bits = _mpint_bits(n)
    elif ktype == "ssh-dss":
        p, o = _ssh_string(blob, o)
        bits = _mpint_bits(p)
    findings.append(Finding.make(target, loc, name, bits=bits, role="ssh key " + ktype))
    return findings


SSH_PUB_RE = re.compile(rb"^(?:[^\s]+ )?(ssh-rsa|ssh-dss|ssh-ed25519|ssh-ed448|ecdsa-sha2-nistp\d+|sk-[\w@.-]+) ([A-Za-z0-9+/=]+)", re.M)


def analyze_ssh_public_lines(target: str, data: bytes) -> Optional[List[Finding]]:
    findings = []
    for i, m in enumerate(SSH_PUB_RE.finditer(data)):
        try:
            blob = base64.b64decode(m.group(2))
        except (binascii.Error, ValueError):
            continue
        line_no = data.count(b"\n", 0, m.start()) + 1
        r = _ssh_pubkey_blob(target, blob, "ssh public key line %d" % line_no)
        if r:
            findings.extend(r)
    return findings or None


def analyze_openssh_private(target: str, raw: bytes, loc: str) -> Optional[List[Finding]]:
    if not raw.startswith(b"openssh-key-v1\x00"):
        return None
    findings = []
    try:
        o = len(b"openssh-key-v1\x00")
        cipher, o = _ssh_string(raw, o)
        kdf, o = _ssh_string(raw, o)
        kdfopts, o = _ssh_string(raw, o)
        nkeys = _u32(raw, o); o += 4
        cipher = cipher.decode(); kdf = kdf.decode()
        if cipher == "none":
            findings.append(Finding.info(target, loc, "private key is NOT passphrase-protected", Verdict.WEAK))
        else:
            findings.append(Finding.make(target, loc, SSH_CIPHERS.get(cipher, cipher), role="key file encryption " + cipher))
            findings.append(Finding.make(target, loc, kdf, role="key file KDF"))
        for k in range(nkeys):
            blob, o = _ssh_string(raw, o)
            r = _ssh_pubkey_blob(target, blob, loc)
            if r:
                findings.extend(r)
    except (struct.error, IndexError, UnicodeDecodeError):
        findings.append(Finding.info(target, loc, "truncated openssh key", Verdict.UNKNOWN))
    return findings


# ============================================================ age ==========
def analyze_age(target: str, data: bytes) -> Optional[List[Finding]]:
    if not data.startswith(b"age-encryption.org/v1\n"):
        return None
    findings = []
    for ln in data.split(b"\n")[1:64]:
        if ln.startswith(b"-> "):
            kind = ln[3:].split(b" ")[0].decode(errors="replace")
            name = {"X25519": "X25519", "scrypt": "scrypt", "ssh-ed25519": "Ed25519", "ssh-rsa": "RSA-OAEP",
                    "piv-p256": "ECDH", "tlock": "tlock"}.get(kind, kind)
            findings.append(Finding.make(target, "age recipient stanza", name, role="file key wrapping (%s)" % kind))
        if ln.startswith(b"---"):
            break
    findings.append(Finding.make(target, "age payload", "ChaCha20-Poly1305", role="payload encryption"))
    return findings


# ============================================================ ZIP ==========
def analyze_zip(target: str, data: bytes) -> Optional[List[Finding]]:
    if not data.startswith(b"PK\x03\x04") and not data.startswith(b"PK\x05\x06"):
        return None
    eocd = data.rfind(b"PK\x05\x06")
    if eocd < 0:
        return [Finding.info(target, "ZIP", "no central directory", Verdict.UNKNOWN)]
    cd_size, cd_off = struct.unpack("<II", data[eocd + 12:eocd + 20])
    pos = cd_off
    findings = []
    seen = set()
    count = 0
    while pos + 46 <= len(data) and data[pos:pos + 4] == b"PK\x01\x02" and count < 10000:
        flags, method = struct.unpack("<HH", data[pos + 8:pos + 12])
        nlen, xlen, clen = struct.unpack("<HHH", data[pos + 28:pos + 34])
        name = data[pos + 46:pos + 46 + nlen].decode(errors="replace")
        extra = data[pos + 46 + nlen:pos + 46 + nlen + xlen]
        if flags & 1:
            if method == 99:
                algo = "AES"
                bits = None
                xo = 0
                while xo + 4 <= len(extra):
                    xid, xsz = struct.unpack("<HH", extra[xo:xo + 4])
                    if xid == 0x9901 and xsz >= 7:
                        strength = extra[xo + 8]
                        bits = {1: 128, 2: 192, 3: 256}.get(strength)
                    xo += 4 + xsz
                key = ("AES", bits)
                if key not in seen:
                    seen.add(key)
                    findings.append(Finding.make(target, "ZIP entries (WinZip AE-x)", "AES", bits=bits, role="entry encryption, PBKDF2-SHA1 KDF"))
            else:
                if "zc" not in seen:
                    seen.add("zc")
                    findings.append(Finding.make(target, "ZIP entries", "ZipCrypto", role="entry encryption"))
        count += 1
        pos += 46 + nlen + xlen + clen
    if not findings:
        findings.append(Finding.info(target, "ZIP", "%d entries, none encrypted" % count))
    return findings


# ============================================================ 7z ===========
def analyze_7z(target: str, data: bytes) -> Optional[List[Finding]]:
    if not data.startswith(b"7z\xbc\xaf\x27\x1c"):
        return None
    try:
        nh_off, nh_size = struct.unpack("<QQ", data[12:28])
        hdr = data[32 + nh_off:32 + nh_off + nh_size]
    except struct.error:
        return [Finding.info(target, "7z", "truncated header", Verdict.UNKNOWN)]
    if b"\x06\xf1\x07\x01" in hdr:   # 7zAES coder id
        return [Finding.make(target, "7z header/streams", "AES-256", role="7zAES (AES-256-CBC, SHA-256 x 2^19 KDF)")]
    return [Finding.info(target, "7z", "no 7zAES coder in header: archive not encrypted")]


# ============================================================ LUKS =========
def analyze_luks(target: str, data: bytes) -> Optional[List[Finding]]:
    if not data.startswith(b"LUKS\xba\xbe"):
        return None
    ver = struct.unpack(">H", data[6:8])[0]
    findings = []
    if ver == 1:
        cname = data[8:40].rstrip(b"\x00").decode(errors="replace")
        cmode = data[40:72].rstrip(b"\x00").decode(errors="replace")
        hsh = data[72:104].rstrip(b"\x00").decode(errors="replace")
        keybytes = _u32(data, 108)
        bits = keybytes * 8 // (2 if "xts" in cmode else 1)
        findings.append(Finding.make(target, "LUKS1 header", cname.upper() if cname == "aes" else cname, bits=bits, role="%s-%s volume key" % (cname, cmode)))
        findings.append(Finding.make(target, "LUKS1 header", hsh.upper().replace("SHA", "SHA-") if hsh.startswith("sha") else hsh, role="PBKDF2 hash"))
        findings.append(Finding.make(target, "LUKS1 header", "PBKDF2", role="key slot KDF"))
    elif ver == 2:
        hdr_size = struct.unpack(">Q", data[8:16])[0]
        js = data[4096:hdr_size].split(b"\x00", 1)[0]
        try:
            j = json.loads(js.decode())
        except (ValueError, UnicodeDecodeError):
            return [Finding.info(target, "LUKS2", "JSON header unreadable", Verdict.UNKNOWN)]
        for kid, ks in j.get("keyslots", {}).items():
            area = ks.get("area", {})
            enc = area.get("encryption", "?")
            ksize = int(area.get("key_size", 0)) * 8
            bits = ksize // 2 if "xts" in enc else ksize
            base = enc.split("-")[0]
            findings.append(Finding.make(target, "LUKS2 keyslot %s" % kid, base.upper() if base == "aes" else base, bits=bits, role=enc))
            kdf = ks.get("kdf", {})
            kname = kdf.get("type", "?")
            findings.append(Finding.make(target, "LUKS2 keyslot %s" % kid, "Argon2" if kname.startswith("argon2") else kname.upper(), role="KDF %s" % kname))
        for sid, seg in j.get("segments", {}).items():
            findings.append(Finding.info(target, "LUKS2 segment %s" % sid, "data encryption %s" % seg.get("encryption", "?")))
    return findings or [Finding.info(target, "LUKS", "unknown version %d" % ver, Verdict.UNKNOWN)]


# ============================================================ KeePass ======
KDBX_CIPHERS = {
    bytes.fromhex("31c1f2e6bf714350be5805216afc5aff"): "AES-256",
    bytes.fromhex("d6038a2b8b6f4cb5a524339a31dbb59a"): "ChaCha20",
    bytes.fromhex("ad68f29f576f4bb9a36ad47af965346c"): "Twofish",
}
KDBX_KDFS = {
    bytes.fromhex("c9d9f39a628a4460bf740d08c18a4fea"): "AES-KDF",
    bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c"): "Argon2",
    bytes.fromhex("9e298b1956db4773b23dfc3ec6f0a1e6"): "Argon2",
}


def analyze_kdbx(target: str, data: bytes) -> Optional[List[Finding]]:
    if data[:8] != b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5":
        return None
    minor, major = struct.unpack("<HH", data[8:12])
    head = data[:4096]
    findings = [Finding.info(target, "KeePass KDBX", "format version %d.%d" % (major, minor))]
    for uuid, name in KDBX_CIPHERS.items():
        if uuid in head:
            findings.append(Finding.make(target, "KDBX header", name, role="database cipher"))
    for uuid, name in KDBX_KDFS.items():
        if uuid in head:
            findings.append(Finding.make(target, "KDBX header", name, role="master key KDF"))
    if major == 3:
        findings.append(Finding.make(target, "KDBX3 header", "AES-KDF", role="master key KDF (v3)"))
    return findings


# ============================================================ PDF ==========
def analyze_pdf(target: str, data: bytes) -> Optional[List[Finding]]:
    if not data.startswith(b"%PDF"):
        return None
    if b"/Encrypt" not in data:
        return [Finding.info(target, "PDF", "not encrypted")]
    m = re.search(rb"/Filter\s*/Standard(.{0,600})", data, re.S)
    if not m:
        return [Finding.info(target, "PDF", "encrypted, but encryption dictionary is inside a compressed object stream", Verdict.UNKNOWN)]
    d = m.group(1)
    v = re.search(rb"/V\s+(\d)", d)
    ln = re.search(rb"/Length\s+(\d+)", d)
    v = int(v.group(1)) if v else 0
    bits = int(ln.group(1)) if ln else 40
    if b"/AESV3" in d or v == 5:
        return [Finding.make(target, "PDF /Encrypt", "AES-256", role="standard security handler V5")]
    if b"/AESV2" in d:
        return [Finding.make(target, "PDF /Encrypt", "AES-128", role="standard security handler V4")]
    return [Finding.make(target, "PDF /Encrypt", "RC4", bits=bits, role="standard security handler V%d" % v)]


# ============================================================ JOSE =========
JWT_RE = re.compile(rb"^\s*([A-Za-z0-9_-]{10,})\.([A-Za-z0-9_-]+)\.([A-Za-z0-9_-]*)(?:\.([A-Za-z0-9_-]*)\.([A-Za-z0-9_-]*))?\s*$")


def _b64url(s):
    s += b"=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def analyze_jose(target: str, data: bytes) -> Optional[List[Finding]]:
    m = JWT_RE.match(data)
    if m:
        try:
            hdr = json.loads(_b64url(m.group(1)).decode())
        except (ValueError, UnicodeDecodeError, binascii.Error):
            return None
        findings = []
        for k in ("alg", "enc"):
            if k in hdr:
                name = JOSE_ALGS.get(hdr[k])
                if hdr[k] == "none":
                    findings.append(Finding.info(target, "JWT header", "alg=none: unsigned token", Verdict.WEAK))
                elif name:
                    findings.append(Finding.make(target, "JOSE header", name, role="%s=%s" % (k, hdr[k])))
                else:
                    findings.append(Finding.info(target, "JOSE header", "unknown %s=%s" % (k, hdr[k]), Verdict.UNKNOWN))
        return findings or None
    try:
        j = json.loads(data.decode("utf-8"))
    except (ValueError, UnicodeDecodeError):
        return None
    keys = j.get("keys") if isinstance(j, dict) and isinstance(j.get("keys"), list) else ([j] if isinstance(j, dict) and "kty" in j else None)
    if keys is None:
        return None
    findings = []
    for i, k in enumerate(keys):
        if not isinstance(k, dict):
            continue
        kty = k.get("kty")
        loc = "JWK #%d (kid=%s)" % (i + 1, k.get("kid", "-"))
        if kty == "RSA" and "n" in k:
            try:
                bits = _mpint_bits(_b64url(k["n"].encode()))
            except (binascii.Error, ValueError):
                bits = None
            findings.append(Finding.make(target, loc, "RSA", bits=bits, role="kty=RSA"))
        elif kty == "EC":
            crv = k.get("crv", "?")
            findings.append(Finding.make(target, loc, crv if crv in ("P-256", "P-384", "P-521", "secp256k1") else "ECDSA", role="kty=EC crv=%s" % crv))
        elif kty == "OKP":
            crv = k.get("crv", "?")
            findings.append(Finding.make(target, loc, crv if crv in ("Ed25519", "Ed448", "X25519", "X448") else "EdDSA", role="kty=OKP"))
        elif kty == "oct":
            findings.append(Finding.info(target, loc, "symmetric JWK (oct)", Verdict.SAFE))
        elif kty in ("AKP", "ML-DSA", "ML-KEM"):
            findings.append(Finding.make(target, loc, k.get("alg", kty), role="kty=%s" % kty))
        if "alg" in k and k["alg"] in JOSE_ALGS:
            findings.append(Finding.make(target, loc, JOSE_ALGS[k["alg"]], role="alg=%s" % k["alg"]))
    return findings or None


# ============================================================ misc =========
def analyze_openssl_enc(target: str, data: bytes) -> Optional[List[Finding]]:
    if not data.startswith(b"Salted__"):
        return None
    return [Finding.info(target, "OpenSSL enc", "symmetric 'openssl enc' file: cipher is not recorded in the file (default aes-256-cbc); "
                         "KDF is MD5/SHA-256 single iteration unless -pbkdf2 was used. Symmetric-only, so quantum-safe if AES-256.", Verdict.UNKNOWN)]


NON_PGP_MAGIC = (b"\x89PNG", b"\xff\xd8\xff", b"\x1f\x8b", b"\xfd7zXZ", b"\xca\xfe\xba\xbe", b"\xcf\xfa\xed\xfe",
                 b"\xd0\xcf\x11\xe0", b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff", b"\x80\x00", b"\x80\x01")
PGP_START_TAGS = {1, 2, 3, 4, 5, 6, 8, 9, 11, 18}


def analyze_gpg_binary(target: str, data: bytes) -> Optional[List[Finding]]:
    """Binary OpenPGP without armor: be strict, many binary formats start with a high bit."""
    if data.startswith(NON_PGP_MAGIC):
        return None
    ctb = data[0]
    tag = (ctb & 0x3F) if ctb & 0x40 else (ctb >> 2) & 0x0F
    if tag not in PGP_START_TAGS:
        return None
    r = analyze_pgp(target, data, "OpenPGP")
    if not r or any(f.algorithm.startswith("unknown") or f.verdict is Verdict.UNKNOWN for f in r):
        return None
    return r


DETECTORS = [
    analyze_pem, analyze_age, analyze_ssh_public_lines, analyze_jose,
    analyze_zip, analyze_7z, analyze_luks, analyze_kdbx, analyze_pdf, analyze_openssl_enc,
]


def analyze_bytes(target: str, data: bytes) -> Optional[List[Finding]]:
    for det in DETECTORS:
        try:
            r = det(target, data)
        except Exception as e:  # detector bug must not kill the scan
            r = [Finding.info(target, det.__name__, "detector error: %r" % e, Verdict.UNKNOWN)]
        if r:
            return r
    if data[:1] == b"\x30":
        r = analyze_der(target, data)
        if r:
            return r
    if data and data[0] & 0x80:
        r = analyze_gpg_binary(target, data)
        if r:
            return r
    return None


def analyze_file(path: str) -> List[Finding]:
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_READ)
    except OSError as e:
        return [Finding.info(path, "file", "cannot read: %s" % e, Verdict.UNKNOWN)]
    if not data:
        return [Finding.info(path, "file", "empty file")]
    r = analyze_bytes(path, data)
    if r is None:
        return [Finding.info(path, "file", "format not recognised as a cryptographic container", Verdict.UNKNOWN)]
    return r

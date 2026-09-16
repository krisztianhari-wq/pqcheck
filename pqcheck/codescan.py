"""CBOM-light: grep source code and configuration for algorithm names."""
import os
import re
from typing import List

from .report import Finding
from .knowledge import Verdict
from .formats import analyze_bytes

SKIP_DIRS = {".git", ".hg", ".svn", "node_modules", ".node", "target", "venv", ".venv",
             "__pycache__", "dist", "build", ".idea", ".vscode", "vendor", ".cargo"}
MAX_TEXT = 5 * 1024 * 1024

# (regex, canonical algorithm, role) — ordered: hybrids and PQC first so that
# their components (X25519, Kyber) are masked before component patterns run.
PATTERNS = [
    (r"X25519MLKEM768|x25519_mlkem768|X25519_ML_KEM_768", "X25519MLKEM768", "TLS hybrid group"),
    (r"SecP256r1MLKEM768|secp256r1_mlkem768", "SecP256r1MLKEM768", "TLS hybrid group"),
    (r"SecP384r1MLKEM1024", "SecP384r1MLKEM1024", "TLS hybrid group"),
    (r"X25519Kyber768(?:Draft00)?|x25519_kyber768", "X25519Kyber768Draft00", "TLS hybrid group (draft)"),
    (r"mlkem768x25519-sha256", "mlkem768x25519-sha256", "SSH kex"),
    (r"sntrup761x25519-sha512(?:@openssh\.com)?", "sntrup761x25519-sha512", "SSH kex"),
    (r"mlkem768nistp256-sha256", "mlkem768nistp256-sha256", "SSH kex"),
    (r"mlkem1024nistp384-sha384", "mlkem1024nistp384-sha384", "SSH kex"),
    (r"ML[-_]?KEM[-_]?(512|768|1024)", "ML-KEM-{0}", "PQC KEM"),
    (r"\bML[-_]?KEM\b|\bMLKEM\b", "ML-KEM", "PQC KEM"),
    (r"\bKyber(?:512|768|1024)?\b", "Kyber", "PQC KEM (pre-standard)"),
    (r"ML[-_]?DSA[-_]?(44|65|87)", "ML-DSA-{0}", "PQC signature"),
    (r"\bML[-_]?DSA\b|\bMLDSA\b", "ML-DSA", "PQC signature"),
    (r"\bDilithium\d?\b", "Dilithium", "PQC signature (pre-standard)"),
    (r"\bSLH[-_]?DSA\b", "SLH-DSA", "PQC signature"),
    (r"\bSPHINCS\+?", "SPHINCS+", "PQC signature (pre-standard)"),
    (r"\bFN[-_]?DSA\b", "FN-DSA", "PQC signature"),
    (r"\bFalcon[-_]?(?:512|1024)\b", "Falcon", "PQC signature"),
    (r"\bHQC(?:-\d+)?\b", "HQC", "PQC KEM"),
    (r"\bsntrup761\b|\bNTRU\b", "sntrup761", "PQC KEM"),
    (r"\bFrodoKEM\b|\bBIKE\b", "FrodoKEM", "PQC KEM (non-NIST)"),
    (r"\bXMSS\b", "XMSS", "stateful hash-based signature"),
    (r"\bLMS\b|\bHSS/LMS\b", "LMS", "stateful hash-based signature"),
    # classical asymmetric
    (r"\bRSA[-_ ]?(1024|2048|3072|4096)\b", "RSA", "RSA with explicit size"),
    (r"\bRSA(?:ES|SSA)?[-_]?(?:OAEP|PSS|PKCS1|SHA\d+)?\b|\brsaEncryption\b|\bRS256\b|\bRS512\b|\bPS256\b", "RSA", "RSA"),
    (r"\bECDSA\b|\bES256\b|\bES384\b|\bES512\b|ecdsa-sha2-nistp\d+|ecdsa-with-", "ECDSA", "EC signature"),
    (r"\bECDHE?\b|ecdh-sha2-nistp\d+|ECDH-ES", "ECDH", "EC key exchange"),
    (r"\bsecp256r1\b|\bprime256v1\b|\bP-256\b|\bnistp256\b|\bsecp256k1\b", "P-256", "EC curve"),
    (r"\bsecp384r1\b|\bP-384\b|\bnistp384\b", "P-384", "EC curve"),
    (r"\bsecp521r1\b|\bP-521\b|\bnistp521\b", "P-521", "EC curve"),
    (r"\bbrainpoolP\d+[rt]1\b", "brainpoolP256r1", "EC curve"),
    (r"\bX25519\b|\bcurve25519(?:-sha256)?(?:@libssh\.org)?\b|\bcv25519\b", "X25519", "EC key exchange"),
    (r"\bX448\b", "X448", "EC key exchange"),
    (r"\bEd25519\b|\bssh-ed25519\b", "Ed25519", "EC signature"),
    (r"\bEd448\b", "Ed448", "EC signature"),
    (r"\bEdDSA\b", "EdDSA", "EC signature"),
    (r"\bdiffie[- ]?hellman(?:-group(?:\d+|-exchange)-sha\d+)?\b|\bDHE?[-_ ](?:RSA|DSS|\d{4})\b|\bffdhe\d{4}\b|\bdhparam", "DH", "finite-field key exchange"),
    (r"\bssh-dss\b|\bDSA\b(?!-)", "DSA", "signature"),
    (r"\bElGamal\b", "ElGamal", "key transport"),
    # symmetric
    (r"\bAES[-_]?128(?:-(?:GCM|CBC|CTR|CCM))?\b|\baes128-(?:ctr|cbc|gcm@openssh\.com)\b|\bA128(?:GCM|KW|CBC)", "AES-128", "symmetric cipher"),
    (r"\bAES[-_]?192\b|\baes192-(?:ctr|cbc)\b", "AES-192", "symmetric cipher"),
    (r"\bAES[-_]?256(?:-(?:GCM|CBC|CTR|CCM|XTS))?\b|\baes256-(?:ctr|cbc|gcm@openssh\.com)\b|\bA256(?:GCM|KW|CBC)", "AES-256", "symmetric cipher"),
    (r"\bChaCha20(?:-Poly1305)?(?:@openssh\.com)?\b", "ChaCha20-Poly1305", "symmetric cipher"),
    (r"\b3DES\b|\bDES-EDE3?\b|\bTripleDES\b|\bdes-ede3-cbc\b|\b3des-cbc\b|\bDESede\b", "3DES", "legacy cipher"),
    (r"\bDES\b(?!-EDE)|\bdes-cbc\b", "DES", "legacy cipher"),
    (r"\bRC4\b|\barcfour(?:128|256)?\b", "RC4", "legacy cipher"),
    (r"\bRC2\b", "RC2", "legacy cipher"),
    (r"\bBlowfish\b|\bblowfish-cbc\b|\bbf-cbc\b", "Blowfish", "legacy cipher"),
    (r"\bCAST5\b|\bcast128-cbc\b", "CAST5", "legacy cipher"),
    # hashes
    (r"\bMD5\b|\bhmac-md5\b", "MD5", "hash"),
    (r"\bSHA-?1\b|\bhmac-sha1\b|\bsha1With", "SHA-1", "hash"),
]
COMPILED = [(re.compile(p, re.I), name, role) for p, name, role in PATTERNS]
TEXT_EXT_HINT = {".pem", ".crt", ".cer", ".key", ".pub", ".gpg", ".pgp", ".asc", ".p12", ".pfx", ".p7m", ".p7s",
                 ".der", ".jks", ".kdbx", ".zip", ".7z", ".pdf", ".age", ".jwk", ".jwt", ".json"}


def is_binary(data: bytes) -> bool:
    return b"\x00" in data[:8192]


def scan_text(target: str, data: bytes, max_hits_per_algo: int = 3) -> List[Finding]:
    try:
        text = data.decode("utf-8", errors="replace")
    except Exception:
        return []
    findings = []
    masked = text
    for rx, name, role in COMPILED:
        hits = []
        for m in rx.finditer(masked):
            hits.append(m)
        if not hits:
            continue
        # mask so component patterns do not re-match inside hybrids
        buf = list(masked)
        for m in hits:
            for i in range(m.start(), m.end()):
                buf[i] = " "
        masked = "".join(buf)
        by_name = {}
        for m in hits:
            n = name.format(*m.groups()) if "{" in name else name
            by_name.setdefault(n, []).append(m)
        for n, ms in by_name.items():
            lines = sorted({text.count("\n", 0, m.start()) + 1 for m in ms})
            shown = ", ".join(str(l) for l in lines[:max_hits_per_algo])
            if len(lines) > max_hits_per_algo:
                shown += ", +%d more" % (len(lines) - max_hits_per_algo)
            bits = None
            r = role
            if name == "RSA" and ms[0].groups() and ms[0].group(1):
                bits = int(ms[0].group(1))
                r = "RSA reference"
            sample = text[ms[0].start():ms[0].end()]
            ctx_line = text.splitlines()[lines[0] - 1].strip() if lines else ""
            r = "%s, matched '%s' in: %s" % (r, sample, ctx_line[:80])
            findings.append(Finding.make(target, "line %s" % shown, n, bits=bits, role=r))
    return findings


def scan_path(root: str, include_code: bool = True, follow_links: bool = False) -> List[Finding]:
    findings = []
    if os.path.isfile(root):
        return scan_one(root, include_code)
    for dirpath, dirnames, filenames in os.walk(root, followlinks=follow_links):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            p = os.path.join(dirpath, fn)
            if os.path.islink(p) and not follow_links:
                continue
            findings.extend(scan_one(p, include_code, quiet_unknown=True))
    return findings


def scan_one(path: str, include_code: bool, quiet_unknown: bool = False) -> List[Finding]:
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            data = fh.read(64 * 1024 * 1024)
    except OSError:
        return []
    if not data:
        return []
    r = analyze_bytes(path, data)
    if r:
        return r
    if include_code and not is_binary(data) and size <= MAX_TEXT:
        return scan_text(path, data)
    if quiet_unknown:
        return []
    return [Finding.info(path, "file", "format not recognised", Verdict.UNKNOWN)]

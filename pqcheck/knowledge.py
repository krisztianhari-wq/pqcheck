"""Algorithm knowledge base: what is quantum-vulnerable, what is not.

Verdict rationale follows NIST IR 8547 (Nov 2024 draft): RSA, ECDSA, ECDH,
DH, DSA, EdDSA are deprecated after 2030 and disallowed after 2035 because
of Shor's algorithm. Symmetric ciphers and hashes are only affected by
Grover (square-root speedup); AES-256 / SHA-256 stay secure. PQC algorithms
are the FIPS 203/204/205 families and their hybrids.
"""
from enum import Enum
from typing import Optional, Tuple


class Verdict(str, Enum):
    VULNERABLE = "QUANTUM_VULNERABLE"  # Shor-breakable public-key crypto
    WEAK = "WEAK"                      # classically weak or deprecated
    UNKNOWN = "UNKNOWN"
    INFO = "INFO"
    HYBRID = "HYBRID_PQC"              # classical + PQC combined (recommended)
    SAFE = "QUANTUM_SAFE"


SEVERITY = {
    Verdict.VULNERABLE: 0,
    Verdict.WEAK: 1,
    Verdict.UNKNOWN: 2,
    Verdict.INFO: 3,
    Verdict.HYBRID: 4,
    Verdict.SAFE: 5,
}

NIST_NOTE = "NIST IR 8547: deprecated after 2030, disallowed after 2035"

# canonical name -> (category, verdict, note)
ALGO_DB = {
    # --- classical public key (Shor) ---
    "RSA": ("asymmetric", Verdict.VULNERABLE, NIST_NOTE),
    "RSA-OAEP": ("key-transport", Verdict.VULNERABLE, NIST_NOTE),
    "RSA-PSS": ("signature", Verdict.VULNERABLE, NIST_NOTE),
    "RSA-PKCS1-SHA1": ("signature", Verdict.VULNERABLE, "SHA-1 signature; " + NIST_NOTE),
    "RSA-PKCS1-MD5": ("signature", Verdict.VULNERABLE, "MD5 signature: classically broken"),
    "RSA-PKCS1-SHA256": ("signature", Verdict.VULNERABLE, NIST_NOTE),
    "RSA-PKCS1-SHA384": ("signature", Verdict.VULNERABLE, NIST_NOTE),
    "RSA-PKCS1-SHA512": ("signature", Verdict.VULNERABLE, NIST_NOTE),
    "DSA": ("signature", Verdict.VULNERABLE, "DSA is already deprecated (FIPS 186-5); " + NIST_NOTE),
    "DH": ("key-exchange", Verdict.VULNERABLE, NIST_NOTE),
    "ElGamal": ("key-transport", Verdict.VULNERABLE, NIST_NOTE),
    "ECDSA": ("signature", Verdict.VULNERABLE, NIST_NOTE),
    "ECDH": ("key-exchange", Verdict.VULNERABLE, NIST_NOTE),
    "EdDSA": ("signature", Verdict.VULNERABLE, NIST_NOTE),
    "Ed25519": ("signature", Verdict.VULNERABLE, NIST_NOTE),
    "Ed448": ("signature", Verdict.VULNERABLE, NIST_NOTE),
    "X25519": ("key-exchange", Verdict.VULNERABLE, NIST_NOTE),
    "X448": ("key-exchange", Verdict.VULNERABLE, NIST_NOTE),
    "P-256": ("ec-curve", Verdict.VULNERABLE, NIST_NOTE),
    "P-384": ("ec-curve", Verdict.VULNERABLE, NIST_NOTE),
    "P-521": ("ec-curve", Verdict.VULNERABLE, NIST_NOTE),
    "P-224": ("ec-curve", Verdict.VULNERABLE, "112-bit classical security; " + NIST_NOTE),
    "secp256k1": ("ec-curve", Verdict.VULNERABLE, NIST_NOTE),
    "brainpoolP256r1": ("ec-curve", Verdict.VULNERABLE, NIST_NOTE),
    "brainpoolP384r1": ("ec-curve", Verdict.VULNERABLE, NIST_NOTE),
    "brainpoolP512r1": ("ec-curve", Verdict.VULNERABLE, NIST_NOTE),
    "Curve25519": ("ec-curve", Verdict.VULNERABLE, NIST_NOTE),
    "FFDHE": ("key-exchange", Verdict.VULNERABLE, NIST_NOTE),

    # --- symmetric ---
    "AES-128": ("symmetric", Verdict.SAFE, "Grover halves the exponent; NIST still rates AES-128 acceptable, prefer AES-256 for long-lived data"),
    "AES-192": ("symmetric", Verdict.SAFE, ""),
    "AES-256": ("symmetric", Verdict.SAFE, "128-bit post-quantum security"),
    "AES": ("symmetric", Verdict.SAFE, "key size unknown; AES-256 recommended"),
    "ChaCha20-Poly1305": ("symmetric", Verdict.SAFE, "256-bit key"),
    "ChaCha20": ("symmetric", Verdict.SAFE, "256-bit key"),
    "Camellia-128": ("symmetric", Verdict.SAFE, "prefer 256-bit keys"),
    "Camellia-256": ("symmetric", Verdict.SAFE, ""),
    "Twofish": ("symmetric", Verdict.SAFE, "256-bit key"),
    "Serpent": ("symmetric", Verdict.SAFE, ""),
    "3DES": ("symmetric", Verdict.WEAK, "112-bit effective, 64-bit block (Sweet32); NIST disallowed after 2023"),
    "DES": ("symmetric", Verdict.WEAK, "56-bit key: broken"),
    "RC4": ("symmetric", Verdict.WEAK, "broken stream cipher (RFC 7465)"),
    "RC2": ("symmetric", Verdict.WEAK, "legacy, 40-128 bit"),
    "IDEA": ("symmetric", Verdict.WEAK, "128-bit key but 64-bit block, legacy"),
    "CAST5": ("symmetric", Verdict.WEAK, "128-bit key, 64-bit block, legacy"),
    "Blowfish": ("symmetric", Verdict.WEAK, "64-bit block (Sweet32)"),
    "ZipCrypto": ("symmetric", Verdict.WEAK, "PKWARE traditional encryption: classically broken (known-plaintext)"),

    # --- hashes / MAC / KDF ---
    "MD5": ("hash", Verdict.WEAK, "collision-broken"),
    "SHA-1": ("hash", Verdict.WEAK, "collision-broken (SHAttered); disallowed for signatures"),
    "RIPEMD-160": ("hash", Verdict.WEAK, "160-bit, legacy"),
    "SHA-224": ("hash", Verdict.SAFE, "112-bit collision resistance, prefer SHA-256+"),
    "SHA-256": ("hash", Verdict.SAFE, ""),
    "SHA-384": ("hash", Verdict.SAFE, ""),
    "SHA-512": ("hash", Verdict.SAFE, ""),
    "SHA3-256": ("hash", Verdict.SAFE, ""),
    "SHA3-512": ("hash", Verdict.SAFE, ""),
    "SHAKE128": ("hash", Verdict.SAFE, ""),
    "SHAKE256": ("hash", Verdict.SAFE, ""),
    "HMAC-SHA1": ("mac", Verdict.SAFE, "HMAC-SHA1 is still acceptable as a MAC, but migrate to SHA-2"),
    "HMAC-MD5": ("mac", Verdict.WEAK, "legacy"),
    "HMAC-SHA256": ("mac", Verdict.SAFE, ""),
    "HMAC-SHA512": ("mac", Verdict.SAFE, ""),
    "UMAC": ("mac", Verdict.SAFE, ""),
    "Poly1305": ("mac", Verdict.SAFE, ""),
    "PBKDF2": ("kdf", Verdict.SAFE, "strength depends on iteration count and password"),
    "scrypt": ("kdf", Verdict.SAFE, "memory-hard KDF"),
    "Argon2": ("kdf", Verdict.SAFE, "memory-hard KDF"),
    "bcrypt": ("kdf", Verdict.SAFE, ""),
    "AES-KDF": ("kdf", Verdict.SAFE, "KeePass legacy KDF, prefer Argon2"),
    "PBES2": ("kdf", Verdict.SAFE, "PKCS#5 v2 password-based encryption"),
    "PBE-SHA1-3DES": ("kdf", Verdict.WEAK, "PKCS#12 legacy PBE with 3DES"),
    "PBE-SHA1-RC2-40": ("kdf", Verdict.WEAK, "PKCS#12 legacy PBE with 40-bit RC2"),
    "PBE-SHA1-RC4-128": ("kdf", Verdict.WEAK, "PKCS#12 legacy PBE with RC4"),
    "PBE-MD2-DES": ("kdf", Verdict.WEAK, "PKCS#5 v1 PBES1: MD2 + 56-bit DES, obsolete"),
    "PBE-MD5-DES": ("kdf", Verdict.WEAK, "PKCS#5 v1 PBES1: MD5 + 56-bit DES, obsolete (LibreSSL/old OpenSSL pkcs8 default)"),
    "PBE-SHA1-DES": ("kdf", Verdict.WEAK, "PKCS#5 v1 PBES1: 56-bit DES, obsolete"),
    "PBE-SHA1-RC2-64": ("kdf", Verdict.WEAK, "PKCS#5 v1 PBES1: 64-bit RC2, obsolete"),
    "SMIMECapabilities": ("attribute", Verdict.INFO, "signer-advertised capability list, not what this file uses"),

    # --- post-quantum ---
    "ML-KEM-512": ("pqc-kem", Verdict.SAFE, "FIPS 203, NIST level 1"),
    "ML-KEM-768": ("pqc-kem", Verdict.SAFE, "FIPS 203, NIST level 3"),
    "ML-KEM-1024": ("pqc-kem", Verdict.SAFE, "FIPS 203, NIST level 5"),
    "ML-KEM": ("pqc-kem", Verdict.SAFE, "FIPS 203"),
    "Kyber": ("pqc-kem", Verdict.SAFE, "pre-standard ML-KEM; migrate to FIPS 203 codepoints"),
    "ML-DSA-44": ("pqc-sig", Verdict.SAFE, "FIPS 204"),
    "ML-DSA-65": ("pqc-sig", Verdict.SAFE, "FIPS 204"),
    "ML-DSA-87": ("pqc-sig", Verdict.SAFE, "FIPS 204"),
    "ML-DSA": ("pqc-sig", Verdict.SAFE, "FIPS 204"),
    "Dilithium": ("pqc-sig", Verdict.SAFE, "pre-standard ML-DSA"),
    "SLH-DSA": ("pqc-sig", Verdict.SAFE, "FIPS 205 (SPHINCS+)"),
    "SPHINCS+": ("pqc-sig", Verdict.SAFE, "pre-standard SLH-DSA"),
    "FN-DSA": ("pqc-sig", Verdict.SAFE, "FIPS 206 draft (Falcon)"),
    "Falcon": ("pqc-sig", Verdict.SAFE, "pre-standard FN-DSA"),
    "HQC": ("pqc-kem", Verdict.SAFE, "NIST 4th round selection (2025), standard pending"),
    "BIKE": ("pqc-kem", Verdict.SAFE, "not selected by NIST, research only"),
    "NTRU": ("pqc-kem", Verdict.SAFE, "not standardized by NIST"),
    "sntrup761": ("pqc-kem", Verdict.SAFE, "NTRU Prime, OpenSSH"),
    "FrodoKEM": ("pqc-kem", Verdict.SAFE, "ISO track, not NIST"),
    "XMSS": ("pqc-sig", Verdict.SAFE, "stateful hash-based (SP 800-208)"),
    "LMS": ("pqc-sig", Verdict.SAFE, "stateful hash-based (SP 800-208)"),

    # --- hybrids ---
    "X25519MLKEM768": ("hybrid-kex", Verdict.HYBRID, "IETF hybrid, recommended default"),
    "SecP256r1MLKEM768": ("hybrid-kex", Verdict.HYBRID, "IETF hybrid"),
    "SecP384r1MLKEM1024": ("hybrid-kex", Verdict.HYBRID, "IETF hybrid, CNSA 2.0 level"),
    "X25519Kyber768Draft00": ("hybrid-kex", Verdict.HYBRID, "obsolete draft codepoint, migrate to X25519MLKEM768"),
    "SecP256r1Kyber768Draft00": ("hybrid-kex", Verdict.HYBRID, "obsolete draft codepoint"),
    "mlkem768x25519-sha256": ("hybrid-kex", Verdict.HYBRID, "OpenSSH 9.9+ default"),
    "sntrup761x25519-sha512": ("hybrid-kex", Verdict.HYBRID, "OpenSSH 9.0+ default"),
    "mlkem768nistp256-sha256": ("hybrid-kex", Verdict.HYBRID, ""),
    "mlkem1024nistp384-sha384": ("hybrid-kex", Verdict.HYBRID, ""),
    "ML-KEM-768+X25519": ("hybrid-kex", Verdict.HYBRID, "OpenPGP PQC draft"),
    "ML-KEM-1024+X448": ("hybrid-kex", Verdict.HYBRID, "OpenPGP PQC draft"),
    "ML-DSA-65+Ed25519": ("hybrid-sig", Verdict.HYBRID, "OpenPGP PQC draft"),
    "ML-DSA-87+Ed448": ("hybrid-sig", Verdict.HYBRID, "OpenPGP PQC draft"),
}

# Aliases that map to canonical names.
ALIASES = {
    "prime256v1": "P-256", "secp256r1": "P-256", "nistp256": "P-256",
    "secp384r1": "P-384", "nistp384": "P-384",
    "secp521r1": "P-521", "nistp521": "P-521",
    "secp224r1": "P-224",
    "cv25519": "X25519", "curve25519": "X25519",
    "AES128": "AES-128", "AES256": "AES-256", "AES192": "AES-192",
    "SHA1": "SHA-1", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
    "TripleDES": "3DES", "DES-EDE3": "3DES",
}


def canonical(name: str) -> str:
    return ALIASES.get(name, name)


def classify(name: str, bits: Optional[int] = None) -> Tuple[str, Verdict, str]:
    """Return (category, verdict, note) for an algorithm name, with key-size hints."""
    name = canonical(name)
    entry = ALGO_DB.get(name)
    if entry is None:
        return ("unknown", Verdict.UNKNOWN, "algorithm not in knowledge base")
    cat, verdict, note = entry
    if bits:
        if name in ("RSA", "DSA", "DH", "ElGamal", "FFDHE", "RSA-OAEP", "RSA-PSS"):
            if bits < 2048:
                note = "%d-bit key is classically weak (<112-bit security); " % bits + note
            elif bits < 3072:
                note = "%d-bit key = 112-bit security, NIST disallows after 2030; " % bits + note
        if name == "AES" and bits in (128, 192, 256):
            return classify("AES-%d" % bits)
    return (cat, verdict, note)


# ---------------------------------------------------------------- OIDs ----
# dotted OID -> (algorithm name, role)
OIDS = {
    # RSA
    "1.2.840.113549.1.1.1": ("RSA", "public key"),
    "1.2.840.113549.1.1.4": ("RSA-PKCS1-MD5", "signature"),
    "1.2.840.113549.1.1.5": ("RSA-PKCS1-SHA1", "signature"),
    "1.2.840.113549.1.1.7": ("RSA-OAEP", "key transport"),
    "1.2.840.113549.1.1.10": ("RSA-PSS", "signature"),
    "1.2.840.113549.1.1.11": ("RSA-PKCS1-SHA256", "signature"),
    "1.2.840.113549.1.1.12": ("RSA-PKCS1-SHA384", "signature"),
    "1.2.840.113549.1.1.13": ("RSA-PKCS1-SHA512", "signature"),
    # DSA / DH
    "1.2.840.10040.4.1": ("DSA", "public key"),
    "1.2.840.10040.4.3": ("DSA", "signature (SHA-1)"),
    "2.16.840.1.101.3.4.3.2": ("DSA", "signature (SHA-256)"),
    "1.2.840.10046.2.1": ("DH", "public key"),
    "1.2.840.113549.1.3.1": ("DH", "key agreement"),
    # EC
    "1.2.840.10045.2.1": ("ECDH", "public key (ecPublicKey)"),
    "1.2.840.10045.4.1": ("ECDSA", "signature (SHA-1)"),
    "1.2.840.10045.4.3.1": ("ECDSA", "signature (SHA-224)"),
    "1.2.840.10045.4.3.2": ("ECDSA", "signature (SHA-256)"),
    "1.2.840.10045.4.3.3": ("ECDSA", "signature (SHA-384)"),
    "1.2.840.10045.4.3.4": ("ECDSA", "signature (SHA-512)"),
    "1.2.840.10045.3.1.7": ("P-256", "curve"),
    "1.3.132.0.34": ("P-384", "curve"),
    "1.3.132.0.35": ("P-521", "curve"),
    "1.3.132.0.33": ("P-224", "curve"),
    "1.3.132.0.10": ("secp256k1", "curve"),
    "1.3.36.3.3.2.8.1.1.7": ("brainpoolP256r1", "curve"),
    "1.3.36.3.3.2.8.1.1.11": ("brainpoolP384r1", "curve"),
    "1.3.36.3.3.2.8.1.1.13": ("brainpoolP512r1", "curve"),
    "1.3.101.110": ("X25519", "public key"),
    "1.3.101.111": ("X448", "public key"),
    "1.3.101.112": ("Ed25519", "public key / signature"),
    "1.3.101.113": ("Ed448", "public key / signature"),
    "1.3.6.1.4.1.11591.15.1": ("Ed25519", "curve (legacy OpenPGP OID)"),
    "1.3.6.1.4.1.3029.1.5.1": ("X25519", "curve (legacy OpenPGP OID)"),
    # ECDH key agreement in CMS
    "1.3.133.16.840.63.0.2": ("ECDH", "key agreement (SHA-1 KDF)"),
    "1.3.132.1.11.1": ("ECDH", "key agreement (SHA-256 KDF)"),
    "1.3.132.1.11.2": ("ECDH", "key agreement (SHA-384 KDF)"),
    "1.3.132.1.11.3": ("ECDH", "key agreement (SHA-512 KDF)"),
    # symmetric
    "2.16.840.1.101.3.4.1.2": ("AES-128", "content encryption (CBC)"),
    "2.16.840.1.101.3.4.1.5": ("AES-128", "key wrap"),
    "2.16.840.1.101.3.4.1.6": ("AES-128", "content encryption (GCM)"),
    "2.16.840.1.101.3.4.1.22": ("AES-192", "content encryption (CBC)"),
    "2.16.840.1.101.3.4.1.25": ("AES-192", "key wrap"),
    "2.16.840.1.101.3.4.1.26": ("AES-192", "content encryption (GCM)"),
    "2.16.840.1.101.3.4.1.42": ("AES-256", "content encryption (CBC)"),
    "2.16.840.1.101.3.4.1.45": ("AES-256", "key wrap"),
    "2.16.840.1.101.3.4.1.46": ("AES-256", "content encryption (GCM)"),
    "1.2.840.113549.3.7": ("3DES", "content encryption (CBC)"),
    "1.2.840.113549.1.9.16.3.6": ("3DES", "key wrap"),
    "1.3.14.3.2.7": ("DES", "content encryption (CBC)"),
    "1.2.840.113549.3.2": ("RC2", "content encryption"),
    "1.2.840.113549.3.4": ("RC4", "content encryption"),
    "1.2.840.113549.1.12.1.3": ("PBE-SHA1-3DES", "password-based encryption"),
    "1.2.840.113549.1.12.1.6": ("PBE-SHA1-RC2-40", "password-based encryption"),
    "1.2.840.113549.1.12.1.1": ("PBE-SHA1-RC4-128", "password-based encryption"),
    "1.2.840.113549.1.5.13": ("PBES2", "password-based encryption"),
    "1.2.840.113549.1.5.1": ("PBE-MD2-DES", "password-based encryption (PBES1)"),
    "1.2.840.113549.1.5.3": ("PBE-MD5-DES", "password-based encryption (PBES1)"),
    "1.2.840.113549.1.5.10": ("PBE-SHA1-DES", "password-based encryption (PBES1)"),
    "1.2.840.113549.1.5.11": ("PBE-SHA1-RC2-64", "password-based encryption (PBES1)"),
    "1.2.840.113549.1.9.15": ("SMIMECapabilities", "attribute"),
    "1.2.840.113549.1.5.12": ("PBKDF2", "key derivation"),
    "1.3.6.1.4.1.11591.4.11": ("scrypt", "key derivation"),
    # hashes / MAC
    "1.2.840.113549.2.5": ("MD5", "hash"),
    "1.3.14.3.2.26": ("SHA-1", "hash"),
    "2.16.840.1.101.3.4.2.4": ("SHA-224", "hash"),
    "2.16.840.1.101.3.4.2.1": ("SHA-256", "hash"),
    "2.16.840.1.101.3.4.2.2": ("SHA-384", "hash"),
    "2.16.840.1.101.3.4.2.3": ("SHA-512", "hash"),
    "2.16.840.1.101.3.4.2.8": ("SHA3-256", "hash"),
    "2.16.840.1.101.3.4.2.10": ("SHA3-512", "hash"),
    "1.2.840.113549.2.7": ("HMAC-SHA1", "mac"),
    "1.2.840.113549.2.9": ("HMAC-SHA256", "mac"),
    "1.2.840.113549.2.11": ("HMAC-SHA512", "mac"),
    # PQC (NIST CSOR arc)
    "2.16.840.1.101.3.4.4.1": ("ML-KEM-512", "KEM"),
    "2.16.840.1.101.3.4.4.2": ("ML-KEM-768", "KEM"),
    "2.16.840.1.101.3.4.4.3": ("ML-KEM-1024", "KEM"),
    "2.16.840.1.101.3.4.3.17": ("ML-DSA-44", "signature"),
    "2.16.840.1.101.3.4.3.18": ("ML-DSA-65", "signature"),
    "2.16.840.1.101.3.4.3.19": ("ML-DSA-87", "signature"),
    "2.16.840.1.101.3.4.3.20": ("SLH-DSA", "signature (SHA2-128s)"),
    "2.16.840.1.101.3.4.3.21": ("SLH-DSA", "signature (SHA2-128f)"),
    "2.16.840.1.101.3.4.3.22": ("SLH-DSA", "signature (SHA2-192s)"),
    "2.16.840.1.101.3.4.3.23": ("SLH-DSA", "signature (SHA2-192f)"),
    "2.16.840.1.101.3.4.3.24": ("SLH-DSA", "signature (SHA2-256s)"),
    "2.16.840.1.101.3.4.3.25": ("SLH-DSA", "signature (SHA2-256f)"),
    "2.16.840.1.101.3.4.3.26": ("SLH-DSA", "signature (SHAKE-128s)"),
    "2.16.840.1.101.3.4.3.27": ("SLH-DSA", "signature (SHAKE-128f)"),
    "2.16.840.1.101.3.4.3.28": ("SLH-DSA", "signature (SHAKE-192s)"),
    "2.16.840.1.101.3.4.3.29": ("SLH-DSA", "signature (SHAKE-192f)"),
    "2.16.840.1.101.3.4.3.30": ("SLH-DSA", "signature (SHAKE-256s)"),
    "2.16.840.1.101.3.4.3.31": ("SLH-DSA", "signature (SHAKE-256f)"),
    "1.3.9999.3.6": ("Falcon", "signature (OQS Falcon-512)"),
    "1.3.9999.3.9": ("Falcon", "signature (OQS Falcon-1024)"),
}

# Structural OIDs we recognise but do not grade (used for context labels only).
STRUCT_OIDS = {
    "1.2.840.113549.1.7.1": "CMS data",
    "1.2.840.113549.1.7.2": "CMS signedData",
    "1.2.840.113549.1.7.3": "CMS envelopedData",
    "1.2.840.113549.1.7.6": "CMS encryptedData",
    "1.2.840.113549.1.9.16.1.23": "CMS authEnvelopedData",
    "1.2.840.113549.1.9.16.13.3": "CMS KEMRecipientInfo",
    "1.2.840.113549.1.12.10.1.1": "PKCS#12 keyBag",
    "1.2.840.113549.1.12.10.1.2": "PKCS#12 pkcs8ShroudedKeyBag",
    "1.2.840.113549.1.12.10.1.3": "PKCS#12 certBag",
}

# ---------------------------------------------------------------- TLS -----
TLS_GROUPS = {
    23: "P-256", 24: "P-384", 25: "P-521", 29: "X25519", 30: "X448",
    256: "FFDHE", 257: "FFDHE", 258: "FFDHE", 259: "FFDHE", 260: "FFDHE",
    512: "ML-KEM-512", 513: "ML-KEM-768", 514: "ML-KEM-1024",
    4587: "SecP256r1MLKEM768", 4588: "X25519MLKEM768", 4589: "SecP384r1MLKEM1024",
    25497: "X25519Kyber768Draft00", 25498: "SecP256r1Kyber768Draft00",
}
TLS_GROUP_BITS = {256: 2048, 257: 3072, 258: 4096, 259: 6144, 260: 8192}
TLS_PQC_PROBE_GROUPS = [4588, 4587, 4589, 513, 514, 512, 25497]
TLS_CLASSICAL_PROBE_GROUPS = [29, 23, 24, 25, 256]

# ---------------------------------------------------------------- SSH -----
SSH_KEX = {
    "mlkem768x25519-sha256": "mlkem768x25519-sha256",
    "sntrup761x25519-sha512": "sntrup761x25519-sha512",
    "sntrup761x25519-sha512@openssh.com": "sntrup761x25519-sha512",
    "mlkem768nistp256-sha256": "mlkem768nistp256-sha256",
    "mlkem1024nistp384-sha384": "mlkem1024nistp384-sha384",
    "curve25519-sha256": "X25519",
    "curve25519-sha256@libssh.org": "X25519",
    "ecdh-sha2-nistp256": "ECDH",
    "ecdh-sha2-nistp384": "ECDH",
    "ecdh-sha2-nistp521": "ECDH",
    "diffie-hellman-group-exchange-sha256": "DH",
    "diffie-hellman-group14-sha256": "DH",
    "diffie-hellman-group16-sha512": "DH",
    "diffie-hellman-group18-sha512": "DH",
    "diffie-hellman-group14-sha1": "DH",
    "diffie-hellman-group1-sha1": "DH",
    "diffie-hellman-group-exchange-sha1": "DH",
}
SSH_KEX_BITS = {
    "diffie-hellman-group1-sha1": 1024, "diffie-hellman-group14-sha1": 2048,
    "diffie-hellman-group14-sha256": 2048, "diffie-hellman-group16-sha512": 4096,
    "diffie-hellman-group18-sha512": 8192,
}
SSH_HOSTKEY = {
    "ssh-rsa": ("RSA-PKCS1-SHA1", None), "rsa-sha2-256": ("RSA", None), "rsa-sha2-512": ("RSA", None),
    "ssh-dss": ("DSA", 1024),
    "ecdsa-sha2-nistp256": ("ECDSA", 256), "ecdsa-sha2-nistp384": ("ECDSA", 384), "ecdsa-sha2-nistp521": ("ECDSA", 521),
    "ssh-ed25519": ("Ed25519", 255), "ssh-ed448": ("Ed448", 448),
    "sk-ssh-ed25519@openssh.com": ("Ed25519", 255), "sk-ecdsa-sha2-nistp256@openssh.com": ("ECDSA", 256),
}
SSH_CIPHERS = {
    "chacha20-poly1305@openssh.com": "ChaCha20-Poly1305",
    "aes256-gcm@openssh.com": "AES-256", "aes256-ctr": "AES-256", "aes256-cbc": "AES-256",
    "aes192-ctr": "AES-192", "aes192-cbc": "AES-192",
    "aes128-gcm@openssh.com": "AES-128", "aes128-ctr": "AES-128", "aes128-cbc": "AES-128",
    "3des-cbc": "3DES", "arcfour": "RC4", "arcfour128": "RC4", "arcfour256": "RC4",
    "blowfish-cbc": "Blowfish", "cast128-cbc": "CAST5",
}
SSH_MACS = {
    "hmac-sha2-256": "HMAC-SHA256", "hmac-sha2-512": "HMAC-SHA512",
    "hmac-sha2-256-etm@openssh.com": "HMAC-SHA256", "hmac-sha2-512-etm@openssh.com": "HMAC-SHA512",
    "hmac-sha1": "HMAC-SHA1", "hmac-sha1-etm@openssh.com": "HMAC-SHA1", "hmac-sha1-96": "HMAC-SHA1",
    "hmac-md5": "HMAC-MD5", "hmac-md5-96": "HMAC-MD5", "hmac-md5-etm@openssh.com": "HMAC-MD5",
    "umac-64@openssh.com": "UMAC", "umac-128@openssh.com": "UMAC",
    "umac-64-etm@openssh.com": "UMAC", "umac-128-etm@openssh.com": "UMAC",
}

# ---------------------------------------------------------------- PGP -----
PGP_PUBKEY_ALGOS = {
    1: "RSA", 2: "RSA", 3: "RSA", 16: "ElGamal", 17: "DSA", 18: "ECDH", 19: "ECDSA",
    22: "EdDSA", 25: "X25519", 26: "X448", 27: "Ed25519", 28: "Ed448",
    # draft-ietf-openpgp-pqc codepoints
    30: "ML-DSA-65+Ed25519", 31: "ML-DSA-87+Ed448",
    32: "SLH-DSA", 33: "SLH-DSA", 34: "SLH-DSA",
    35: "ML-KEM-768+X25519", 36: "ML-KEM-1024+X448",
}
PGP_SYM_ALGOS = {
    1: "IDEA", 2: "3DES", 3: "CAST5", 4: "Blowfish", 7: "AES-128", 8: "AES-192", 9: "AES-256",
    10: "Twofish", 11: "Camellia-128", 12: "Camellia-192", 13: "Camellia-256",
}
PGP_HASH_ALGOS = {
    1: "MD5", 2: "SHA-1", 3: "RIPEMD-160", 8: "SHA-256", 9: "SHA-384", 10: "SHA-512",
    11: "SHA-224", 12: "SHA3-256", 14: "SHA3-512",
}
PGP_AEAD = {1: "EAX", 2: "OCB", 3: "GCM"}

# ---------------------------------------------------------------- JOSE ----
JOSE_ALGS = {
    "RS256": "RSA-PKCS1-SHA256", "RS384": "RSA-PKCS1-SHA384", "RS512": "RSA-PKCS1-SHA512",
    "PS256": "RSA-PSS", "PS384": "RSA-PSS", "PS512": "RSA-PSS",
    "ES256": "ECDSA", "ES384": "ECDSA", "ES512": "ECDSA", "ES256K": "ECDSA",
    "EdDSA": "EdDSA", "Ed25519": "Ed25519",
    "HS256": "HMAC-SHA256", "HS384": "HMAC-SHA512", "HS512": "HMAC-SHA512",
    "RSA1_5": "RSA", "RSA-OAEP": "RSA-OAEP", "RSA-OAEP-256": "RSA-OAEP",
    "ECDH-ES": "ECDH", "ECDH-ES+A128KW": "ECDH", "ECDH-ES+A256KW": "ECDH",
    "A128KW": "AES-128", "A256KW": "AES-256", "A128GCMKW": "AES-128", "A256GCMKW": "AES-256",
    "PBES2-HS256+A128KW": "PBKDF2", "PBES2-HS512+A256KW": "PBKDF2",
    "A128GCM": "AES-128", "A192GCM": "AES-192", "A256GCM": "AES-256",
    "A128CBC-HS256": "AES-128", "A256CBC-HS512": "AES-256",
    "ML-DSA-44": "ML-DSA-44", "ML-DSA-65": "ML-DSA-65", "ML-DSA-87": "ML-DSA-87",
}

"""Run: python3 -m unittest discover -s tests -v"""
import os
import struct
import unittest

from pqcheck.formats import analyze_file, analyze_bytes, analyze_pgp
from pqcheck.codescan import scan_text
from pqcheck.tlsprobe import build_client_hello
from pqcheck.knowledge import Verdict, classify
from pqcheck.report import worst, exit_code

FX = os.path.join(os.path.dirname(__file__), "fixtures")


def algos(findings):
    return {f.algorithm for f in findings}


def by_algo(findings, name):
    return [f for f in findings if f.algorithm == name]


class KnowledgeTests(unittest.TestCase):
    def test_classification(self):
        self.assertEqual(classify("RSA", 2048)[1], Verdict.VULNERABLE)
        self.assertEqual(classify("AES-256")[1], Verdict.SAFE)
        self.assertEqual(classify("X25519MLKEM768")[1], Verdict.HYBRID)
        self.assertEqual(classify("prime256v1")[1], Verdict.VULNERABLE)
        self.assertEqual(classify("3DES")[1], Verdict.WEAK)
        self.assertIn("classically weak", classify("RSA", 1024)[2])


class PemDerTests(unittest.TestCase):
    def test_rsa_key(self):
        f = analyze_file(os.path.join(FX, "rsa2048.key"))
        rsa = by_algo(f, "RSA")
        self.assertTrue(rsa and rsa[0].bits == 2048)
        self.assertEqual(worst(f), Verdict.VULNERABLE)

    def test_rsa_cert_pem_and_der(self):
        for name in ("rsa2048.crt", "rsa2048.der"):
            f = analyze_file(os.path.join(FX, name))
            self.assertIn("RSA-PKCS1-SHA256", algos(f))
            self.assertTrue(any(x.bits == 2048 for x in by_algo(f, "RSA")))

    def test_ec_cert(self):
        f = analyze_file(os.path.join(FX, "ec256.crt"))
        self.assertIn("ECDSA", algos(f))
        self.assertIn("P-256", algos(f))
        self.assertNotIn("RSA", algos(f))   # signature r/s must not be mistaken for an RSA modulus

    def test_cms_enveloped(self):
        f = analyze_file(os.path.join(FX, "enveloped_rsa.p7m"))
        self.assertIn("RSA", algos(f))
        self.assertIn("AES-256", algos(f))
        self.assertTrue(any("envelopedData" in x.note for x in f))

    def test_pkcs12(self):
        f = analyze_file(os.path.join(FX, "bundle.p12"))
        self.assertIn("PBE-SHA1-3DES", algos(f))
        self.assertEqual(worst(f), Verdict.WEAK)

    def test_encrypted_pkcs8(self):
        f = analyze_file(os.path.join(FX, "rsa2048.pk8"))
        self.assertIn("PBE-MD5-DES", algos(f))

    def test_dh_params(self):
        f = analyze_file(os.path.join(FX, "dh1024.pem"))
        self.assertEqual(by_algo(f, "DH")[0].bits, 1024)

    def test_pqc_oid_in_spki(self):
        # SubjectPublicKeyInfo with ML-DSA-65 OID and dummy key bits
        oid = bytes.fromhex("0609608648016503040312")           # 2.16.840.1.101.3.4.3.18
        algid = b"\x30" + bytes([len(oid)]) + oid
        bits = b"\x03\x05\x00\x01\x02\x03\x04"
        spki = b"\x30" + bytes([len(algid) + len(bits)]) + algid + bits
        f = analyze_bytes("t", spki)
        self.assertIn("ML-DSA-65", algos(f))
        self.assertEqual(worst(f), Verdict.SAFE)


class SshTests(unittest.TestCase):
    def test_openssh_private_unprotected(self):
        f = analyze_file(os.path.join(FX, "id_ed25519"))
        self.assertIn("Ed25519", algos(f))
        self.assertTrue(any("NOT passphrase-protected" in x.note for x in f))

    def test_openssh_private_rsa_encrypted(self):
        f = analyze_file(os.path.join(FX, "id_rsa"))
        self.assertEqual(by_algo(f, "RSA")[0].bits, 3072)
        self.assertIn("bcrypt", algos(f))

    def test_pubkey_line(self):
        f = analyze_file(os.path.join(FX, "id_ecdsa.pub"))
        self.assertEqual(by_algo(f, "ECDSA")[0].bits, 256)


class PgpTests(unittest.TestCase):
    def _pkt(self, tag, body):
        return bytes([0xC0 | tag, len(body)]) + body

    def test_rsa_pkesk_and_aes256(self):
        pkesk = self._pkt(1, b"\x03" + b"\x11" * 8 + b"\x01" + b"\x00\x08\xff")      # v3, RSA
        skesk = self._pkt(3, b"\x04\x09\x03\x08" + b"\x00" * 9)                        # v4, AES-256, iterated S2K SHA-256
        seipd = self._pkt(18, b"\x01" + b"\x00" * 20)
        f = analyze_pgp("t", pkesk + skesk + seipd)
        self.assertIn("RSA", algos(f))
        self.assertIn("AES-256", algos(f))
        self.assertIn("SHA-256", algos(f))
        self.assertEqual(worst(f), Verdict.VULNERABLE)

    def test_pqc_pkesk(self):
        pkesk = self._pkt(1, b"\x03" + b"\x11" * 8 + bytes([35]) + b"\x00")           # ML-KEM-768+X25519
        f = analyze_pgp("t", pkesk)
        self.assertEqual(worst(f), Verdict.HYBRID)

    def test_v4_key_ecdh_curve(self):
        oid = bytes.fromhex("2a8648ce3d030107")                                        # P-256
        body = b"\x04" + b"\x00" * 4 + b"\x12" + bytes([len(oid)]) + oid + b"\x00\x08\x04"
        f = analyze_pgp("t", self._pkt(6, body))
        self.assertIn("P-256", algos(f))
        self.assertIn("ECDH", algos(f))

    def test_old_format_rsa_key(self):
        body = b"\x04" + b"\x00" * 4 + b"\x01" + struct.pack(">H", 4096) + b"\xff" * 512
        pkt = bytes([0x80 | (6 << 2) | 1]) + struct.pack(">H", len(body)) + body
        f = analyze_pgp("t", pkt)
        self.assertEqual(by_algo(f, "RSA")[0].bits, 4096)


class ContainerTests(unittest.TestCase):
    def test_zipcrypto(self):
        f = analyze_file(os.path.join(FX, "zipcrypto.zip"))
        self.assertIn("ZipCrypto", algos(f))

    def test_age(self):
        f = analyze_file(os.path.join(FX, "test.age"))
        self.assertIn("X25519", algos(f))
        self.assertIn("scrypt", algos(f))

    def test_jwt_jwks(self):
        self.assertIn("RSA-PKCS1-SHA256", algos(analyze_file(os.path.join(FX, "token.jwt"))))
        f = analyze_file(os.path.join(FX, "jwks.json"))
        self.assertIn("P-256", algos(f))
        self.assertTrue(by_algo(f, "RSA")[0].bits >= 2040)

    def test_pdf_aes256(self):
        pdf = b"%PDF-1.7\n1 0 obj << /Filter /Standard /V 5 /R 6 /Length 256 /CF << /StdCF << /CFM /AESV3 >> >> >> endobj\ntrailer << /Encrypt 1 0 R >>"
        self.assertIn("AES-256", algos(analyze_bytes("t", pdf)))

    def test_luks1(self):
        hdr = bytearray(1024)
        hdr[0:6] = b"LUKS\xba\xbe"; hdr[6:8] = b"\x00\x01"
        hdr[8:11] = b"aes"; hdr[40:51] = b"xts-plain64"; hdr[72:78] = b"sha256"; hdr[108:112] = struct.pack(">I", 64)
        f = analyze_bytes("t", bytes(hdr))
        self.assertEqual(by_algo(f, "AES")[0].bits, 256)
        self.assertEqual(worst(f), Verdict.SAFE)

    def test_kdbx(self):
        head = b"\x03\xd9\xa2\x9a\x67\xfb\x4b\xb5" + b"\x00\x00\x04\x00" + bytes.fromhex("31c1f2e6bf714350be5805216afc5aff") + bytes.fromhex("ef636ddf8c29444b91f7a9a403e30a0c")
        f = analyze_bytes("t", head)
        self.assertIn("AES-256", algos(f))
        self.assertIn("Argon2", algos(f))

    def test_unknown(self):
        self.assertEqual(worst(analyze_file(os.path.join(FX, "plain.txt"))), Verdict.UNKNOWN)


class CodeScanTests(unittest.TestCase):
    def test_hybrid_masks_components(self):
        f = scan_text("t", b'group = "X25519MLKEM768"\n')
        self.assertEqual(algos(f), {"X25519MLKEM768"})

    def test_mixed(self):
        f = scan_text("t", b"KexAlgorithms sntrup761x25519-sha512,curve25519-sha256\nCiphers 3des-cbc\nhashlib.md5\nrsa.generate_private_key(65537, 4096) # RSA-4096\n")
        self.assertIn("sntrup761x25519-sha512", algos(f))
        self.assertIn("X25519", algos(f))
        self.assertIn("3DES", algos(f))
        self.assertIn("MD5", algos(f))
        self.assertEqual(by_algo(f, "RSA")[0].bits, 4096)


class TlsTests(unittest.TestCase):
    def test_client_hello_shape(self):
        ch = build_client_hello("example.com", [4588, 29])
        self.assertEqual(ch[:3], b"\x16\x03\x01")
        self.assertEqual(struct.unpack(">H", ch[3:5])[0], len(ch) - 5)
        self.assertEqual(ch[5], 0x01)
        self.assertIn(struct.pack(">H", 4588), ch)
        self.assertIn(b"example.com", ch)


class ExitCodeTests(unittest.TestCase):
    def test_codes(self):
        f = analyze_file(os.path.join(FX, "rsa2048.key"))
        self.assertEqual(exit_code(f), 2)
        self.assertEqual(exit_code(f, "never"), 0)
        z = analyze_file(os.path.join(FX, "zipcrypto.zip"))
        self.assertEqual(exit_code(z), 0)
        self.assertEqual(exit_code(z, "weak"), 1)


if __name__ == "__main__":
    unittest.main()

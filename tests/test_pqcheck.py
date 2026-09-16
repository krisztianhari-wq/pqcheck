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

    def test_encrypted_pkcs8_pbes1(self):
        f = analyze_file(os.path.join(FX, "rsa2048.pk8"))
        self.assertTrue(any(a.startswith("PBE-") for a in algos(f)), algos(f))   # PBE-MD5-DES or PBE-SHA1-3DES
        self.assertEqual(worst(f), Verdict.WEAK)

    def test_encrypted_pkcs8_pbes2(self):
        f = analyze_file(os.path.join(FX, "rsa2048_pbes2.pk8"))
        self.assertIn("PBES2", algos(f))
        self.assertIn("AES-256", algos(f))
        self.assertEqual(worst(f), Verdict.SAFE)

    def test_dh_params(self):
        f = analyze_file(os.path.join(FX, "dh1024.pem"))
        self.assertTrue(by_algo(f, "DH"), [x.algorithm + ":" + x.note for x in f])
        self.assertEqual(by_algo(f, "DH")[0].bits, 1024)

    def test_dh_params_x942_label(self):
        # X9.42 style: SEQUENCE { p, g, q } with a dotted PEM label
        p = b"\x02\x81\x81\x00" + b"\xff" * 128
        body = p + b"\x02\x01\x02" + b"\x02\x02\x7f\xff"
        der = b"\x30\x81" + bytes([len(body)]) + body
        import base64
        pem = b"-----BEGIN X9.42 DH PARAMETERS-----\n" + base64.encodebytes(der) + b"-----END X9.42 DH PARAMETERS-----\n"
        f = analyze_bytes("t", pem)
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


class StoreTests(unittest.TestCase):
    def test_roundtrip_and_export(self):
        import tempfile
        from pqcheck.store import Store
        with tempfile.TemporaryDirectory() as d:
            st = Store(os.path.join(d, "h.db"))
            f = analyze_file(os.path.join(FX, "rsa2048.crt"))
            rid = st.save_run("file", ["rsa2048.crt"], f)
            self.assertEqual(rid, 1)
            runs = st.runs()
            self.assertEqual(runs[0]["overall"], "QUANTUM_VULNERABLE")
            self.assertEqual(runs[0]["targets"], ["rsa2048.crt"])
            back = st.findings(rid)
            self.assertEqual(len(back), len(f))
            self.assertEqual(back[0].verdict, f[0].verdict)
            inv = st.latest_per_target()
            self.assertEqual(inv[0]["overall"], "QUANTUM_VULNERABLE")
            csv_text = st.export("csv")
            self.assertIn("run_id,ts,command", csv_text.splitlines()[0])
            self.assertEqual(len(csv_text.strip().splitlines()), len(f) + 1)
            js = __import__("json").loads(st.export("json", rid))
            self.assertEqual(len(js), len(f))
            st.delete_run(rid)
            self.assertEqual(st.runs(), [])
            st.close()


class WebProbeTests(unittest.TestCase):
    def test_site_heuristic(self):
        from pqcheck.webprobe import _site
        self.assertEqual(_site("static.yettel.hu"), "yettel.hu")
        self.assertEqual(_site("www.yettel.hu"), "yettel.hu")
        self.assertEqual(_site("a.b.example.co.uk"), "example.co.uk")
        self.assertNotEqual(_site("cdn.jsdelivr.net"), _site("www.yettel.hu"))

    def test_suite_families(self):
        from pqcheck.webprobe import FS_SUITES, STATIC_RSA_SUITES, WEAK_SUITES, SUITES
        self.assertIn(0xC030, FS_SUITES)
        self.assertIn(0x009D, STATIC_RSA_SUITES)
        self.assertIn(0x000A, WEAK_SUITES)
        self.assertFalse(set(FS_SUITES) & set(STATIC_RSA_SUITES))
        self.assertTrue(all(c in SUITES for c in FS_SUITES + STATIC_RSA_SUITES + WEAK_SUITES))

    def test_legacy_client_hello(self):
        ch = build_client_hello("example.com", [23], versions=(0x0303,), suites=(0xC030, 0x009D))
        self.assertEqual(ch[:3], b"\x16\x03\x01")
        self.assertEqual(ch[9:11], b"\x03\x03")          # legacy_version inside ClientHello
        self.assertNotIn(struct.pack(">HH", 43, 5), ch)   # no supported_versions extension
        self.assertNotIn(struct.pack(">HH", 51, 0), ch)   # no key_share extension


class GuiDetectTests(unittest.TestCase):
    def test_detect(self):
        from pqcheck.gui import detect_command
        self.assertEqual(detect_command("file", "https://www.cetin.hu/"), "web")
        self.assertEqual(detect_command("file", "cetin.hu:443"), "tls")
        self.assertEqual(detect_command("file", "cetin.hu"), "tls")
        self.assertEqual(detect_command("file", "bastion.example.com:22"), "ssh")
        self.assertEqual(detect_command("file", os.path.join(FX, "rsa2048.crt")), "file")
        self.assertEqual(detect_command("file", "missing.example.pem"), "file")
        self.assertEqual(detect_command("tls", "anything"), "tls")


class PortDiscoveryTests(unittest.TestCase):
    def test_split_hostport(self):
        from pqcheck.ports import split_hostport
        self.assertEqual(split_hostport("example.com", "tls"), ("example.com", None))
        self.assertEqual(split_hostport("example.com:8443", "tls"), ("example.com", 8443))
        self.assertEqual(split_hostport("[::1]:2222", "ssh"), ("::1", 2222))
        self.assertEqual(split_hostport("[::1]", "ssh"), ("::1", None))

    def test_open_ports_with_local_listener(self):
        import socket
        from pqcheck.ports import open_ports, resolve_ports
        srv = socket.socket(); srv.bind(("127.0.0.1", 0)); srv.listen(1)
        port = srv.getsockname()[1]
        closed = socket.socket(); closed.bind(("127.0.0.1", 0)); dead = closed.getsockname()[1]; closed.close()
        try:
            self.assertEqual(open_ports("127.0.0.1", [dead, port], timeout=1.0), [port])
            host, ports, note = resolve_ports("127.0.0.1:%d" % port, "tls")
            self.assertEqual((host, ports, note), ("127.0.0.1", [port], None))
        finally:
            srv.close()

    def test_resolve_ports_none_open_falls_back_to_default(self):
        from pqcheck import ports as P
        saved = P.WELL_KNOWN["ssh"]
        P.WELL_KNOWN["ssh"] = [1, 2]          # nothing listens there
        try:
            host, found, note = P.resolve_ports("127.0.0.1", "ssh", timeout=0.5)
            self.assertEqual(found, [22])
            self.assertIn("no well-known SSH port answered", note)
        finally:
            P.WELL_KNOWN["ssh"] = saved


class BatchTests(unittest.TestCase):
    def test_csv_with_header(self):
        from pqcheck.batch import parse_list
        rows, errs = parse_list(b"kind;host;port;note\ntls;www.example.com;;x\nssh;10.0.0.5;;\nweb;https://a.example.com;;\n;b.example.com;8443;\n;c.example.com;22;\nbad;d.example.com;;\ntls;e.example.com;99999;\n", "list.csv")
        self.assertEqual([r.target for r in rows], ["www.example.com", "10.0.0.5", "https://a.example.com", "b.example.com:8443", "c.example.com:22"])
        self.assertEqual([r.kind for r in rows], ["tls", "ssh", "web", "tls", "ssh"])
        self.assertEqual([e.error.split(" ")[0] for e in errs], ["unknown", "invalid"])

    def test_headerless_variants(self):
        from pqcheck.batch import parse_list
        rows, errs = parse_list(b"# comment\nexample.com\nexample.org,8443\nssh,bastion.example.com\nweb,https://x.example.com,\nexample.com\n", "hosts.txt")
        self.assertEqual([(r.kind, r.target) for r in rows],
                         [("tls", "example.com"), ("tls", "example.org:8443"), ("ssh", "bastion.example.com"), ("web", "https://x.example.com")])
        self.assertFalse(errs)

    def test_xlsx(self):
        import zipfile, io
        from pqcheck.batch import parse_list
        buf = io.BytesIO()
        with zipfile.ZipFile(buf, "w") as z:
            z.writestr("xl/workbook.xml", '<workbook xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main" xmlns:r="http://schemas.openxmlformats.org/officeDocument/2006/relationships"><sheets><sheet name="S" sheetId="1" r:id="rId1"/></sheets></workbook>')
            z.writestr("xl/_rels/workbook.xml.rels", '<Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships"><Relationship Id="rId1" Type="x" Target="worksheets/sheet1.xml"/></Relationships>')
            z.writestr("xl/sharedStrings.xml", '<sst xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><si><t>host</t></si><si><t>port</t></si><si><t>example.com</t></si><si><t>kind</t></si><si><t>ssh</t></si></sst>')
            z.writestr("xl/worksheets/sheet1.xml", '<worksheet xmlns="http://schemas.openxmlformats.org/spreadsheetml/2006/main"><sheetData>'
                       '<row r="1"><c r="A1" t="s"><v>3</v></c><c r="B1" t="s"><v>0</v></c><c r="C1" t="s"><v>1</v></c></row>'
                       '<row r="2"><c r="A2" t="s"><v>4</v></c><c r="B2" t="s"><v>2</v></c><c r="C2"><v>2222</v></c></row>'
                       '<row r="3"><c r="B3" t="inlineStr"><is><t>10.1.2.3</t></is></c><c r="C3"><v>8443.0</v></c></row>'
                       '</sheetData></worksheet>')
        rows, errs = parse_list(buf.getvalue(), "hosts.xlsx")
        self.assertEqual([(r.kind, r.target) for r in rows], [("ssh", "example.com:2222"), ("tls", "10.1.2.3:8443")])
        self.assertFalse(errs)

    def test_template_parses(self):
        from pqcheck.batch import parse_list, TEMPLATE_CSV
        rows, errs = parse_list(TEMPLATE_CSV.encode(), "template.csv")
        self.assertEqual(len(rows), 7)
        self.assertFalse(errs)

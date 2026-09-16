"""TLS 1.3 key-exchange group probing with a hand-built ClientHello.

We offer a supported_groups list but an EMPTY key_share vector (allowed by
RFC 8446 4.2.8). A server that supports one of the offered groups answers
with HelloRetryRequest naming that group; one that does not sends an alert.
This needs no local PQC library, so it works on top of any Python/OpenSSL.
"""
import os
import socket
import ssl
import struct
from typing import List, Optional, Tuple

from .knowledge import TLS_GROUPS, TLS_GROUP_BITS, TLS_PQC_PROBE_GROUPS, TLS_CLASSICAL_PROBE_GROUPS, Verdict
from .report import Finding, worst
from .formats import analyze_der

HRR_RANDOM = bytes.fromhex("CF21AD74E59A6111BE1D8C021E65B891C2A211167ABB8C5E079E09E2C8A8339C")
ALERTS = {40: "handshake_failure", 47: "illegal_parameter", 70: "protocol_version", 109: "missing_extension",
          112: "unrecognized_name", 80: "internal_error", 0: "close_notify", 10: "unexpected_message",
          50: "decode_error", 71: "insufficient_security"}


def _ext(t, body):
    return struct.pack(">HH", t, len(body)) + body


def build_client_hello(sni: str, groups: List[int]) -> bytes:
    suites = b"".join(struct.pack(">H", s) for s in (0x1301, 0x1302, 0x1303, 0xC02C, 0xC030, 0xC02B, 0xC02F, 0x009D))
    sigalgs = b"".join(struct.pack(">H", s) for s in (0x0403, 0x0503, 0x0603, 0x0804, 0x0805, 0x0806,
                                                       0x0401, 0x0501, 0x0601, 0x0807, 0x0808, 0x0904, 0x0905, 0x0906))
    grp = b"".join(struct.pack(">H", g) for g in groups)
    host = sni.encode("idna")
    exts = b""
    exts += _ext(0, struct.pack(">HBH", len(host) + 3, 0, len(host)) + host)
    exts += _ext(10, struct.pack(">H", len(grp)) + grp)
    exts += _ext(11, b"\x01\x00")
    exts += _ext(13, struct.pack(">H", len(sigalgs)) + sigalgs)
    exts += _ext(43, b"\x04\x03\x04\x03\x03")
    exts += _ext(45, b"\x01\x01")
    exts += _ext(51, b"\x00\x00")   # empty client_shares -> request HRR
    body = b"\x03\x03" + os.urandom(32) + b"\x20" + os.urandom(32)
    body += struct.pack(">H", len(suites)) + suites + b"\x01\x00"
    body += struct.pack(">H", len(exts)) + exts
    hs = b"\x01" + struct.pack(">I", len(body))[1:] + body
    return b"\x16\x03\x01" + struct.pack(">H", len(hs)) + hs


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            raise ConnectionError("connection closed")
        buf += chunk
    return buf


def _read_record(sock):
    hdr = _recv_exact(sock, 5)
    typ, ln = hdr[0], struct.unpack(">H", hdr[3:5])[0]
    return typ, _recv_exact(sock, ln)


def probe_groups(host: str, port: int, groups: List[int], timeout: float = 5.0) -> Tuple[str, Optional[int], str]:
    """Returns (status, selected_group, detail). status in hrr|tls12|alert|error|serverhello."""
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(build_client_hello(host, groups))
            typ, rec = _read_record(s)
            if typ == 0x15:
                return "alert", None, ALERTS.get(rec[1], "alert %d" % rec[1]) if len(rec) >= 2 else "alert"
            if typ != 0x16 or rec[0] != 0x02:
                return "error", None, "unexpected record type %d" % typ
            p = 4
            p += 2                       # legacy_version
            rnd = rec[p:p + 32]; p += 32
            sidl = rec[p]; p += 1 + sidl
            p += 2 + 1                   # cipher, compression
            extl = struct.unpack(">H", rec[p:p + 2])[0]; p += 2
            exts = rec[p:p + extl]
            e = 0
            selected = None
            tls13 = False
            while e + 4 <= len(exts):
                et, el = struct.unpack(">HH", exts[e:e + 4])
                ev = exts[e + 4:e + 4 + el]
                if et == 43:
                    tls13 = ev == b"\x03\x04"
                if et == 51 and len(ev) >= 2:
                    selected = struct.unpack(">H", ev[:2])[0]
                e += 4 + el
            if not tls13:
                return "tls12", None, "server negotiated TLS 1.2 (classical ECDHE/RSA key exchange)"
            if rnd == HRR_RANDOM:
                return "hrr", selected, "HelloRetryRequest"
            return "serverhello", selected, "ServerHello without HRR (server picked a group without our key share)"
    except socket.timeout:
        return "error", None, "timeout"
    except (OSError, ConnectionError, struct.error, IndexError) as ex:
        return "error", None, str(ex)


def fetch_cert(host: str, port: int, timeout: float = 5.0) -> Optional[bytes]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            with ctx.wrap_socket(s, server_hostname=host) as ss:
                return ss.getpeercert(binary_form=True)
    except (OSError, ssl.SSLError):
        return None


def probe_tls(hostport: str, timeout: float = 5.0) -> List[Finding]:
    host, _, port = hostport.partition(":")
    port = int(port) if port else 443
    target = "tls://%s:%d" % (host, port)
    findings = []

    # 1. server preference among everything we know
    status, sel, detail = probe_groups(host, port, TLS_PQC_PROBE_GROUPS + TLS_CLASSICAL_PROBE_GROUPS, timeout)
    if status == "error":
        return [Finding.info(target, "TLS", "cannot probe: %s" % detail, Verdict.UNKNOWN)]
    if status == "tls12":
        findings.append(Finding.info(target, "TLS version", "TLS 1.2 only: no PQC key exchange possible", Verdict.VULNERABLE))
    elif status in ("hrr", "serverhello") and sel is not None:
        name = TLS_GROUPS.get(sel, "group 0x%04x" % sel)
        findings.append(Finding.make(target, "TLS 1.3 preferred group", name, bits=TLS_GROUP_BITS.get(sel),
                                     role="server choice when all groups offered"))
    else:
        findings.append(Finding.info(target, "TLS", "no group selected: %s" % detail, Verdict.UNKNOWN))

    # 2. individual PQC groups
    supported = []
    for g in TLS_PQC_PROBE_GROUPS:
        st, s2, d2 = probe_groups(host, port, [g], timeout)
        if st in ("hrr", "serverhello") and s2 == g:
            supported.append(g)
            findings.append(Finding.make(target, "TLS 1.3 group probe", TLS_GROUPS[g], role="supported"))
    if not supported and status != "tls12":
        findings.append(Finding.info(target, "TLS 1.3 group probe", "no ML-KEM / Kyber group accepted: key exchange is purely classical",
                                     Verdict.VULNERABLE))

    # 3. classical fallback groups (informational)
    classical = []
    for g in TLS_CLASSICAL_PROBE_GROUPS:
        st, s2, d2 = probe_groups(host, port, [g], timeout)
        if st in ("hrr", "serverhello", "tls12") and (s2 == g or st == "tls12"):
            classical.append(TLS_GROUPS[g])
    if classical:
        findings.append(Finding.info(target, "TLS classical groups", "also accepts: " + ", ".join(dict.fromkeys(classical))))

    # 4. certificate
    der = fetch_cert(host, port, timeout)
    cert_findings = []
    if der:
        r = analyze_der(target, der, "leaf certificate")
        if r:
            cert_findings = [f for f in r if f.algorithm != "-"]
    findings.extend(cert_findings)

    # 5. split verdict: key exchange (HNDL-exposed) vs authentication (not HNDL-exposed)
    kex_v = Verdict.VULNERABLE
    if supported:
        kex_v = Verdict.HYBRID if any(TLS_GROUPS[g].endswith(("MLKEM768", "MLKEM1024", "Draft00")) for g in supported) else Verdict.SAFE
    auth = ", ".join(dict.fromkeys(f.label() for f in cert_findings if f.category in ("signature", "asymmetric", "ec-curve")))
    auth_v = worst(cert_findings) if cert_findings else Verdict.UNKNOWN
    findings.insert(0, Finding.info(target, "headline", "key exchange %s | authentication %s" % (kex_v.value, auth_v.value)))
    findings.insert(1, Finding.info(target, "verdict split",
                                    "key exchange: %s%s | certificate: %s. Key exchange is the harvest-now-decrypt-later exposure; "
                                    "certificate signatures only matter at connection time." % (
                                        kex_v.value, " (server prefers %s)" % TLS_GROUPS.get(sel, "?") if sel else "", auth or "?")))
    return findings

"""Read an SSH server's KEXINIT (sent in the clear) and grade its algorithms."""
import socket
import struct
from typing import List

from .knowledge import SSH_KEX, SSH_KEX_BITS, SSH_HOSTKEY, SSH_CIPHERS, SSH_MACS, Verdict
from .report import Finding, worst


def _recv_exact(sock, n):
    buf = b""
    while len(buf) < n:
        c = sock.recv(n - len(buf))
        if not c:
            raise ConnectionError("closed")
        buf += c
    return buf


def read_kexinit(host: str, port: int, timeout: float = 5.0):
    with socket.create_connection((host, port), timeout=timeout) as s:
        banner = b""
        while True:
            line = b""
            while not line.endswith(b"\n"):
                c = s.recv(1)
                if not c:
                    raise ConnectionError("closed before banner")
                line += c
                if len(line) > 512:
                    raise ValueError("banner too long")
            if line.startswith(b"SSH-"):
                banner = line.strip()
                break
        s.sendall(b"SSH-2.0-pqcheck_0.1\r\n")
        plen = struct.unpack(">I", _recv_exact(s, 4))[0]
        if plen > 1 << 20:
            raise ValueError("bad packet length")
        pkt = _recv_exact(s, plen)
        padlen = pkt[0]
        payload = pkt[1:plen - padlen]
        if payload[0] != 20:
            raise ValueError("expected KEXINIT, got %d" % payload[0])
        o = 17
        lists = []
        for _ in range(10):
            n = struct.unpack(">I", payload[o:o + 4])[0]
            lists.append(payload[o + 4:o + 4 + n].decode().split(",") if n else [])
            o += 4 + n
        return banner.decode(errors="replace"), lists


def probe_ssh(hostport: str, timeout: float = 5.0) -> List[Finding]:
    from .ports import resolve_ports
    host, ports, note = resolve_ports(hostport, "ssh", min(timeout, 2.0))
    out: List[Finding] = []
    for port in ports:
        r = probe_ssh_port(host, port, timeout)
        if note and port == ports[0]:
            r.insert(0, Finding.info(r[0].target if r else "ssh://%s" % host, "port discovery", note))
        out.extend(r)
    return out


def probe_ssh_port(host: str, port: int, timeout: float = 5.0) -> List[Finding]:
    target = "ssh://%s:%d" % (host, port)
    try:
        banner, lists = read_kexinit(host, port, timeout)
    except (OSError, ValueError, ConnectionError, struct.error, UnicodeDecodeError) as e:
        return [Finding.info(target, "SSH", "cannot probe: %s" % e, Verdict.UNKNOWN)]
    kex, hostkeys, enc_c2s, enc_s2c, mac_c2s, mac_s2c = lists[:6]
    findings = [Finding.info(target, "SSH banner", banner)]
    kex_algos = [k for k in kex if not k.startswith("ext-info") and not k.startswith("kex-strict")]
    for i, k in enumerate(kex_algos):
        name = SSH_KEX.get(k, k)
        findings.append(Finding.make(target, "kex #%d" % (i + 1), name, bits=SSH_KEX_BITS.get(k), role=k))
    if not any(SSH_KEX.get(k, "").startswith(("mlkem", "sntrup")) for k in kex_algos):
        findings.append(Finding.info(target, "kex", "no PQC hybrid kex offered (need OpenSSH 9.0+ sntrup761x25519 or 9.9+ mlkem768x25519)", Verdict.VULNERABLE))
    else:
        first = kex_algos[0] if kex_algos else ""
        if not SSH_KEX.get(first, "").startswith(("mlkem", "sntrup")):
            findings.append(Finding.info(target, "kex", "PQC hybrid offered but not first in server preference", Verdict.WEAK))
    first = kex_algos[0] if kex_algos else ""
    pq_first = SSH_KEX.get(first, "").startswith(("mlkem", "sntrup"))
    pq_any = any(SSH_KEX.get(k, "").startswith(("mlkem", "sntrup")) for k in kex_algos)
    kex_v = Verdict.HYBRID if pq_first else (Verdict.WEAK if pq_any else Verdict.VULNERABLE)
    hk = [Finding.make(target, "x", SSH_HOSTKEY.get(h.replace("-cert-v01@openssh.com", ""), (h, None))[0]) for h in hostkeys]
    auth_v = worst(hk) if hk else Verdict.UNKNOWN
    findings.insert(1, Finding.info(target, "headline", "key exchange %s | host authentication %s" % (kex_v.value, auth_v.value)))
    findings.insert(2, Finding.info(target, "verdict split", "kex: %s (first offered: %s) | hostkeys: %s. Only the key exchange is exposed to "
                                    "harvest-now-decrypt-later; host keys matter at connection time." % (kex_v.value, first, ", ".join(hostkeys))))
    for i, h in enumerate(hostkeys):
        base = h.replace("-cert-v01@openssh.com", "")
        name, bits = SSH_HOSTKEY.get(base, (base, None))
        findings.append(Finding.make(target, "hostkey #%d" % (i + 1), name, bits=bits, role=h))
    for c in dict.fromkeys(enc_c2s + enc_s2c):
        findings.append(Finding.make(target, "cipher", SSH_CIPHERS.get(c, c), role=c))
    for m in dict.fromkeys(mac_c2s + mac_s2c):
        findings.append(Finding.make(target, "mac", SSH_MACS.get(m, m), role=m))
    return findings

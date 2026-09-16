"""Whole-website check: TLS versions, TLS 1.2 cipher families (forward secrecy),
certificate chain, HSTS / HTTP redirect, and third-party resource hosts."""
import re
import socket
import ssl
import urllib.request
import urllib.error
from typing import List, Optional
from urllib.parse import urlsplit, urljoin

from .knowledge import Verdict, TLS_GROUPS, TLS_PQC_PROBE_GROUPS, TLS_CLASSICAL_PROBE_GROUPS
from .report import Finding, worst
from .tlsprobe import probe_tls, probe_groups, legacy_handshake
from .formats import analyze_der

# cipher id -> (name, key exchange family, symmetric)
SUITES = {
    0xC02B: ("ECDHE-ECDSA-AES128-GCM-SHA256", "ECDHE", "AES-128"), 0xC02C: ("ECDHE-ECDSA-AES256-GCM-SHA384", "ECDHE", "AES-256"),
    0xC02F: ("ECDHE-RSA-AES128-GCM-SHA256", "ECDHE", "AES-128"), 0xC030: ("ECDHE-RSA-AES256-GCM-SHA384", "ECDHE", "AES-256"),
    0xCCA8: ("ECDHE-RSA-CHACHA20-POLY1305", "ECDHE", "ChaCha20-Poly1305"), 0xCCA9: ("ECDHE-ECDSA-CHACHA20-POLY1305", "ECDHE", "ChaCha20-Poly1305"),
    0xC027: ("ECDHE-RSA-AES128-SHA256", "ECDHE", "AES-128"), 0xC028: ("ECDHE-RSA-AES256-SHA384", "ECDHE", "AES-256"),
    0xC013: ("ECDHE-RSA-AES128-SHA", "ECDHE", "AES-128"), 0xC014: ("ECDHE-RSA-AES256-SHA", "ECDHE", "AES-256"),
    0xC009: ("ECDHE-ECDSA-AES128-SHA", "ECDHE", "AES-128"), 0xC00A: ("ECDHE-ECDSA-AES256-SHA", "ECDHE", "AES-256"),
    0x009E: ("DHE-RSA-AES128-GCM-SHA256", "DHE", "AES-128"), 0x009F: ("DHE-RSA-AES256-GCM-SHA384", "DHE", "AES-256"),
    0x0033: ("DHE-RSA-AES128-SHA", "DHE", "AES-128"), 0x0039: ("DHE-RSA-AES256-SHA", "DHE", "AES-256"),
    0x0067: ("DHE-RSA-AES128-SHA256", "DHE", "AES-128"), 0x006B: ("DHE-RSA-AES256-SHA256", "DHE", "AES-256"),
    0x009C: ("AES128-GCM-SHA256", "RSA", "AES-128"), 0x009D: ("AES256-GCM-SHA384", "RSA", "AES-256"),
    0x002F: ("AES128-SHA", "RSA", "AES-128"), 0x0035: ("AES256-SHA", "RSA", "AES-256"),
    0x003C: ("AES128-SHA256", "RSA", "AES-128"), 0x003D: ("AES256-SHA256", "RSA", "AES-256"),
    0x000A: ("DES-CBC3-SHA", "RSA", "3DES"), 0xC012: ("ECDHE-RSA-DES-CBC3-SHA", "ECDHE", "3DES"), 0x0016: ("DHE-RSA-DES-CBC3-SHA", "DHE", "3DES"),
    0x0005: ("RC4-SHA", "RSA", "RC4"), 0x0004: ("RC4-MD5", "RSA", "RC4"), 0xC011: ("ECDHE-RSA-RC4-SHA", "ECDHE", "RC4"),
    0x0009: ("DES-CBC-SHA", "RSA", "DES"), 0x0003: ("EXP-RC4-MD5", "RSA", "RC4"), 0x0006: ("EXP-RC2-CBC-MD5", "RSA", "RC2"),
    0x0001: ("NULL-MD5", "RSA", "NULL"), 0x0002: ("NULL-SHA", "RSA", "NULL"), 0x003B: ("NULL-SHA256", "RSA", "NULL"),
}
FS_SUITES = [c for c, v in SUITES.items() if v[1] in ("ECDHE", "DHE") and v[2] not in ("3DES", "RC4", "DES", "RC2", "NULL")]
STATIC_RSA_SUITES = [c for c, v in SUITES.items() if v[1] == "RSA" and v[2] in ("AES-128", "AES-256")]
WEAK_SUITES = [c for c, v in SUITES.items() if v[2] in ("3DES", "RC4", "DES", "RC2", "NULL")]
VERSIONS = {0x0301: "TLS 1.0", 0x0302: "TLS 1.1", 0x0303: "TLS 1.2", 0x0304: "TLS 1.3"}

RES_RE = re.compile(rb"""<(?:script|link|img|iframe|source|video|audio|embed)\b[^>]*?\s(?:src|href)\s*=\s*["']?(https?://[^"'\s>]+|//[^"'\s>]+)""", re.I)


def _site(h: str) -> str:
    """Registrable-domain heuristic: last two labels (three for co.uk-style suffixes)."""
    parts = h.lower().split(".")
    if len(parts) >= 3 and parts[-2] in ("co", "com", "org", "net", "gov", "ac", "edu") and len(parts[-1]) == 2:
        return ".".join(parts[-3:])
    return ".".join(parts[-2:])


def _http(url: str, timeout: float, insecure: bool = False):
    ctx = ssl.create_default_context()
    if insecure:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE

    class NoRedirect(urllib.request.HTTPRedirectHandler):
        def redirect_request(self, req, fp, code, msg, headers, newurl):
            return None
    opener = urllib.request.build_opener(NoRedirect, urllib.request.HTTPSHandler(context=ctx))
    req = urllib.request.Request(url, headers={"User-Agent": "pqcheck/web (+https://github.com/krisztianhari-wq/pqcheck)"})
    try:
        with opener.open(req, timeout=timeout) as r:
            return r.status, dict(r.headers), r.read(2 * 1024 * 1024)
    except urllib.error.HTTPError as e:
        return e.code, dict(e.headers), b""
    except (urllib.error.URLError, OSError, ValueError) as e:
        return None, {"_error": str(e)}, b""


def probe_web(url: str, timeout: float = 5.0, third_party_limit: int = 8) -> List[Finding]:
    if "://" not in url:
        url = "https://" + url
    u = urlsplit(url)
    host = u.hostname or ""
    port = u.port or (443 if u.scheme == "https" else 80)
    target = "web://%s" % (host if port in (80, 443) else "%s:%d" % (host, port))
    findings: List[Finding] = []
    if not host:
        return [Finding.info(target, "URL", "cannot parse URL", Verdict.UNKNOWN)]
    if u.scheme != "https":
        findings.append(Finding.info(target, "scheme", "URL is plain HTTP; checking the HTTPS endpoint on the same host", Verdict.WEAK))
        port = 443

    # 1. TLS 1.3 groups + leaf cert (reuses probe_tls, drop its headline lines)
    tls = probe_tls("%s:%d" % (host, port), timeout)
    tls_err = [f for f in tls if f.location == "TLS" and "cannot probe" in f.note]
    if tls_err:
        return [Finding.info(target, "TLS", tls_err[0].note, Verdict.UNKNOWN)]
    kex_head = next((f.note for f in tls if f.location == "headline"), "")
    for f in tls:
        if f.location in ("headline", "verdict split"):
            continue
        f.target = target
        if f.location.startswith("leaf certificate"):
            continue   # the chain walk below covers the leaf too
        findings.append(f)

    # 2. protocol versions
    supported_versions = []
    for ver in (0x0301, 0x0302, 0x0303):
        r = legacy_handshake(host, port, (ver,), FS_SUITES + STATIC_RSA_SUITES + WEAK_SUITES, timeout)
        if r["status"] == "ok" and r["version"] == ver:
            supported_versions.append(ver)
            v = Verdict.WEAK if ver < 0x0303 else Verdict.INFO
            note = "deprecated (RFC 8996), disable" if ver < 0x0303 else "supported"
            findings.append(Finding.info(target, "protocol", "%s %s" % (VERSIONS[ver], note), v))
    if any(f.algorithm != "-" and f.category == "hybrid-kex" for f in tls) or "TLS 1.3" in kex_head:
        pass
    tls13 = not any(f.location == "TLS version" for f in tls)
    if tls13:
        findings.append(Finding.info(target, "protocol", "TLS 1.3 supported"))

    # 3. TLS 1.2 key-exchange families
    chain = []
    if 0x0303 in supported_versions:
        r = legacy_handshake(host, port, (0x0303,), STATIC_RSA_SUITES, timeout)
        if r["status"] == "ok" and r["cipher"] in SUITES:
            name = SUITES[r["cipher"]][0]
            f = Finding.make(target, "TLS 1.2 cipher probe", "RSA", role="static RSA key exchange accepted (%s)" % name)
            f.note = "NO forward secrecy: one broken server key decrypts every recorded session. Worst case for harvest-now-decrypt-later; " + f.note
            findings.append(f)
        r = legacy_handshake(host, port, (0x0303,), FS_SUITES, timeout)
        if r["status"] == "ok" and r["cipher"] in SUITES:
            name, fam, sym = SUITES[r["cipher"]]
            findings.append(Finding.make(target, "TLS 1.2 cipher probe", "ECDH" if fam == "ECDHE" else "DH",
                                         role="forward-secret %s accepted (%s)" % (fam, name)))
            findings.append(Finding.make(target, "TLS 1.2 cipher probe", sym, role="bulk cipher in %s" % name))
            chain = r["certs"]
        r = legacy_handshake(host, port, (0x0303,), WEAK_SUITES, timeout)
        if r["status"] == "ok" and r["cipher"] in SUITES:
            name, fam, sym = SUITES[r["cipher"]]
            findings.append(Finding.make(target, "TLS 1.2 cipher probe", sym if sym != "NULL" else "DES", role="weak suite accepted (%s)" % name))
    if not chain:
        r = legacy_handshake(host, port, (0x0303,), FS_SUITES + STATIC_RSA_SUITES, timeout)
        chain = r.get("certs", [])

    # 4. certificate chain
    if chain:
        findings.append(Finding.info(target, "certificate chain", "%d certificate(s) sent by server" % len(chain)))
        for i, der in enumerate(chain):
            label = "chain cert #%d%s" % (i + 1, " (leaf)" if i == 0 else "")
            r = analyze_der(target, der, label)
            for f in r or []:
                if f.algorithm != "-":
                    findings.append(f)
    else:
        findings.append(Finding.info(target, "certificate chain", "chain not readable (TLS 1.3-only server encrypts it); leaf via ssl module only", Verdict.INFO))
        for f in tls:
            if f.location.startswith("leaf certificate"):
                f.target = target
                findings.append(f)

    # 5. HTTP layer
    status, headers, body = _http("https://%s%s%s" % (host, "" if port == 443 else ":%d" % port, u.path or "/"), timeout, insecure=True)
    hsts = None
    if status is None:
        findings.append(Finding.info(target, "HTTP", "HTTPS GET failed: %s" % headers.get("_error", "?"), Verdict.UNKNOWN))
    else:
        hsts = next((v for k, v in headers.items() if k.lower() == "strict-transport-security"), None)
        if hsts:
            m = re.search(r"max-age=(\d+)", hsts)
            age = int(m.group(1)) if m else 0
            v = Verdict.SAFE if age >= 15552000 else Verdict.WEAK
            findings.append(Finding.info(target, "HTTP header", "HSTS: %s%s" % (hsts[:80], "" if age >= 15552000 else " (max-age < 180 days)"), v))
        else:
            findings.append(Finding.info(target, "HTTP header", "no Strict-Transport-Security header: HTTPS downgrade / stripping possible", Verdict.WEAK))
        hosts = []
        for m in RES_RE.finditer(body):
            ref = m.group(1).decode(errors="replace")
            h = urlsplit(urljoin("https://" + host, ref)).hostname
            if h and _site(h) != _site(host) and h not in hosts:
                hosts.append(h)
        for h in hosts[:third_party_limit]:
            st, sel, det = probe_groups(h, 443, TLS_PQC_PROBE_GROUPS + TLS_CLASSICAL_PROBE_GROUPS, timeout)
            if st in ("hrr", "serverhello") and sel is not None:
                name = TLS_GROUPS.get(sel, "group 0x%04x" % sel)
                f = Finding.make(target, "third-party host %s" % h, name, role="preferred TLS 1.3 group")
                findings.append(f)
            elif st == "tls12":
                findings.append(Finding.info(target, "third-party host %s" % h, "TLS 1.2 only, classical key exchange", Verdict.VULNERABLE))
            else:
                findings.append(Finding.info(target, "third-party host %s" % h, "not probed: %s" % det, Verdict.UNKNOWN))
        if len(hosts) > third_party_limit:
            findings.append(Finding.info(target, "third-party hosts", "%d more external hosts not probed" % (len(hosts) - third_party_limit)))
    if port == 443:
        st, hdrs, _ = _http("http://%s%s" % (host, u.path or "/"), timeout)
        if st is None:
            findings.append(Finding.info(target, "HTTP :80", "no plain-HTTP listener (%s)" % hdrs.get("_error", "")[:60]))
        elif st in (301, 302, 307, 308) and str(hdrs.get("Location", "")).lower().startswith("https://"):
            findings.append(Finding.info(target, "HTTP :80", "redirects to HTTPS (%d)" % st, Verdict.SAFE))
        else:
            findings.append(Finding.info(target, "HTTP :80", "plain HTTP answers %s without HTTPS redirect" % st, Verdict.WEAK))

    # 6. headline
    own = [f for f in findings if not f.location.startswith("third-party")]
    kex = "HYBRID_PQC" if any(f.category == "hybrid-kex" and f.verdict is Verdict.HYBRID for f in own) else "QUANTUM_VULNERABLE"
    fs = "NO" if any("static RSA key exchange" in f.location for f in findings) else "yes"
    old = [VERSIONS[v] for v in supported_versions if v < 0x0303]
    chain_v = worst([f for f in findings if f.location.startswith("chain cert")]) if chain else None
    findings.insert(0, Finding.info(target, "headline", "key exchange %s | forward secrecy %s | chain %s | %s" % (
        kex, fs, chain_v.value if chain_v else "?", ("legacy " + "/".join(old)) if old else ("HSTS" if hsts else "no HSTS"))))
    return findings

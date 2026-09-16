"""Well-known port discovery: when a target has no explicit port, try the ports
commonly used for that purpose and probe every one that accepts a TCP connection."""
import socket
from concurrent.futures import ThreadPoolExecutor
from typing import List, Optional, Tuple

WELL_KNOWN = {
    "tls": [443, 8443, 465, 993, 995, 636, 4443, 9443],   # https, alt-https, smtps, imaps, pop3s, ldaps, alt, alt
    "web": [443, 8443],
    "ssh": [22, 2222, 2200, 22222],
}
DEFAULT = {"tls": 443, "web": 443, "ssh": 22}


def split_hostport(target: str, kind: str) -> Tuple[str, Optional[int]]:
    """'host', 'host:port', '[v6]:port' -> (host, port or None)."""
    t = target.strip()
    if t.startswith("["):                       # [ipv6]:port
        host, _, rest = t[1:].partition("]")
        port = rest[1:] if rest.startswith(":") else ""
        return host, (int(port) if port.isdigit() else None)
    if t.count(":") == 1:
        host, _, port = t.partition(":")
        return host, (int(port) if port.isdigit() else None)
    return t, None                              # bare host or raw ipv6 without port


def tcp_open(host: str, port: int, timeout: float = 1.5) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def open_ports(host: str, candidates: List[int], timeout: float = 1.5, max_hits: int = 4) -> List[int]:
    """Candidates that accept a TCP connection, in candidate order (checked in parallel)."""
    with ThreadPoolExecutor(max_workers=min(8, len(candidates) or 1)) as ex:
        results = list(ex.map(lambda p: tcp_open(host, p, timeout), candidates))
    return [p for p, ok in zip(candidates, results) if ok][:max_hits]


def resolve_ports(target: str, kind: str, timeout: float = 1.5) -> Tuple[str, List[int], Optional[str]]:
    """Returns (host, ports_to_probe, note). Explicit port -> just that one.
    No port -> every open well-known port; if none, the default with a note."""
    host, port = split_hostport(target, kind)
    if port is not None:
        return host, [port], None
    cands = WELL_KNOWN[kind]
    found = open_ports(host, cands, timeout)
    tried = ", ".join(str(p) for p in cands)
    if not found:
        return host, [DEFAULT[kind]], "no well-known %s port answered (tried %s); probing default %d" % (kind.upper(), tried, DEFAULT[kind])
    if found == [DEFAULT[kind]]:
        return host, found, None
    return host, found, "no port given: tried %s, open: %s" % (tried, ", ".join(str(p) for p in found))

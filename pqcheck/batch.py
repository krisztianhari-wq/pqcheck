"""Bulk target lists from CSV / TSV / TXT / XLSX (stdlib only).

Accepted columns (header optional, any order, case-insensitive):
  kind / type / check / test / purpose   -> tls | ssh | web | file | scan   (empty = auto-detect)
  host / target / ip / domain / address / url / name
  port                                   -> optional integer
  note / comment                         -> ignored, kept for reference
Without a header: 1 column = target; 2 columns = target,port (numeric) or kind,target;
3 columns = kind,target,port. Lines starting with # are comments. Duplicates are dropped.
"""
import csv
import io
import re
import zipfile
import xml.etree.ElementTree as ET
from typing import Dict, List, Optional, Tuple

KIND_COLS = {"kind", "type", "check", "test", "purpose", "mode", "cel", "cél", "vizsgalat", "vizsgálat"}
HOST_COLS = {"host", "target", "ip", "domain", "address", "url", "name", "hostname", "server", "cim", "cím"}
PORT_COLS = {"port"}
KIND_ALIASES = {
    "tls": "tls", "ssl": "tls", "https": "tls", "smtps": "tls", "imaps": "tls", "ldaps": "tls",
    "ssh": "ssh", "sftp": "ssh",
    "web": "web", "website": "web", "http": "web", "site": "web", "url": "web",
    "file": "file", "scan": "scan", "dir": "scan", "directory": "scan",
}
IP_RE = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
HOST_RE = re.compile(r"^[A-Za-z0-9.-]+$")

TEMPLATE_CSV = """kind,host,port,note
tls,www.example.com,,public website endpoint
tls,mail.example.com,465,SMTP submission
ssh,bastion.example.com,22,jump host
web,https://portal.example.com,,full website check incl. certificate chain and HSTS
tls,10.0.0.12,8443,appliance management UI
ssh,10.0.0.5,,port left empty: 22 2222 2200 22222 are tried
,intranet.example.com,,kind left empty: auto-detected (URL->web, :22->ssh, otherwise tls)
"""


class Row:
    __slots__ = ("kind", "host", "port", "note", "line", "error")

    def __init__(self, kind, host, port, note="", line=0, error=""):
        self.kind, self.host, self.port, self.note, self.line, self.error = kind, host, port, note, line, error

    @property
    def target(self) -> str:
        if self.kind == "web":
            if "://" in self.host:
                return self.host
            return "https://%s%s/" % (self.host, ":%d" % self.port if self.port and self.port != 443 else "")
        if self.kind in ("file", "scan"):
            return self.host
        return "%s:%d" % (self.host, self.port) if self.port else self.host

    def as_dict(self):
        return {"kind": self.kind, "host": self.host, "port": self.port, "note": self.note, "line": self.line,
                "target": self.target, "error": self.error}


# ------------------------------------------------------------------ readers
def _read_xlsx(data: bytes) -> List[List[str]]:
    z = zipfile.ZipFile(io.BytesIO(data))
    ns = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
          "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships"}
    shared = []
    if "xl/sharedStrings.xml" in z.namelist():
        for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", ns):
            shared.append("".join(t.text or "" for t in si.iter("{%s}t" % ns["m"])))
    wb = ET.fromstring(z.read("xl/workbook.xml"))
    first = wb.find("m:sheets/m:sheet", ns)
    rid = first.get("{%s}id" % ns["r"]) if first is not None else None
    sheet_path = "xl/worksheets/sheet1.xml"
    if rid and "xl/_rels/workbook.xml.rels" in z.namelist():
        for rel in ET.fromstring(z.read("xl/_rels/workbook.xml.rels")):
            if rel.get("Id") == rid:
                t = rel.get("Target")
                sheet_path = t.lstrip("/") if t.startswith("/") else "xl/" + t
    rows = []
    for row in ET.fromstring(z.read(sheet_path)).iter("{%s}row" % ns["m"]):
        cells: Dict[int, str] = {}
        for c in row.findall("m:c", ns):
            ref = c.get("r", "")
            col = 0
            for ch in ref:
                if ch.isalpha():
                    col = col * 26 + (ord(ch.upper()) - 64)
                else:
                    break
            t = c.get("t")
            v = c.find("m:v", ns)
            if t == "s" and v is not None:
                val = shared[int(v.text)] if v.text and v.text.isdigit() and int(v.text) < len(shared) else ""
            elif t == "inlineStr":
                val = "".join(x.text or "" for x in c.iter("{%s}t" % ns["m"]))
            else:
                val = v.text if v is not None and v.text is not None else ""
                if re.fullmatch(r"\d+\.0", val):
                    val = val[:-2]
            cells[col - 1 if col else len(cells)] = val
        if cells:
            width = max(cells) + 1
            rows.append([cells.get(i, "") for i in range(width)])
    return rows


def _read_delimited(data: bytes) -> List[List[str]]:
    text = data.decode("utf-8-sig", errors="replace")
    sample = text[:4096]
    try:
        dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
    except csv.Error:
        class dialect(csv.excel):  # type: ignore
            delimiter = "," if "," in sample else ";" if ";" in sample else "\t"
    return [r for r in csv.reader(io.StringIO(text), dialect)]


def read_table(data: bytes, filename: str = "") -> List[List[str]]:
    if data[:2] == b"PK" or filename.lower().endswith(".xlsx"):
        return _read_xlsx(data)
    return _read_delimited(data)


# ------------------------------------------------------------------ parsing
def detect_kind(host: str, port: Optional[int]) -> str:
    h = host.strip().lower()
    if h.startswith(("http://", "https://")):
        return "web"
    if "/" in h or "\\" in h:
        return "file"
    if port in (22, 2222, 2200, 22222):
        return "ssh"
    return "tls"


def normalize_kind(value: str) -> Optional[str]:
    v = (value or "").strip().lower()
    if not v:
        return None
    return KIND_ALIASES.get(v)


def parse_rows(table: List[List[str]]) -> Tuple[List[Row], List[Row]]:
    """Returns (valid_rows, error_rows)."""
    rows: List[Row] = []
    errors: List[Row] = []
    if not table:
        return rows, errors
    # header detection
    head = [c.strip().lower() for c in table[0]]
    kind_i = host_i = port_i = note_i = None
    has_header = False
    for i, h in enumerate(head):
        if h in KIND_COLS and kind_i is None:
            kind_i, has_header = i, True
        elif h in HOST_COLS and host_i is None:
            host_i, has_header = i, True
        elif h in PORT_COLS and port_i is None:
            port_i, has_header = i, True
        elif h in ("note", "comment", "megjegyzes", "megjegyzés") and note_i is None:
            note_i = i
    body = table[1:] if has_header else table
    seen = set()
    for n, raw in enumerate(body, start=2 if has_header else 1):
        cells = [c.strip() for c in raw]
        if not any(cells) or cells[0].startswith("#"):
            continue
        kind_s = host = port_s = note = ""
        if has_header:
            if host_i is None or host_i >= len(cells):
                errors.append(Row(None, " ".join(cells), None, "", n, "no host column"))
                continue
            host = cells[host_i]
            kind_s = cells[kind_i] if kind_i is not None and kind_i < len(cells) else ""
            port_s = cells[port_i] if port_i is not None and port_i < len(cells) else ""
            note = cells[note_i] if note_i is not None and note_i < len(cells) else ""
        else:
            cells = [c for c in cells if c != ""]
            if len(cells) == 1:
                host = cells[0]
            elif len(cells) == 2:
                if cells[1].isdigit():
                    host, port_s = cells
                elif normalize_kind(cells[0]):
                    kind_s, host = cells
                else:
                    host, note = cells
            else:
                kind_s, host, port_s = cells[0], cells[1], cells[2]
                note = " ".join(cells[3:])
        if not host:
            errors.append(Row(None, " ".join(cells), None, "", n, "empty host"))
            continue
        port = None
        if port_s:
            if not port_s.isdigit() or not 0 < int(port_s) < 65536:
                errors.append(Row(None, host, None, note, n, "invalid port '%s'" % port_s))
                continue
            port = int(port_s)
        # host:port inside the host cell
        if port is None and "://" not in host and host.count(":") == 1 and host.rsplit(":", 1)[1].isdigit():
            host, p = host.rsplit(":", 1)
            port = int(p)
        kind = normalize_kind(kind_s)
        if kind_s and kind is None:
            errors.append(Row(None, host, port, note, n, "unknown kind '%s' (use tls, ssh, web, file, scan)" % kind_s))
            continue
        if kind is None:
            kind = detect_kind(host, port)
        if kind in ("tls", "ssh", "web") and "://" not in host and not (IP_RE.match(host) or HOST_RE.match(host)):
            errors.append(Row(kind, host, port, note, n, "not a valid host name or IP"))
            continue
        r = Row(kind, host, port, note, n)
        key = (r.kind, r.target)
        if key in seen:
            continue
        seen.add(key)
        rows.append(r)
    return rows, errors


def parse_list(data: bytes, filename: str = "") -> Tuple[List[Row], List[Row]]:
    return parse_rows(read_table(data, filename))


def run_rows(rows: List[Row], timeout: float = 5.0):
    """Yields (row, findings) for every row."""
    from .gui import run_command
    for r in rows:
        try:
            yield r, run_command(r.kind, [r.target], timeout)
        except Exception as e:  # one bad row must not stop the batch
            from .report import Finding
            from .knowledge import Verdict
            yield r, [Finding.info(r.target, "batch", "error: %s" % e, Verdict.UNKNOWN)]

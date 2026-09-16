"""Finding model and text/JSON rendering."""
import json
import sys
from dataclasses import dataclass, asdict, field
from typing import List, Optional

from .knowledge import Verdict, SEVERITY, classify


@dataclass
class Finding:
    target: str
    location: str
    algorithm: str
    category: str = ""
    verdict: Verdict = Verdict.UNKNOWN
    bits: Optional[int] = None
    note: str = ""

    @classmethod
    def make(cls, target, location, algorithm, bits=None, note=None, role=None):
        cat, verdict, base_note = classify(algorithm, bits)
        if role:
            location = "%s [%s]" % (location, role)
        if note is None:
            note = base_note
        elif base_note:
            note = "%s; %s" % (note, base_note)
        return cls(target, location, algorithm, cat, verdict, bits, note)

    @classmethod
    def info(cls, target, location, text, verdict=Verdict.INFO):
        return cls(target, location, "-", "info", verdict, None, text)

    def label(self):
        return "%s-%d" % (self.algorithm, self.bits) if self.bits else self.algorithm


COLORS = {
    Verdict.VULNERABLE: "\033[91m", Verdict.WEAK: "\033[93m", Verdict.UNKNOWN: "\033[95m",
    Verdict.INFO: "\033[90m", Verdict.HYBRID: "\033[92m", Verdict.SAFE: "\033[92m",
}
SYMBOLS = {
    Verdict.VULNERABLE: "!!", Verdict.WEAK: " !", Verdict.UNKNOWN: " ?",
    Verdict.INFO: " i", Verdict.HYBRID: "OK", Verdict.SAFE: "OK",
}
RESET = "\033[0m"


def worst(findings: List[Finding]) -> Optional[Verdict]:
    graded = [f.verdict for f in findings if f.verdict is not Verdict.INFO]
    if not graded:
        return None
    return min(graded, key=lambda v: SEVERITY[v])


def render_text(findings: List[Finding], color: bool = True, verbose: bool = False) -> str:
    out = []
    by_target = {}
    for f in findings:
        by_target.setdefault(f.target, []).append(f)
    for target, items in by_target.items():
        w = worst(items)
        headline = [f for f in items if f.location == "headline"]
        if headline:
            head = "== %s  ->  %s" % (target, headline[0].note)
            items = [f for f in items if f.location != "headline"]
        else:
            head = "== %s  ->  %s" % (target, w.value if w else "no graded findings")
        if color and w:
            head = COLORS[w] + head + RESET
        out.append(head)
        for f in items:
            if f.verdict is Verdict.INFO and not verbose and f.algorithm == "-" and len(items) > 1:
                pass
            sym = SYMBOLS[f.verdict]
            line = "  [%s] %-18s %-24s %-13s %s" % (sym, f.verdict.value, f.label()[:24], f.category[:13], f.location)
            if f.note:
                line += "\n" + " " * 8 + "- " + f.note
            if color:
                line = COLORS[f.verdict] + line + RESET
            out.append(line)
        out.append("")
    # summary
    counts = {}
    for f in findings:
        counts[f.verdict] = counts.get(f.verdict, 0) + 1
    summary = ", ".join("%s=%d" % (v.value, counts[v]) for v in SEVERITY if v in counts)
    w = worst(findings)
    out.append("Summary: %s" % summary)
    out.append("Overall: %s" % (w.value if w else "nothing graded"))
    return "\n".join(out)


def render_json(findings: List[Finding]) -> str:
    data = {
        "tool": "pqcheck",
        "overall": (worst(findings).value if worst(findings) else None),
        "findings": [dict(asdict(f), verdict=f.verdict.value) for f in findings],
    }
    return json.dumps(data, indent=2)


def exit_code(findings: List[Finding], fail_on: str = "vulnerable") -> int:
    w = worst(findings)
    if w is None:
        return 0
    if fail_on == "never":
        return 0
    if fail_on == "weak":
        return 1 if SEVERITY[w] <= SEVERITY[Verdict.WEAK] else 0
    return 2 if w is Verdict.VULNERABLE else 0

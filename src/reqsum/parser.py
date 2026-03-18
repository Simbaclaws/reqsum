
from __future__ import annotations
from dataclasses import dataclass
from typing import Optional
import re
from packaging.requirements import Requirement, InvalidRequirement

REQ_LINE_RE = re.compile(r"^\s*(?P<value>[^#\n\r]*?)(?P<comment>\s+#.*)?$")

@dataclass
class Line:
    raw: str
    kind: str  # requirement|include|constraint|editable|vcs|url|path|option|blank|comment
    value: str
    comment: str
    name: Optional[str] = None  # normalized package name if resolvable
    req: Optional[Requirement] = None

    @property
    def is_requirement(self) -> bool:
        return self.kind == "requirement"


def parse_line(raw: str) -> Line:
    m = REQ_LINE_RE.match(raw.rstrip("\n"))
    if not m:
        return Line(raw=raw, kind="option", value=raw.strip(), comment="")
    value = (m.group("value") or "").strip()
    comment = (m.group("comment") or "").strip()
    if value == "":
        return Line(raw=raw, kind="blank" if not comment else "comment", value=value, comment=comment)

    # includes / constraints
    if value.startswith("-r ") or value.startswith("--requirement "):
        return Line(raw=raw, kind="include", value=value, comment=comment)
    if value.startswith("-c ") or value.startswith("--constraint "):
        return Line(raw=raw, kind="constraint", value=value, comment=comment)

    # editable, options
    if value.startswith("-e ") or value.startswith("--editable "):
        return Line(raw=raw, kind="editable", value=value, comment=comment)
    if value.startswith("-"):
        return Line(raw=raw, kind="option", value=value, comment=comment)

    # URL / VCS / local path heuristics
    if re.match(r"^(git\+|https?://|ssh://|file://)", value, re.I):
        kind = "vcs" if value.startswith("git+") else ("url")
        return Line(raw=raw, kind=kind, value=value, comment=comment)
    if any(value.startswith(pfx) for pfx in ("./", "../", "/")):
        return Line(raw=raw, kind="path", value=value, comment=comment)

    # Try parse as requirement
    try:
        req = Requirement(value)
        name = req.name
        return Line(raw=raw, kind="requirement", value=value, comment=comment, name=name, req=req)
    except InvalidRequirement:
        # fallback: unknown option-like
        return Line(raw=raw, kind="option", value=value, comment=comment)


def parse_file(path: str):
    with open(path, "r", encoding="utf-8") as f:
        for raw in f:
            yield parse_line(raw)

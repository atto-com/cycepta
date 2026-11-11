"""Input hygiene for sentence units.

The NCD paper (arXiv 2502.21315) filters procedural boilerplates before
embedding, otherwise structured feed template fields (CVE JSON fields,
page chrome, truncation marks) cluster into dense pseudo-concepts that
recur every period. This module is deliberately dependency-free so the
DB cleanup script can import it without pulling numpy/umap/torch.
"""
from __future__ import annotations

import re

_BOILERPLATE_RES = [
    re.compile(r"^cve\s+cve-\d{4}-\d+", re.I),
    # CVE record template: a bare id followed by the NVD field labels.
    re.compile(r"^cve-\d{4}-\d{4,7}\b.*\b(published|updated|nvd status|severity)\s*:", re.I),
    # A sentence opening with a CVSS mention is template text ("CVSS v3.1
    # Base Score: -- Vector: Unknown."), not prose.
    re.compile(r"^cvss\b", re.I),
    re.compile(r"^product status:", re.I),
    re.compile(r"^\[\.+\]"),
    re.compile(r"^(read more|additional metrics|vector string|view csaf|summary|"
               r"equipment|references|external links|see also|edit section)\.?$", re.I),
]

# Sentences shorter than this carry no clusterable semantics (the paper
# drops sub-300-char procedural speeches; threat-feed junk sits far below).
MIN_UNIT_CHARS = 25


def is_boilerplate(s: str) -> bool:
    t = (s or "").strip()
    if len(t) < MIN_UNIT_CHARS:
        return True
    if sum(ch.isalpha() for ch in t) / len(t) < 0.55:
        return True
    return any(rx.search(t) for rx in _BOILERPLATE_RES)

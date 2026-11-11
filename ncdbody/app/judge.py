"""Second-stage garbage judge: whole-document junk verdicts from the local LLM.

A Verdict is a per-document tuple (is_junk, p_junk) with p_junk in 0..1.
judge_documents returns None when no model is available or a batch is too
garbled to parse - the caller then passes documents through unchanged; ingest
must never block on the judge.
"""
from __future__ import annotations

import re

from .config import NcdConfig
from .llm import _generate

Verdict = tuple[bool, float]

_LINE_RE = re.compile(r"^\s*(\d+)\s*:\s*(YES|NO)\b", re.IGNORECASE)
# 200 chars: template junk shows in the first fields and real prose continues
# past it; the full text still passes the per-sentence regex stage.
_DOC_CHARS = 200

_SYSTEM = "You are a classifier for security-feed documents. Follow the output format exactly."


def _parse_verdicts(raw: str, n: int) -> list[Verdict] | None:
    verdicts: list[Verdict | None] = [None] * n
    for line in raw.splitlines():
        m = _LINE_RE.match(line)
        if not m:
            continue
        idx = int(m.group(1))
        if not 1 <= idx <= n or verdicts[idx - 1] is not None:
            continue
        verdicts[idx - 1] = (True, 1.0) if m.group(2).upper() == "YES" else (False, 0.0)
    missing = sum(1 for v in verdicts if v is None)
    # Fail over only when the model garbled more than half the batch; a stray
    # missing line must never delete a document (default below is keep).
    if missing * 2 > n:
        return None
    return [v if v is not None else (False, 0.0) for v in verdicts]


def _judge_messages(chunk: list[str]) -> list[dict]:
    numbered = "\n".join(f"{i}: {text[:_DOC_CHARS]}" for i, text in enumerate(chunk, 1))
    user = (
        "A security-feed document is substantive only if at least one of its sentences is prose describing a "
        "real threat: what the vulnerability is, who exploits it, what malware does, or how to patch. "
        "Documents that contain only metadata fields, CVE ids, scores, statuses, navigation, boilerplate, "
        "feed chrome or truncated fragments are junk - that includes CVE records whose fields are empty "
        "placeholders ('--', '[]'). When in doubt, answer YES (junk).\n\n"
        f"Documents:\n{numbered}\n\n"
        'Answer one line per document, exactly "<n>: YES" if the document is junk '
        'or "<n>: NO" if it is substantive. Nothing else.'
    )
    return [
        {"role": "system", "content": _SYSTEM},
        {"role": "user", "content": user},
    ]


def judge_documents(texts: list[str]) -> list[Verdict] | None:
    if not texts:
        return []
    verdicts: list[Verdict] = []
    batch = NcdConfig.JUDGE_BATCH
    for start in range(0, len(texts), batch):
        chunk = texts[start:start + batch]
        raw = _generate(_judge_messages(chunk), max_tokens=3 * len(chunk) + 20, temp=0.0)
        parsed = _parse_verdicts(raw, len(chunk))
        if parsed is None:
            return None
        verdicts.extend(parsed)
    return verdicts

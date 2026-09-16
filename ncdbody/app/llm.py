"""LLM-based threat analysis (MLX 4-bit Granite-4.0-1B).

Two-stage pipeline:
  1. Structured extraction -> JSON (IOCs, severity, MITRE techniques, actions)
  2. Human-readable digest built on top of the extracted JSON

A deterministic regex + heuristic layer always runs alongside, so the output
is useful even when the LLM output is malformed or unavailable.
"""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import platform
import re
import sys
import threading
from pathlib import Path

from .config import NcdConfig

logger = logging.getLogger(__name__)

_LLM_DIR = Path(os.getenv(
    "NCD_LLM_MODEL",
    str(Path(__file__).resolve().parent.parent / "models" / "granite-4.0-1b-mlx-4bit"),
))
_LLM_BACKEND = os.getenv("NCD_LLM_BACKEND", "auto").strip().lower()
_LLM_DEVICE = os.getenv("NCD_LLM_DEVICE", "auto").strip()

_model = None
_tokenizer = None
_llm_lock = threading.Lock()


# ---------------------------------------------------------------------------
# Deterministic IOC extraction
# ---------------------------------------------------------------------------

_URL_RE = re.compile(r"https?://[^\s<>\"]+", re.IGNORECASE)
_DOMAIN_RE = re.compile(
    r"(?<![\w.-])(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+"
    r"(?:com|net|org|io|ru|de|cn|info|biz|xyz|onion|gov|mil|edu)"
    r"(?![\w.])", re.IGNORECASE)
_IPV4_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6_RE = re.compile(r"\b[0-9a-fA-F:]{4,45}\b(?=[:/]|$)")
_EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}")
_HASH_RE = re.compile(r"\b(?:[a-fA-F0-9]{32}|[a-fA-F0-9]{40}|[a-fA-F0-9]{64})\b")
# CVE-YYYY-NNNNN, CAPEC-NNN, CWE-NNN, CPE matches
_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.IGNORECASE)
_CAPEC_RE = re.compile(r"CAPEC-\d{1,5}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d{1,5}", re.IGNORECASE)
# MITRE ATT&CK technique IDs: T1234, or T1234.001
_MITRE_TECH_RE = re.compile(r"\bT\d{3,5}(?:\.\d{1,3})?\b")
_SID_RE = re.compile(r"\bS-\d+-\d+(?:-\d+){3,}\b")


def _valid_ipv4(s: str) -> bool:
    try:
        ipaddress.IPv4Address(s)
        return not s.startswith(("0.", "127.", "255."))
    except ValueError:
        return False


def extract_iocs(text: str) -> dict:
    """Deterministic IOC extraction. Returns {ioc_type: [values]}."""
    iocs: dict[str, list[str]] = {
        "ipv4": [], "ipv6": [], "domains": [], "urls": [], "emails": [],
        "hashes": [], "cve_ids": [], "capec_ids": [], "cwe_ids": [],
        "mitre_techniques": [], "sids": [],
    }
    if not text:
        return iocs

    def _add(key, value):
        if value and value not in iocs[key]:
            iocs[key].append(value)

    for cand in _IPV4_RE.findall(text):
        if _valid_ipv4(cand):
            _add("ipv4", cand)
    for cand in _IPV6_RE.findall(text):
        try:
            ipaddress.IPv6Address(cand)
            _add("ipv6", cand)
        except ValueError:
            pass
    for cand in _DOMAIN_RE.findall(text):
        _add("domains", cand.lower())
    for cand in _URL_RE.findall(text):
        _add("urls", cand)
    for cand in _EMAIL_RE.findall(text):
        _add("emails", cand.lower())
    for cand in _HASH_RE.findall(text):
        _add("hashes", cand.lower())
    for cand in _CVE_RE.findall(text):
        _add("cve_ids", cand.upper())
    for cand in _CAPEC_RE.findall(text):
        _add("capec_ids", cand.upper())
    for cand in _CWE_RE.findall(text):
        _add("cwe_ids", cand.upper())
    for cand in _MITRE_TECH_RE.findall(text):
        # avoid catching CVE-style tokens as MITRE technique IDs
        if not cand.startswith("CVE"):
            _add("mitre_techniques", cand.upper())
    for cand in _SID_RE.findall(text):
        _add("sids", cand)

    return {k: v for k, v in iocs.items() if v}


# ---------------------------------------------------------------------------
# Severity heuristic + MITRE keyword catalogue (fallback enrichment)
# ---------------------------------------------------------------------------

_SEVERITY_KEYWORDS = {
    "critical": {
        "zero-day", "0day", "exploited in the wild", "ransomware deployed", "code execution",
        "remote code execution", "critical severity", "cve-2", "worm", "nation-state",
    },
    "high": {
        "elevated", "high severity", "privilege escalation", "data exfiltration",
        "backdoor", "brute force", "lateral movement", "active exploit", "malware",
        "botnet", "c2", "command and control",
    },
    "medium": {
        "medium severity", "phishing", "spoofing", "dos", "denial of service",
        "information disclosure", "cross-site", "xss", "sql injection",
    },
    "low": {
        "low severity", "best practice", "configuration", "advisory",
        "patch available", "mitigation", "recommendation",
    },
}


def _text_scope(concepts) -> str:
    """Join normalized concept text into a single searchable corpus."""
    parts = []
    for c in concepts:
        if isinstance(c, dict):
            parts.append(str(c.get("label") or ""))
            parts.extend(str(s) for s in (c.get("sentences") or [])[:5])
        else:
            parts.append(getattr(c, "label", "") or "")
            parts.extend(getattr(c, "sentences", [])[:5])
    return "\n".join(parts)[:20000]


def assess_severity(concepts) -> str:
    """Keyword-based severity assessment over the whole concept space."""
    corpus = _text_scope(concepts).lower()
    for level, words in _SEVERITY_KEYWORDS.items():
        for w in words:
            if w.lower() in corpus:
                return level
    return "medium"


_MITRE_CATALOGUE = [
    ("T1190", "Exploit Public-Facing Application", ["exploit public-facing", "public-facing application", "internet-facing", "cve-2021"]),
    ("T1566", "Phishing", ["phishing", "spear-phishing", "malicious link"]),
    ("T1059", "Command and Scripting Interpreter", ["powershell", "cmd", "script", "wscript", "cscript"]),
    ("T1071", "Application Layer Protocol", ["c2", "command and control", "http beacon", "dns tunneling"]),
    ("T1219", "Remote Access Software", ["anydesk", "teamviewer", "remote access", "vnc"]),
    ("T1567", "Exfiltration Over Web Service", ["exfiltrat", "dropbox", "steal", "data theft"]),
    ("T1486", "Data Encrypted for Impact", ["ransomware", "encrypt", "decryptor", "lockbit", "qakbot", "locker"]),
    ("T1572", "Protocol Tunneling", ["tunneling", "ngrok", "chisel"]),
    ("T1041", "Exfiltration Over C2 Channel", ["beacon", "exfil over c2"]),
    ("T1539", "Steal Web Session Cookie", ["cookie stealing", "session hijack"]),
    ("T1548", "Abuse Elevation Control Mechanism", ["privilege escalation", "uac bypass", "bypass"]),
    ("T1003", "OS Credential Dumping", ["credential dumping", "mimikatz", "lsass", "samdump"]),
    ("T1053", "Scheduled Task/Job", ["scheduled task", "cron", "persistence"]),
    ("T1562", "Impair Defenses", ["disable antivirus", "kill defender", "impair defenses", "disabled security"]),
    ("T1078", "Valid Accounts", ["valid account", "stolen credential", "compromised account"]),
    ("T1133", "External Remote Services", ["vpn", "rdp", "citrix", "remote desktop"]),
    ("T1027", "Obfuscated Files or Information", ["payload obfusc", "packed", "xor", "base64 decode"]),
    ("T1203", "Exploitation for Client Execution", ["guacamole", "exploit kit", "weaponized document", "macro"]),
    ("T1583", "Acquire Infrastructure", ["bulletproof", "typosquat", "malicious domain infrastructure"]),
    ("T1566.001", "Phishing: Spearphishing Attachment", ["spearphishing attachment", "malicious attachment", "iso attachment"]),
    ("T1566.002", "Phishing: Spearphishing Link", ["spearphishing link", "malicious link"]),
]


def map_mitre_techniques(concepts) -> list[dict]:
    """Map detected concepts to MITRE ATT&CK technique IDs via keyword matching."""
    corpus = _text_scope(concepts).lower()
    matched: list[dict] = []
    for tech_id, name, keywords in _MITRE_CATALOGUE:
        if any(k.lower() in corpus for k in keywords):
            matched.append({"id": tech_id, "name": name})
    # Any CVE reference implies exploitation of a public-facing app/service
    if _CVE_RE.search(corpus):
        if not any(m["id"] == "T1190" for m in matched):
            matched.insert(0, {"id": "T1190", "name": "Exploit Public-Facing Application"})
    # Also capture explicit T-IDs already present in the text
    for tid in _MITRE_TECH_RE.findall(corpus):
        if not tid.startswith("cve"):
            if not any(m["id"] == tid.upper() for m in matched):
                matched.append({"id": tid.upper(), "name": "Technique (detected in text)"})
    return matched


_ACTIONS_BY_SEVERITY = {
    "critical": [
        "Isolate affected hosts and block associated IOCs at network egress immediately.",
        "Rapid threat hunt for lateral movement using the extracted indicators.",
        "Consult the latest public advisories for a patch/containment timeline.",
        "Stand up a tracking ticket with DSO/IR and preserve forensic artifacts.",
    ],
    "high": [
        "Hunt on SIEM for the extracted IOCs across the last 30 days.",
        "Review exposed services / edge appliances for the mapped MITRE techniques.",
        "Plan an emergency patch window if a CVE-IDs match in-scope assets.",
    ],
    "medium": [
        "Enrich indicators with a reputable CTI platform before blocking.",
        "Update detection rules for the reported techniques.",
        "Notify owners of affected products.",
    ],
    "low": [
        "Log advisory as informational; re-evaluate on new information.",
        "Review hardening guidance for the affected components.",
    ],
}


def recommend_actions(severity: str) -> list[str]:
    return _ACTIONS_BY_SEVERITY.get(severity, _ACTIONS_BY_SEVERITY["medium"])


def _merge_iocs(extracted: list[dict]) -> dict:
    merged: dict[str, list[str]] = {}
    for e in extracted:
        for typ, values in e.items():
            if isinstance(values, list):
                merged.setdefault(typ, [])
                for v in values:
                    if v not in merged[typ]:
                        merged[typ].append(v)
    return merged


# ---------------------------------------------------------------------------
# LLM integration (optional enrichment layer)
# ---------------------------------------------------------------------------

def _resolve_backend() -> str:
    """Выбор бэкенда генерации: 'mlx' (Apple Silicon), 'transformers' (CUDA/CPU), 'none'."""
    if _LLM_BACKEND in ("mlx", "transformers", "none"):
        return _LLM_BACKEND
    # auto
    try:
        import torch
        if torch.cuda.is_available():
            return "transformers"
    except Exception:
        pass
    try:
        if sys.platform == "darwin" and platform.machine().lower() in ("arm64", "aarch64"):
            import mlx  # noqa: F401
            return "mlx"
    except Exception:
        pass
    return "none"


def _pick_dtype() -> str:
    v = os.getenv("NCD_LLM_DTYPE", "auto").lower()
    if v != "auto":
        return v
    import torch
    if _LLM_DEVICE != "cpu" and torch.cuda.is_available() and torch.cuda.get_device_capability()[0] >= 8:
        return "bfloat16"
    return "float16"


def _load_llm():
    global _model, _tokenizer
    with _llm_lock:
        if _model is not None:
            return _model, _tokenizer
        if not list(_LLM_DIR.glob("*.safetensors")):
            logger.warning("LLM weights not found at %s", _LLM_DIR)
            return None, None

        backend = _resolve_backend()
        if backend == "mlx":
            from mlx_lm import load

            logger.info("Loading LLM (%s) from %s", backend, _LLM_DIR)
            _model, _tokenizer = load(str(_LLM_DIR))
        elif backend == "transformers":
            import torch
            from transformers import AutoModelForCausalLM, AutoTokenizer

            dtype = {"bfloat16": torch.bfloat16, "float16": torch.float16, "float32": torch.float32}.get(_pick_dtype(), torch.float16)
            logger.info("Loading LLM (transformers, dtype=%s) from %s", dtype, _LLM_DIR)
            _tokenizer = AutoTokenizer.from_pretrained(str(_LLM_DIR), trust_remote_code=True)
            _model = AutoModelForCausalLM.from_pretrained(
                str(_LLM_DIR),
                torch_dtype=dtype,
                device_map=_LLM_DEVICE if _LLM_DEVICE != "auto" else "auto",
                trust_remote_code=True,
            )
            _model.eval()
        else:
            logger.warning("No usable LLM backend (NCD_LLM_BACKEND=%s)", _LLM_BACKEND)
            return None, None

        logger.info("LLM ready (%s)", backend)
        return _model, _tokenizer


def _generate(messages: list[dict], max_tokens: int = 600, temp: float = 0.2) -> str:
    model, tokenizer = _load_llm()
    if model is None:
        return ""

    backend = _resolve_backend()
    if backend == "mlx":
        from mlx_lm import generate
        from mlx_lm.sample_utils import make_sampler

        prompt = tokenizer.apply_chat_template(messages, add_generation_prompt=True)
        sampler = make_sampler(temp=temp, top_p=0.9)
        return generate(
            model,
            tokenizer,
            prompt=prompt,
            max_tokens=max_tokens,
            sampler=sampler,
        ).strip()

    if backend == "transformers":
        import torch

        prompt = tokenizer.apply_chat_template(messages, add_generation_prompt=True)
        inputs = tokenizer(prompt, return_tensors="pt", truncation=True, max_length=4096).to(model.device)
        with torch.no_grad():
            out = model.generate(
                **inputs,
                max_new_tokens=max_tokens,
                do_sample=True,
                temperature=temp,
                top_p=0.9,
                pad_token_id=tokenizer.eos_token_id,
            )
        return tokenizer.decode(out[0][inputs["input_ids"].shape[1]:], skip_special_tokens=True).strip()

    return ""


_JSON_RE_OBJ = re.compile(r"\{.*\}", re.DOTALL)


def _extract_json_block(text: str) -> dict | None:
    """Extract the first balanced JSON object from LLM output."""
    m = _JSON_RE_OBJ.search(text)
    if not m:
        return None
    raw = m.group(0)
    try:
        return json.loads(raw)
    except json.JSONDecodeError:
        pass
    # Attempt repair: strip trailing-broken tail, try progressively shorter suffixes
    for split_point in range(len(raw), len(raw) // 2, -10):
        try:
            return json.loads(raw[:split_point])
        except json.JSONDecodeError:
            continue
    return None


def _llm_extract_structured(concepts_lines: str) -> dict | None:
    """Step 1: ask the LLM to emit a JSON structure with IOCs/severity/actions."""
    system = (
        "You are a threat-intelligence analyst. Extract structured indicators from the "
        "concepts below. Return ONLY valid JSON with exactly these keys: "
        '"iocs" (object with ipv4, domains, urls, hashes, cve_ids, mitre_techniques arrays), '
        '"severity" (one of low/medium/high/critical), '
        '"mitre_techniques" (array of {id, name}), '
        '"recommended_actions" (array of strings). '
        "Do not add commentary."
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": concepts_lines},
    ]
    raw = _generate(messages, max_tokens=500, temp=0.1)
    if not raw:
        return None
    return _extract_json_block(raw)


def _llm_digest(concepts_lines: str, structured: dict) -> str:
    """Step 2: human-readable digest grounded in the structured extraction."""
    sev = structured.get("severity", "medium")
    mitre = structured.get("mitre_techniques", [])
    iocs = structured.get("iocs", {})
    ioc_summary = "; ".join(
        f"{k}={len(v)}" for k, v in iocs.items() if isinstance(v, list) and v
    ) or "none"

    system = (
        "You are a threat-intelligence analyst. Write a concise operational digest "
        "of the detected concept space. Structure it with short Markdown sections: "
        "**Overall picture**, **Key risks**, **Recommended actions**. "
        f"Context: severity is {sev}; indicators found: {ioc_summary}. "
        "Keep it under 350 words. Do not invent facts beyond the provided list."
    )
    messages = [
        {"role": "system", "content": system},
        {"role": "user", "content": concepts_lines},
    ]
    return _generate(messages, max_tokens=600, temp=0.3)


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _backend_label() -> str:
    b = _resolve_backend()
    if b == "mlx":
        return "granite-4.0-1b (MLX 4-bit)"
    if b == "transformers":
        return "granite-4.0-1b (HF Transformers)"
    return "granite-4.0-1b (heuristics only)"


def summarize_space(concepts) -> dict:
    from .models import DetectedConcept

    norm = []
    for c in concepts:
        if isinstance(c, DetectedConcept):
            line = {
                "label": c.label or c.summary or c.concept_id,
                "strength": c.strength,
                "doc_count": c.document_count,
                "sentences": c.sentences[:3],
            }
        elif isinstance(c, dict):
            line = {
                "label": c.get("label") or c.get("summary") or c.get("conceptId") or c.get("concept_id") or "concept",
                "strength": float(c.get("strength", 0.0)),
                "doc_count": int(c.get("documentCount", c.get("document_count", 0))),
                "sentences": list(c.get("sentences") or [])[:3],
            }
        else:
            continue
        norm.append(line)

    if not norm:
        return {"summary": "", "model": "", "concepts": 0, "fallback": True}

    corpus = _text_scope(norm)

    # Deterministic layer (always available, never blocks)
    per_concept_iocs = [extract_iocs((" ".join(c["sentences"]) + " " + c["label"])) for c in norm]
    iocs = _merge_iocs(per_concept_iocs)
    severity = assess_severity(norm)
    mitre = map_mitre_techniques(norm)
    actions = recommend_actions(severity)

    lines = []
    for i, c in enumerate(norm, 1):
        head = f"{i}. {c['label']} (strength {c['strength']:.2f}, {c['doc_count']} documents)"
        lines.append(head)
        for s in c["sentences"]:
            lines.append(f"    - {s[:220]}")
    concepts_text = "\n".join(lines)

    # LLM layer (optional enrichment; fall back to heuristics if unavailable)
    structured = _llm_extract_structured(concepts_text)
    llm_ok = structured is not None

    if llm_ok:
        # Prefer LLM-extracted structured values but merge in deterministic IOCs
        llm_iocs = structured.get("iocs") or {}
        for typ, values in llm_iocs.items():
            if isinstance(values, list):
                iocs.setdefault(typ, [])
                for v in values:
                    s = str(v)
                    if s not in iocs[typ]:
                        iocs[typ].append(s)
        if structured.get("severity"):
            severity = structured["severity"]
        llm_mitre = structured.get("mitre_techniques") or []
        seen_ids = {m["id"] for m in mitre}
        for m in llm_mitre:
            if isinstance(m, dict) and m.get("id") and m["id"] not in seen_ids:
                mitre.append({"id": m["id"], "name": m.get("name", "")})
        if structured.get("recommended_actions"):
            actions = structured["recommended_actions"]

    digest = _llm_digest(concepts_text, {
        "severity": severity,
        "mitre_techniques": mitre,
        "iocs": iocs,
    }) if llm_ok else ""

    if not digest:
        # Deterministic fallback digest (no LLM required, informative)
        digest_lines = ["**Overall picture**",
                        f"Detected {len(norm)} distinct concepts in the embedding space.",
                        "",
                        "**Key indicators**"]
        if iocs:
            for typ, values in iocs.items():
                digest_lines.append(f"- {typ}: {', '.join(values[:8])}{'…' if len(values) > 8 else ''}")
        else:
            digest_lines.append("- no concrete IOCs extracted")
        digest_lines += ["", "**Assessed severity**", f"- {severity}",
                         "", "**Recommended actions**"]
        digest_lines += [f"- {a}" for a in actions]
        digest = "\n".join(digest_lines)

    fallback = not llm_ok

    return {
        "summary": digest,
        "model": _backend_label(),
        "concepts": len(norm),
        "concepts_input": [c["label"] for c in norm],
        "iocs": iocs,
        "severity": severity,
        "mitre_techniques": mitre,
        "recommended_actions": actions,
        "structured": llm_ok,
        "fallback": fallback,
    }
"""Contracts for the summarize endpoint, report builder and LLM guard."""
from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest import mock

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "ncdbody"))

from app.llm import (  # noqa: E402
    _REPORT_BATCH_SIZE,
    _REPORT_MAX_ITEMS,
    _api_generate,
    _build_security_report,
    _classify_concept,
    _concept_quality,
    _dedupe_concepts,
    _fallback_item_summary,
    _format_weight_size,
    _is_grounded,
    _llm_item_summaries,
    _normalize_concept,
    _parse_numbered_summaries,
    _prepare_report_items,
    _report_headline,
    _report_period,
    _select_report_items,
    _sources_checked,
    _split_reasoning,
    _summary_ctx,
    _summary_max_tokens,
    _summary_temperature,
    _THINK_CLOSE,
    _THINK_OPEN,
    _sanitize_digest,
    _resolve_llm_request,
    _weights_size,
    providers_snapshot,
    summarize_space,
)

REGISTRY = {
    "local": [],
    "api": [
        {
            "name": "OpenAI",
            "base_url": "https://api.openai.com/v1",
            "model": "gpt-4o-mini",
            "key_env": "OPENAI_API_KEY",
        },
        {
            "name": "Anthropic",
            "base_url": "https://api.anthropic.com/v1",
            "model": "claude-sonnet-4-5",
            "key_env": "ANTHROPIC_API_KEY",
            "format": "anthropic",
        },
    ],
}


class FakeResponse:
    def __init__(self, payload):
        self._body = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_args):
        return False

    def read(self):
        return self._body


class ReasoningSplitTest(unittest.TestCase):
    def test_closed_trace(self):
        reasoning, answer = _split_reasoning(_THINK_OPEN + " trace " + _THINK_CLOSE + " answer")
        self.assertEqual(reasoning, "trace")
        self.assertEqual(answer, "answer")

    def test_unterminated_trace(self):
        reasoning, answer = _split_reasoning(_THINK_OPEN + " cut trace...")
        self.assertEqual(reasoning, "cut trace...")
        self.assertEqual(answer, "")

    def test_plain_answer(self):
        reasoning, answer = _split_reasoning("plain answer")
        self.assertEqual(reasoning, "")
        self.assertEqual(answer, "plain answer")


class SummaryProfileTest(unittest.TestCase):
    """The summarization profile is the only generation configuration."""

    def test_defaults_are_sized_for_a_full_digest(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            for key in ("NCD_LLM_CTX", "NCD_LLM_MAX_TOKENS", "NCD_LLM_TEMPERATURE"):
                os.environ.pop(key, None)
            self.assertEqual(_summary_ctx(), 4096)
            self.assertEqual(_summary_max_tokens(), 1024)
            self.assertEqual(_summary_temperature(), 0.3)

    def test_environment_overrides_profile(self):
        with mock.patch.dict(os.environ, {
            "NCD_LLM_CTX": "8192",
            "NCD_LLM_MAX_TOKENS": "2048",
            "NCD_LLM_TEMPERATURE": "0.3",
        }):
            self.assertEqual(_summary_ctx(), 8192)
            self.assertEqual(_summary_max_tokens(), 2048)
            self.assertEqual(_summary_temperature(), 0.3)

    def test_invalid_values_fall_back_to_defaults(self):
        with mock.patch.dict(os.environ, {
            "NCD_LLM_CTX": "not-a-number",
            "NCD_LLM_MAX_TOKENS": "",
            "NCD_LLM_TEMPERATURE": "warm",
        }):
            self.assertEqual(_summary_ctx(), 4096)
            self.assertEqual(_summary_max_tokens(), 1024)
            self.assertEqual(_summary_temperature(), 0.3)


def _raw_concept(
    label: str,
    sentences: list[str] | None = None,
    strength: float = 0.5,
    documents: list[dict] | None = None,
    first_seen: str = "2026-10-01T12:00:00Z",
    summary: str | None = None,
) -> dict:
    sentences = sentences or [label]
    documents = documents or [
        {"url": "https://example.com/article", "source": "rss:www.example.com"},
    ]
    return {
        "label": label,
        "summary": summary if summary is not None else " ".join(sentences),
        "strength": strength,
        "documentCount": len(documents),
        "sentences": sentences,
        "documents": documents,
        "firstSeen": first_seen,
        "lastSeen": first_seen,
        "source": "web_20261102_040949",
    }


def _norm(label: str, **kwargs) -> dict:
    return _normalize_concept(_raw_concept(label, **kwargs))


class SecurityReportTest(unittest.TestCase):
    """The report must cover every concept, then show a balanced 32-item set."""

    def test_classification_examples(self):
        cases = [
            ("Trezor warns users of email provider breach, phishing attacks.", "news"),
            ("CVE-2026-114625 Arista VeloCloud Orchestrator SQL Injection", "research"),
            (
                "Post-quantum authentication: Why organizations should start testing "
                "certificate ecosystems now.",
                "ideas",
            ),
            ("Ransomware Attacks are on the Rise.", "ideas"),
            ("Siemens SIMATIC S7 PLCs Web Server.", "research"),
            ("LG to Ban Residential Proxies from Smart TV Apps.", "news"),
            ("OpenSSL announced a new attack affecting the Triple-DES cipher.", "research"),
        ]
        for label, expected in cases:
            with self.subTest(label=label):
                self.assertEqual(_classify_concept(_norm(label)), expected)

    def test_selection_is_balanced_and_capped(self):
        concepts = []
        for index in range(20):
            company = f"Acme{index}"
            product = f"Example{index}"
            concepts.append(_norm(
                f"{company} confirms data breach after ransomware attack",
                sentences=[
                    f"{company} confirms data breach after ransomware attack",
                    f"{company} said the ransomware attack exposed customer records in City{index}.",
                ],
                strength=1.0 - index / 100,
            ))
            concepts.append(_norm(
                f"CVE-2026-{1000 + index} affects {product} Server",
                sentences=[
                    f"CVE-2026-{1000 + index} affects {product} Server",
                    f"{product} Server is affected by the flaw, which allows remote code execution.",
                ],
                strength=0.9 - index / 100,
            ))
            concepts.append(_norm(
                f"Security strategy {index}: rethink risk management for {company}",
                sentences=[
                    f"Security strategy {index}: rethink risk management for {company}",
                    f"{company} should map risk management to Framework{index} priorities.",
                ],
                strength=0.8 - index / 100,
            ))

        selected = _select_report_items(concepts, _REPORT_MAX_ITEMS)
        total = sum(len(items) for items in selected.values())

        self.assertEqual(total, _REPORT_MAX_ITEMS)
        self.assertEqual(set(selected), {"news", "research", "ideas"})
        for category in ("news", "research", "ideas"):
            self.assertIn(len(selected[category]), (10, 11))

    def test_quality_filter_rejects_boilerplate_and_off_topic_items(self):
        for label in (
            "All rights to registrations and trademarks reside with their respective owners.",
            "The 4 biggest Amazon smart home announcements from today.",
            "An architectural weakness",
        ):
            with self.subTest(label=label):
                self.assertEqual(_concept_quality(_norm(label)), 0.0)
        self.assertGreater(_concept_quality(_norm("CVE-2026-1234 affects Example Server")), 0.0)

    def test_sources_checked_strips_rss_and_deduplicates(self):
        concepts = [
            _norm("CVE-2026-1234 affects Example Server", documents=[
                {"url": "https://www.cisa.gov/a", "source": "rss:www.cisa.gov"},
                {"url": "https://www.cisa.gov/b", "source": "rss:www.cisa.gov"},
                {"url": "https://blog.cloudflare.com/x", "source": "rss:blog.cloudflare.com"},
            ]),
        ]
        self.assertEqual(_sources_checked(concepts), ["blog.cloudflare.com", "cisa.gov"])

    def test_period_uses_explicit_since_then_earliest_first_seen(self):
        concepts = [
            _norm("CVE-2026-1234 affects Example Server", first_seen="2026-10-03T10:00:00Z"),
            _norm("CVE-2026-1235 affects Example Server", first_seen="2026-09-09T10:00:00Z"),
        ]
        self.assertEqual(_report_period(concepts), "Since 2026-09-09")
        self.assertEqual(_report_period(concepts, since="2026-10-01"), "Since 2026-10-01")
        self.assertEqual(_report_period([]), "First run")

    def test_headline_completes_a_truncated_label(self):
        label = "North Korean hackers blamed for stealing record $6.3B in Bin"
        sentence = "North Korean hackers blamed for stealing record $6.3B in Binance breach."
        concept = _norm(label, sentences=[sentence, "Binance hit by the largest crypto theft."])
        self.assertEqual(_report_headline(concept), sentence)

    def test_headline_strips_a_publisher_suffix(self):
        label = "Employees Still the Biggest Threat to Enterprise Security | DigiCert.com."
        concept = _norm(label, sentences=[label])
        self.assertEqual(
            _report_headline(concept),
            "Employees Still the Biggest Threat to Enterprise Security",
        )

    def test_fallback_summary_prefers_the_detail_sentence(self):
        label = "Trezor warns users of email provider breach, phishing attacks."
        detail = (
            "Trezor warned customers on Wednesday that threat actors who breached its "
            "third-party email provider are targeting them in phishing attacks."
        )
        concept = _norm(label, sentences=[label, detail])
        self.assertEqual(_fallback_item_summary(_report_headline(concept), concept), detail)

    def test_dedupe_keeps_the_strongest_near_duplicate(self):
        weak = _norm("Acme confirms data breach after attack one", strength=0.2)
        strong = _norm("Acme confirms data breach after attack two", strength=0.9)
        deduped = _dedupe_concepts([weak, strong])
        self.assertEqual(len(deduped), 1)
        self.assertEqual(deduped[0]["strength"], 0.9)

    def test_numbered_summary_parser_accepts_preamble_and_continuation(self):
        parsed = _parse_numbered_summaries(
            "Here are the summaries:\n"
            "1. First detail.\n"
            "2. Second detail\n"
            "continued on the next line.\n"
            "3. Third detail.",
            3,
        )
        self.assertEqual(parsed[1], "First detail.")
        self.assertIn("continued", parsed[2])
        self.assertEqual(parsed[3], "Third detail.")

    def test_grounding_rejects_invented_numbers_and_cves(self):
        source = "A breach exposed 4.1 million people and involved CVE-2026-1234."
        self.assertTrue(_is_grounded("A breach exposed 4.1 million people.", source))
        self.assertFalse(_is_grounded("A breach exposed 5 million people.", source))
        self.assertFalse(_is_grounded("CVE-2026-9999 is critical.", source))

    def test_empty_model_output_falls_back_without_raising(self):
        label = "Trezor warns users of email provider breach, phishing attacks."
        detail = (
            "Trezor warned customers that threat actors who breached its email "
            "provider are targeting them in phishing attacks."
        )
        items = _prepare_report_items(_select_report_items(
            [_norm(label, sentences=[label, detail])],
            _REPORT_MAX_ITEMS,
        ))
        with mock.patch("app.llm._generate", return_value=""):
            summaries, errors, batches = _llm_item_summaries(items)
        self.assertEqual(summaries, {})
        self.assertEqual(errors, [])
        self.assertEqual(batches, 1)

    def test_summarize_space_emits_the_requested_layout(self):
        concepts = []
        for index in range(12):
            company = f"Acme{index}"
            product = f"Example{index}"
            concepts.append(_raw_concept(
                f"{company} confirms data breach after ransomware attack",
                sentences=[
                    f"{company} confirms data breach after ransomware attack",
                    f"{company} said the ransomware attack exposed customer records in City{index}.",
                ],
                strength=0.9 - index / 100,
            ))
            concepts.append(_raw_concept(
                f"CVE-2026-{2000 + index} affects {product} Server",
                sentences=[
                    f"CVE-2026-{2000 + index} affects {product} Server",
                    f"{product} Server is affected by the flaw, which allows remote code execution.",
                ],
                strength=0.8 - index / 100,
                documents=[
                    {"url": "https://www.cisa.gov/x", "source": "rss:www.cisa.gov"},
                    {"url": "https://www.cisa.gov/y", "source": "rss:www.cisa.gov"},
                ],
            ))
            concepts.append(_raw_concept(
                f"Security strategy {index}: rethink risk management for {company}",
                sentences=[
                    f"Security strategy {index}: rethink risk management for {company}",
                    f"{company} should map risk management to Framework{index} priorities.",
                ],
                strength=0.7 - index / 100,
            ))

        with mock.patch("app.llm._llm_item_summaries", return_value=({}, [], 0)):
            result = summarize_space(concepts, llm=None, since="2026-10-01")

        report = result["summary"]
        self.assertTrue(result["fallback"])
        self.assertEqual(result["concepts"], 36)
        self.assertEqual(result["selected_items"], _REPORT_MAX_ITEMS)
        self.assertEqual(result["llm_items"], 0)
        self.assertEqual(sum(result["categories"].values()), _REPORT_MAX_ITEMS)
        self.assertTrue(report.startswith("# Security Updates"))
        self.assertIn("**Generated:**", report)
        self.assertIn("**Sources Checked:**", report)
        self.assertIn("cisa.gov", report)
        self.assertIn("**Period:** Since 2026-10-01", report)
        self.assertIn("## Security News (Breaches & Incidents)", report)
        self.assertIn("## Security Research", report)
        self.assertIn("## Security Ideas", report)
        self.assertIn("## Summary", report)
        self.assertIn("| News |", report)
        self.assertIn(f"**Total:** {_REPORT_MAX_ITEMS}/{_REPORT_MAX_ITEMS} items", report)

    def test_report_builder_marks_an_empty_category(self):
        label = "Trezor warns users of email provider breach, phishing attacks."
        detail = (
            "Trezor warned customers that threat actors who breached its email "
            "provider are targeting them in phishing attacks."
        )
        items = _prepare_report_items(_select_report_items(
            [_norm(label, sentences=[label, detail])],
            _REPORT_MAX_ITEMS,
        ))
        report = _build_security_report(
            [item for item in items if item["category"] == "news"],
            ["cisa.gov"],
            "2026-11-05 10:00 UTC",
            "Since 2026-10-01",
        )
        self.assertIn("_No items in this window._", report)
        self.assertIn("| Research | 0 | — |", report)
        self.assertIn("**Total:** 1/32 items", report)

    def test_batch_size_keeps_local_prompts_small(self):
        self.assertLessEqual(_REPORT_BATCH_SIZE, 8)


class DigestSanitizerTest(unittest.TestCase):
    def test_clean_digest_is_unchanged(self):
        clean, truncated = _sanitize_digest("**Overall picture**\n\nAll good.")
        self.assertEqual(clean, "**Overall picture**\n\nAll good.")
        self.assertFalse(truncated)

    def test_degenerate_tail_is_cut(self):
        clean, truncated = _sanitize_digest("**Overall picture**\n\nok\n\n!!!!!!!!!!!!!!!!")
        self.assertEqual(clean, "**Overall picture**\n\nok")
        self.assertTrue(truncated)


class ModelWeightsTest(unittest.TestCase):
    def test_format_weight_size_uses_binary_units(self):
        self.assertEqual(_format_weight_size(0), "0 B")
        self.assertEqual(_format_weight_size(512), "512 B")
        self.assertEqual(_format_weight_size(1024), "1.0 KB")
        self.assertEqual(_format_weight_size(1024 ** 2), "1.0 MB")
        self.assertEqual(_format_weight_size(3 * 1024 ** 3), "3.0 GB")
        self.assertEqual(_format_weight_size(5 * 1024 ** 4), "5.0 TB")

    def test_weights_size_sums_only_safetensors(self):
        with tempfile.TemporaryDirectory() as tmp:
            model_dir = Path(tmp)
            (model_dir / "model-00001-of-00002.safetensors").write_bytes(b"x" * 1024)
            (model_dir / "model-00002-of-00002.safetensors").write_bytes(b"x" * 2048)
            (model_dir / "config.json").write_bytes(b"x" * 4096)
            self.assertEqual(_weights_size(model_dir), 3072)

    def test_weights_size_missing_directory_is_zero(self):
        with tempfile.TemporaryDirectory() as tmp:
            self.assertEqual(_weights_size(Path(tmp) / "missing"), 0)

    def test_providers_snapshot_reports_actual_weight_size(self):
        with tempfile.TemporaryDirectory() as tmp:
            model_dir = Path(tmp)
            (model_dir / "model.safetensors").write_bytes(b"x" * 1536)
            registry = {
                "local": [{
                    "name": "Granite 4.0 1B (transformers)",
                    "size_hint": "~3.3 GB",
                }],
                "api": [],
            }
            with mock.patch("app.llm._load_registry", return_value=registry), \
                    mock.patch("app.llm._LLM_DIR", model_dir):
                local = providers_snapshot()["local"][0]

        self.assertTrue(local["available"])
        self.assertEqual(local["size_bytes"], 1536)
        self.assertEqual(local["size_human"], "1.5 KB")
        self.assertEqual(local["size_hint"], "~3.3 GB")

    def test_providers_snapshot_keeps_the_download_hint_without_weights(self):
        with tempfile.TemporaryDirectory() as tmp:
            registry = {
                "local": [{"name": "Granite 4.0 1B (transformers)",
                           "size_hint": "~3.3 GB"}],
                "api": [],
            }
            with mock.patch("app.llm._load_registry", return_value=registry), \
                    mock.patch("app.llm._LLM_DIR", Path(tmp) / "missing"):
                local = providers_snapshot()["local"][0]

        self.assertFalse(local["available"])
        self.assertEqual(local["size_bytes"], 0)
        self.assertEqual(local["size_human"], "0 B")
        self.assertEqual(local["size_hint"], "~3.3 GB")


class LlmEndpointGuardTest(unittest.TestCase):

    def test_registry_provider_is_allowed(self):
        resolved = _resolve_llm_request(
            {"provider": "api", "name": "OpenAI", "api_key": "test-key"},
            REGISTRY,
        )

        self.assertEqual(resolved["base_url"], "https://api.openai.com/v1")

    def test_custom_base_url_is_rejected_by_default(self):
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("NCD_ALLOW_CUSTOM_LLM_ENDPOINT", None)
            with self.assertRaisesRegex(ValueError, "Custom LLM base_url"):
                _resolve_llm_request(
                    {
                        "provider": "api",
                        "base_url": "http://169.254.169.254/latest",
                        "model": "x",
                        "api_key": "test-key",
                    },
                    REGISTRY,
                )

    def test_custom_endpoint_still_rejects_non_http_schemes(self):
        with mock.patch.dict(os.environ, {"NCD_ALLOW_CUSTOM_LLM_ENDPOINT": "1"}):
            with self.assertRaisesRegex(ValueError, "absolute http"):
                _resolve_llm_request(
                    {
                        "provider": "api",
                        "base_url": "file:///etc/passwd",
                        "model": "x",
                        "api_key": "test-key",
                    },
                    REGISTRY,
                )

    def test_registry_base_url_matches_explicit_request(self):
        resolved = _resolve_llm_request(
            {
                "provider": "api",
                "name": "OpenAI",
                "base_url": "https://api.openai.com/v1",
                "api_key": "test-key",
            },
            REGISTRY,
        )

        self.assertEqual(resolved["provider"], "api")

    def test_registry_url_without_name_is_allowed(self):
        resolved = _resolve_llm_request(
            {
                "provider": "api",
                "base_url": "https://api.openai.com/v1/",
                "model": "gpt-4o-mini",
                "api_key": "test-key",
            },
            REGISTRY,
        )

        self.assertEqual(resolved["base_url"], "https://api.openai.com/v1/")

    def test_anthropic_registry_entry_uses_messages_format(self):
        with mock.patch.dict(os.environ, {"ANTHROPIC_API_KEY": "test-key"}):
            resolved = _resolve_llm_request(
                {"provider": "api", "name": "Anthropic"},
                REGISTRY,
            )

        self.assertEqual(resolved["format"], "anthropic")
        self.assertEqual(resolved["base_url"], "https://api.anthropic.com/v1")
        self.assertEqual(resolved["model"], "claude-sonnet-4-5")

    def test_anthropic_format_is_inferred_from_registered_base_url(self):
        resolved = _resolve_llm_request(
            {
                "provider": "api",
                "base_url": "https://api.anthropic.com/v1",
                "api_key": "test-key",
            },
            REGISTRY,
        )

        self.assertEqual(resolved["format"], "anthropic")
        self.assertEqual(resolved["model"], "claude-sonnet-4-5")

    def test_unsupported_api_format_is_rejected(self):
        with self.assertRaisesRegex(ValueError, "Unsupported LLM API format"):
            _resolve_llm_request(
                {
                    "provider": "api",
                    "name": "OpenAI",
                    "api_key": "test-key",
                    "format": "gemini",
                },
                REGISTRY,
            )

    def test_anthropic_generate_uses_messages_api(self):
        captured = {}

        def fake_urlopen(request, timeout=0):
            captured["url"] = request.full_url
            captured["headers"] = {
                key.lower(): value for key, value in request.headers.items()
            }
            captured["body"] = json.loads(request.data.decode("utf-8"))
            captured["timeout"] = timeout
            return FakeResponse({
                "content": [
                    {"type": "text", "text": "Short "},
                    {"type": "text", "text": "summary"},
                ]
            })

        with mock.patch("app.llm.urllib.request.urlopen", side_effect=fake_urlopen):
            text = _api_generate(
                [
                    {"role": "system", "content": "Be concise"},
                    {"role": "user", "content": "Summarize this advisory"},
                ],
                base_url="https://api.anthropic.com/v1",
                api_key="test-key",
                model="claude-sonnet-4-5",
                max_tokens=200,
                temp=0.3,
                api_format="anthropic",
            )

        self.assertEqual(text, "Short summary")
        self.assertEqual(captured["url"], "https://api.anthropic.com/v1/messages")
        self.assertEqual(captured["headers"]["x-api-key"], "test-key")
        self.assertEqual(captured["headers"]["anthropic-version"], "2023-06-01")
        self.assertEqual(captured["headers"]["content-type"], "application/json")
        self.assertEqual(captured["body"]["system"], "Be concise")
        self.assertEqual(captured["body"]["model"], "claude-sonnet-4-5")
        self.assertEqual(captured["body"]["max_tokens"], 200)
        self.assertEqual(captured["body"]["messages"], [
            {"role": "user", "content": "Summarize this advisory"},
        ])

    def test_anthropic_empty_content_is_an_error(self):
        with mock.patch(
            "app.llm.urllib.request.urlopen",
            return_value=FakeResponse({"content": []}),
        ):
            with self.assertRaisesRegex(ValueError, "Anthropic API returned empty content"):
                _api_generate(
                    [{"role": "user", "content": "hi"}],
                    base_url="https://api.anthropic.com/v1",
                    api_key="test-key",
                    model="claude-sonnet-4-5",
                    api_format="anthropic",
                )

    def test_openai_compatible_format_still_works(self):
        captured = {}

        def fake_urlopen(request, timeout=0):
            captured["url"] = request.full_url
            captured["headers"] = {
                key.lower(): value for key, value in request.headers.items()
            }
            return FakeResponse({"choices": [{"message": {"content": "ok"}}]})

        with mock.patch("app.llm.urllib.request.urlopen", side_effect=fake_urlopen):
            text = _api_generate(
                [{"role": "user", "content": "hi"}],
                base_url="https://api.openai.com/v1",
                api_key="test-key",
                model="gpt-4o-mini",
                api_format="openai",
            )

        self.assertEqual(text, "ok")
        self.assertEqual(captured["url"], "https://api.openai.com/v1/chat/completions")
        self.assertEqual(captured["headers"]["authorization"], "Bearer test-key")


if __name__ == "__main__":
    unittest.main()

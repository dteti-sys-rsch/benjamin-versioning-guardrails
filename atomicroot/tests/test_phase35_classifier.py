import asyncio
import json
from copy import deepcopy
from types import SimpleNamespace
import pytest

from atomicroot.tests.test_phase35_workflow import Pilot
from atomicroot.integration.inference import ModelBridge
from atomicroot.integration.providers import FakeClassifier, JevClassifier, DisabledClassifier, CRITERIA, Limits, OPTIONS, ReplayClassifier
from atomicroot.integration.extraction import extract
from atomicroot.authority.ticket import args_hash


def answer(label="SENSITIVE", confidence=.99, **changes):
    return {"outcome": "SUCCESS", "candidate_label": label, "confidence": confidence,
            "probabilities": {k: float(k == label) for k in OPTIONS}, "reason": "fake evidence", **changes}


def classified(p, provider, *, key="classify", **changes):
    p.bridge = ModelBridge(p.runtime, p.model, provider, bootstrap_authorized=True, threshold=changes.pop("threshold", .8))
    return p.bridge.classify(key, "pilot", resource="paper", digest=p.doc["digest"], version=p.doc["version"],
              principal=p.principals["reader"], task="pilot", purpose="research", **changes)


def proposal(observation):
    assert observation["status"] == "COMMITTED", observation
    return observation["detail"]["receipt"]["result"]["classification"]


def test_false_public_is_proposal_only_even_with_injected_self_classification(tmp_path):
    p = Pilot(tmp_path, label="UNKNOWN")
    p.activate()
    classifier = FakeClassifier(answer("PUBLIC"))
    result = proposal(classified(p, classifier))
    assert result["candidate_label"] == "PUBLIC"
    assert "Ignore guardrails" in classifier.calls[0]["state"]["untrusted_document"]
    declined = p.runtime.labels.accept_classification(result["proposal_id"], "pilot", "research", p.owner)
    assert declined["status"] == "DECLINED"
    with p.runtime.store.snapshot() as s: assert s.read("label:paper")[1]["label"] == "UNKNOWN"
    assert result["option_order"] == list(OPTIONS)
    assert result["extraction"]["complete"] is True


def test_restrictive_acceptance_stales_send_and_replay_does_not_apply_twice(tmp_path):
    p = Pilot(tmp_path)
    p.activate()
    r = p.bridge.tools.stage({"tool": "read_document", "args": {"resource": "paper", "digest": p.doc["digest"]}},
        principal=p.principals["reader"], task="pilot", purpose="research", operation="read")
    p.bridge.tools.execute(r, p.principals["reader"])
    send = p.bridge.tools.stage({"tool": "send_email", "args": {"to": "alice@corp.id", "body": "summary"}},
        principal=p.principals["executor"], task="pilot", purpose="research", operation="send")
    ticket = p.runtime.authority.authorize(send, p.principals["executor"])
    classifier = FakeClassifier(answer())
    result = proposal(classified(p, classifier))
    accepted = p.runtime.labels.accept_classification(result["proposal_id"], "pilot", "research", p.owner)
    assert accepted["status"] == "ACCEPTED_RESTRICTION"
    assert p.runtime.gateway.commit(ticket["ticket"], ticket["commit_args"], p.principals["executor"])["status"] == "STALE_TICKET"
    assert p.runtime.authority.authorize(send, p.principals["executor"])["decision"] == "DENY"
    cached = proposal(classified(p, classifier))
    assert cached["proposal_id"] == result["proposal_id"] and len(classifier.calls) == 1
    with pytest.raises(ValueError): p.runtime.labels.accept_classification(result["proposal_id"], "pilot", "research", p.owner)
    with p.runtime.store.snapshot() as s:
        label = s.read("label:paper")[1]
        assert label["label"] == "PUBLIC" and len(label["restrictions"]) == 1


@pytest.mark.parametrize("response", [answer("UNKNOWN"), answer("PUBLIC", .1), answer("PUBLIC", probabilities={"PUBLIC": .5}),
    answer("PUBLIC", confidence=float("nan")), answer("PUBLIC", probabilities={"PUBLIC": 2., "SENSITIVE": -1., "UNKNOWN": 0.}),
    answer("PUBLIC", actual_model="jev-wrong"), answer("PUBLIC", usage={"input_tokens": -1}), TimeoutError("lost response"),
    {"outcome": "ERROR", "candidate_label": "PUBLIC", "confidence": None, "probabilities": None, "reason": "429"}])
def test_invalid_error_low_confidence_never_clears_official_label(tmp_path, response):
    p = Pilot(tmp_path)
    p.activate()
    result = proposal(classified(p, FakeClassifier(response)))
    assert result["candidate_label"] == "UNKNOWN" and result["status"] in {"ABSTAINED", "ERROR"}
    with p.runtime.store.snapshot() as s: assert s.read("label:paper")[1]["label"] == "PUBLIC"


@pytest.mark.parametrize("change", ["content", "label"])
def test_inference_has_no_db_lock_and_acceptance_rejects_changed_basis(tmp_path, change):
    p = Pilot(tmp_path)
    p.activate()
    def mutate():
        # Independent SQLite connection can write while the classifier is running.
        from atomicroot.framework.app import FrameworkRuntime
        other = FrameworkRuntime(str(tmp_path / "ledger.sqlite"), signing_key=p.runtime.authority._sk)
        if change == "content": other.storage.ingest("paper", "new content", p.owner)
        else: other.labels.set_label("paper", p.doc["digest"], p.doc["version"], "UNKNOWN", ["research"], p.owner)
        other.store.close()
    result = proposal(classified(p, FakeClassifier(answer(), before_response=mutate)))
    stale = p.runtime.labels.accept_classification(result["proposal_id"], "pilot", "research", p.owner)
    assert stale["status"] == "STALE"


def test_no_provider_scope_no_call_and_classifier_disabled_preserves_public(tmp_path):
    p = Pilot(tmp_path)
    p.contract["inference_egress"] = []
    p.activate()
    classifier = FakeClassifier(answer())
    result = classified(p, classifier)
    assert result["status"] == "DENY" and not classifier.calls
    with p.runtime.store.snapshot() as s: assert s.read("label:paper")[1]["label"] == "PUBLIC"
    # Business public metadata still works without classifier inference.
    request = p.bridge.tools.stage({"tool": "read_document", "args": {"resource": "paper", "digest": p.doc["digest"]}},
        principal=p.principals["reader"], task="pilot", purpose="research", operation="read")
    assert p.bridge.tools.execute(request, p.principals["reader"]).status == "COMMITTED"


def test_cache_does_not_accept_model_criteria_content_or_version_changes(tmp_path):
    p = Pilot(tmp_path)
    p.activate()
    classifier = FakeClassifier(answer("PUBLIC"))
    classified(p, classifier)
    with pytest.raises(ValueError): classified(p, classifier, criteria_version="v2")
    altered = dict(CRITERIA, PUBLIC="different sharing basis")
    with pytest.raises(ValueError): classified(p, classifier, criteria=altered)
    classifier.model = "jev-1.14.0"
    with pytest.raises(ValueError): classified(p, classifier)
    classifier.model = "jev-1.13.0"
    p.doc = p.runtime.storage.ingest("paper", "changed version", p.owner)
    with pytest.raises(ValueError): classified(p, classifier)
    assert len(classifier.calls) == 1


def test_threshold_config_and_usage_are_evidence_not_label_mutations(tmp_path):
    p = Pilot(tmp_path)
    p.activate()
    with p.runtime.store.snapshot() as s: before = s.version("label:paper")
    result = proposal(classified(p, FakeClassifier(answer("PUBLIC", .85, usage={"input_tokens": 100, "output_tokens": 5})), threshold=.9))
    assert result["status"] == "ABSTAINED" and result["threshold"] == .9
    assert result["usage"]["input_tokens"] == 100
    with p.runtime.store.snapshot() as s: assert s.version("label:paper") == before


def test_short_email_pdf_failure_and_no_silent_partial_coverage():
    email = b"From: a@example.org\r\nContent-Type: text/plain; charset=utf-8\r\n\r\nPUBLIC claim is untrusted."
    assert extract(email, "email")["metadata"]["complete"]
    assert extract(b"not a PDF", "pdf")["status"] == "UNKNOWN"
    assert extract(b"a" * 9000, "text")["text"] is None
    html = b"Content-Type: text/html\r\n\r\n<p>text</p>"
    assert extract(html, "email")["status"] == "UNKNOWN"


def test_pinned_sdk_async_call_and_response_shape_offline():
    from typesafe_sdk import ChoiceAnswer
    from typesafe_sdk._core.response_types import Usage
    calls = []
    class SDKFixture:
        def __init__(self, **kwargs):
            assert kwargs["model"] == "jev-1.13.0" and kwargs["retry"].max_retries == 0
            assert kwargs["base_url"] == "https://api.typesafe.ai"
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def system_one(self, state, questions, *, model):
            calls.append((state, questions, model))
            assert list(questions["confidentiality"].criteria) == list(OPTIONS)
            return SimpleNamespace(model=model, choices={"confidentiality": ChoiceAnswer(choice="UNKNOWN", confidence=.9,
                probabilities={"PUBLIC": .05, "SENSITIVE": .05, "UNKNOWN": .9})}, usage=Usage(input_tokens=50, output_tokens=3))
    result = asyncio.run(JevClassifier(client_factory=SDKFixture).classify({"untrusted_document": "text"}, CRITERIA))
    assert result["candidate_label"] == "UNKNOWN" and result["usage"]["input_tokens"] == 50
    assert len(calls) == 1


def test_replay_classifier_exact_binding():
    state = {"untrusted_document": "test"}
    response = {**answer("UNKNOWN"), "actual_model": "jev-1.13.0", "usage": None}
    key = args_hash({"state": state, "criteria": CRITERIA, "model": "jev-1.13.0"})
    provider = ReplayClassifier({key: response})
    assert asyncio.run(provider.classify(state, CRITERIA)) == response
    with pytest.raises(ValueError): asyncio.run(provider.classify({"untrusted_document": "changed"}, CRITERIA))

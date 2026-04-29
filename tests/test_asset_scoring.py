from app.services.asset_scoring import calculate_ai_confidence, confidence_bucket, normalize_signals
from app.services.network_service import _runtime_ai_signal


def test_diminishing_returns_scoring_math():
    score = calculate_ai_confidence([
        {"signal_type": "llm_api_env", "weight": 4},
        {"signal_type": "declared_ai_port", "weight": 2},
    ])
    assert score == 5.2


def test_tier4_signals_are_capped_before_accumulation():
    score = calculate_ai_confidence([
        {"signal_type": "weak_name_match", "weight": 1},
        {"signal_type": "weak_label_match", "weight": 1},
        {"signal_type": "weak_annotation_match", "weight": 1},
        {"signal_type": "weak_image_match", "weight": 1},
    ])
    assert score == 2.0


def test_confidence_bucket_boundaries():
    assert confidence_bucket(2.9) == "Speculative"
    assert confidence_bucket(3.0) == "Probable"
    assert confidence_bucket(4.9) == "Probable"
    assert confidence_bucket(5.0) == "Likely"
    assert confidence_bucket(7.9) == "Likely"
    assert confidence_bucket(8.0) == "Confirmed"
    assert confidence_bucket(9.0) == "Confirmed"


def test_dns_and_sni_collapse_to_one_provider_signal():
    signals = normalize_signals([
        {"signal_type": "ai_provider_dns", "value": "api.openai.com", "weight": 5},
        {"signal_type": "ai_provider_sni", "value": "api.openai.com", "weight": 5},
    ])
    assert signals == [
        {
            "signal_type": "ai_provider_endpoint",
            "value": "openai",
            "weight": 5.0,
        }
    ]


def test_runtime_dns_and_sni_events_become_provider_signals():
    dns_signal = _runtime_ai_signal({
        "event_type": "dns_query",
        "dns_query": "api.openai.com.",
    })
    sni_signal = _runtime_ai_signal({
        "event_type": "tls_sni",
        "tls_sni": "api.anthropic.com",
    })
    assert dns_signal["signal_type"] == "ai_provider_dns"
    assert dns_signal["value"] == "api.openai.com"
    assert sni_signal["signal_type"] == "ai_provider_sni"
    assert sni_signal["value"] == "api.anthropic.com"

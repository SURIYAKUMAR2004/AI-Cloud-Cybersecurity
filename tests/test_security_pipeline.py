import pandas as pd

from ai.risk_engine import calculate_risk
from security.contextual_risk_engine import calculate_contextual_score
from security.risk_aggregator import (
    calculate_signal_agreement,
    calculate_final_risk,
)


def test_normal_event_is_low_risk():
    row = pd.Series({
        "threat_status": "Normal",
        "source_ip": "192.168.1.12",
        "status": "Success",
        "action": "Login",
        "bytes_transferred": 3000,
    })

    score, level = calculate_risk(row)

    assert score == 0
    assert level == "LOW"


def test_suspicious_ip_failed_large_transfer_is_critical():
    row = pd.Series({
        "threat_status": "Anomaly",
        "source_ip": "45.155.205.10",
        "status": "Failed",
        "action": "Login",
        "bytes_transferred": 418840,
    })

    score, level = calculate_risk(row)

    assert score == 85
    assert level == "CRITICAL"


def test_contextual_risk_detects_multiple_signals():
    row = pd.Series({
        "threat_status": "Anomaly",
        "behavior_deviation_score": 50,
        "action": "AssumeRole",
        "status": "Failed",
        "bytes_transferred": 100000,
        "hour": 23,
    })

    score = calculate_contextual_score(row)

    assert score == 95


def test_signal_agreement():
    agreement = calculate_signal_agreement(
        contextual_risk=70,
        chain_score=80,
    )

    assert agreement == 90


def test_final_risk_is_critical():
    score, level = calculate_final_risk(
        contextual_risk=90,
        chain_score=100,
        events_correlated=5,
    )

    assert score == 91
    assert level == "CRITICAL"

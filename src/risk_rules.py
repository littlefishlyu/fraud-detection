from __future__ import annotations

from typing import Dict


def score_transaction(tx: Dict) -> int:
    """Return a fraud risk score from 0 to 100.

    Every signal adds points; higher scores mean higher risk.
    Severe signals (device >=80, velocity >=8) are weighted heavily enough
    that a single one pushes a transaction into medium territory on its own,
    and two severe signals together reach high risk.
    """
    score = 0

    # Device risk score — a compromised or emulated device is a strong fraud signal.
    if tx["device_risk_score"] >= 80:
        score += 35
    elif tx["device_risk_score"] >= 50:
        score += 15
    elif tx["device_risk_score"] >= 30:
        score += 5

    # International transactions carry materially higher fraud rates.
    if tx["is_international"] == 1:
        score += 15

    # Large purchase amounts increase potential loss exposure.
    if tx["amount_usd"] >= 1000:
        score += 25
    elif tx["amount_usd"] >= 500:
        score += 10

    # Transaction velocity — rapid bursts signal card testing or account takeover.
    if tx["velocity_24h"] >= 8:
        score += 30
    elif tx["velocity_24h"] >= 5:
        score += 15
    elif tx["velocity_24h"] >= 3:
        score += 5

    # Failed login attempts in the past 24 h are an account-takeover indicator.
    if tx["failed_logins_24h"] >= 5:
        score += 25
    elif tx["failed_logins_24h"] >= 2:
        score += 10

    # Repeat chargeback history is the strongest predictor of future fraud.
    if tx["prior_chargebacks"] >= 2:
        score += 25
    elif tx["prior_chargebacks"] == 1:
        score += 10

    return max(0, min(score, 100))


def label_risk(score: int) -> str:
    if score >= 60:
        return "high"
    if score >= 30:
        return "medium"
    return "low"

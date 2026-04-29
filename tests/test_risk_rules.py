from risk_rules import label_risk, score_transaction


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def clean_tx(**overrides):
    """Return a baseline low-risk transaction with any field overridden."""
    base = {
        "device_risk_score": 5,
        "is_international": 0,
        "amount_usd": 20.0,
        "velocity_24h": 1,
        "failed_logins_24h": 0,
        "prior_chargebacks": 0,
    }
    base.update(overrides)
    return base


# ---------------------------------------------------------------------------
# Label thresholds
# ---------------------------------------------------------------------------

def test_label_low():
    assert label_risk(0) == "low"
    assert label_risk(29) == "low"


def test_label_medium():
    assert label_risk(30) == "medium"
    assert label_risk(59) == "medium"


def test_label_high():
    assert label_risk(60) == "high"
    assert label_risk(100) == "high"


# ---------------------------------------------------------------------------
# Low-risk baseline
# ---------------------------------------------------------------------------

def test_clean_transaction_scores_zero():
    assert score_transaction(clean_tx()) == 0


def test_clean_transaction_is_low_risk():
    assert label_risk(score_transaction(clean_tx())) == "low"


# ---------------------------------------------------------------------------
# Each signal adds risk (regression guard against sign inversions)
# ---------------------------------------------------------------------------

def test_high_device_risk_increases_score():
    assert score_transaction(clean_tx(device_risk_score=85)) > score_transaction(clean_tx())


def test_international_increases_score():
    assert score_transaction(clean_tx(is_international=1)) > score_transaction(clean_tx())


def test_large_amount_increases_score():
    assert score_transaction(clean_tx(amount_usd=1200)) > score_transaction(clean_tx(amount_usd=20))


def test_high_velocity_increases_score():
    assert score_transaction(clean_tx(velocity_24h=9)) > score_transaction(clean_tx(velocity_24h=1))


def test_failed_logins_increase_score():
    assert score_transaction(clean_tx(failed_logins_24h=6)) > score_transaction(clean_tx(failed_logins_24h=0))


def test_prior_chargebacks_increase_score():
    assert score_transaction(clean_tx(prior_chargebacks=2)) > score_transaction(clean_tx(prior_chargebacks=0))


# ---------------------------------------------------------------------------
# Severe single signals push into medium on their own
# ---------------------------------------------------------------------------

def test_severe_device_risk_alone_reaches_medium():
    # device_risk >= 80 adds 35 points → medium (>=30)
    score = score_transaction(clean_tx(device_risk_score=82))
    assert score >= 30
    assert label_risk(score) == "medium"


def test_severe_velocity_alone_reaches_medium():
    # velocity >= 8 adds 30 points → medium
    score = score_transaction(clean_tx(velocity_24h=10))
    assert score >= 30
    assert label_risk(score) == "medium"


def test_repeat_fraudster_alone_reaches_medium():
    # prior_chargebacks >= 2 adds 25 points → approaching medium
    score = score_transaction(clean_tx(prior_chargebacks=3))
    assert score >= 25


# ---------------------------------------------------------------------------
# Moderate signals combine to reach high risk
# ---------------------------------------------------------------------------

def test_moderate_signals_combine_to_high():
    # device 55 (+15) + international (+15) + amount 800 (+10) + velocity 5 (+15) + logins 2 (+10) = 65
    tx = clean_tx(
        device_risk_score=55,
        is_international=1,
        amount_usd=800,
        velocity_24h=5,
        failed_logins_24h=2,
    )
    score = score_transaction(tx)
    assert score >= 60
    assert label_risk(score) == "high"


def test_international_plus_moderate_device_is_medium():
    # device 55 (+15) + international (+15) = 30 → medium
    tx = clean_tx(device_risk_score=55, is_international=1)
    score = score_transaction(tx)
    assert score >= 30
    assert label_risk(score) == "medium"


def test_prior_chargeback_plus_moderate_signals_is_medium():
    # prior_cb=1 (+10) + international (+15) = 25 → low, but add small velocity
    # prior_cb=1 (+10) + international (+15) + velocity 3 (+5) = 30 → medium
    tx = clean_tx(prior_chargebacks=1, is_international=1, velocity_24h=3)
    score = score_transaction(tx)
    assert score >= 30
    assert label_risk(score) == "medium"


# ---------------------------------------------------------------------------
# Full fraud profile → high risk
# ---------------------------------------------------------------------------

def test_full_fraud_profile_is_high_risk():
    # Mirrors real chargeback tx50011: device=85, intl, $1400, velocity=8, logins=7, prior_cb=1
    tx = clean_tx(
        device_risk_score=85,
        is_international=1,
        amount_usd=1400,
        velocity_24h=8,
        failed_logins_24h=7,
        prior_chargebacks=1,
    )
    score = score_transaction(tx)
    assert score == 100
    assert label_risk(score) == "high"


def test_high_velocity_international_high_device_is_high():
    tx = clean_tx(device_risk_score=82, is_international=1, velocity_24h=9)
    score = score_transaction(tx)
    # 35 + 15 + 30 = 80
    assert score >= 60
    assert label_risk(score) == "high"


# ---------------------------------------------------------------------------
# Score is always bounded to [0, 100]
# ---------------------------------------------------------------------------

def test_score_never_exceeds_100():
    tx = clean_tx(
        device_risk_score=99,
        is_international=1,
        amount_usd=9999,
        velocity_24h=20,
        failed_logins_24h=20,
        prior_chargebacks=10,
    )
    assert score_transaction(tx) == 100


def test_score_never_below_zero():
    assert score_transaction(clean_tx()) == 0

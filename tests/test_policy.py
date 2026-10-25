from phishing_guard.policy import decide

def test_legitimate_low_risk_records_only():
    d = decide({"label":"legitimate","risk_score":0.05,"confidence":"high","limitations":[]},
               auto_quarantine=True, risk_high=.85, risk_low=.30, min_confidence="high")
    assert d.action == "record_only"

def test_phishing_is_reviewed_if_auto_quarantine_disabled():
    d = decide({"label":"phishing","risk_score":.99,"confidence":"high","limitations":[]},
               auto_quarantine=False, risk_high=.85, risk_low=.30, min_confidence="high")
    assert d.action == "review"

def test_limitations_force_review():
    d = decide({"label":"phishing","risk_score":.99,"confidence":"high","limitations":["missing body"]},
               auto_quarantine=True, risk_high=.85, risk_low=.30, min_confidence="high")
    assert d.action == "review"

def test_bad_score_forces_review():
    d = decide({"label":"legitimate","risk_score":4,"confidence":"high","limitations":[]},
               auto_quarantine=True, risk_high=.85, risk_low=.30, min_confidence="high")
    assert d.action == "review"

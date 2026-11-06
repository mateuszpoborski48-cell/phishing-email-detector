
import pytest

from risk_analyser import analyse_full_email
from sender_analyser import analyse_sender
from header_analyser import analyse_headers


# ==========================================
# TEST 1 - LEGITIMATE EMAIL
# ==========================================

def test_legitimate_email():
    email = (
        "From: Reception <reception@clinic.example>\n"
        "Subject: Appointment Confirmation\n"
        "\n"
        "Your appointment is confirmed for Monday."
    )

    result = analyse_full_email(email)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"
    assert result["warnings"] == []
    assert result["warning_details"] == []


# ==========================================
# TEST 2 - MICROSOFT IMPERSONATION
# ==========================================

def test_microsoft_impersonation():
    result = analyse_sender(
        "Microsoft Security <security@micros0ft.com>"
    )

    assert result["risk_score"] >= 35
    assert result["status"] == "suspicious"
    assert any(
        "impersonation" in warning.lower()
        for warning in result["warnings"]
    )


# ==========================================
# TEST 3 - MISSING SENDER
# ==========================================

def test_missing_sender():
    result = analyse_sender("")

    assert result["risk_score"] == 0
    assert result["warnings"] == []
    assert result["status"] == "unavailable"


# ==========================================
# TEST 4 - MISSING AUTHENTICATION HEADERS
# ==========================================

def test_missing_authentication_headers():
    email = (
        "From: test@example.com\n"
        "Subject: Hello\n"
        "\n"
        "Normal message."
    )

    result = analyse_headers(email)

    assert result["risk_score"] == 0
    assert result["warnings"] == []
    assert result["status"] == "unavailable"
    assert result["trusted"] is False


# ==========================================
# TEST 5 - REPORTED AUTHENTICATION FAILURE
# ==========================================

def test_authentication_failure():
    email = (
        "Authentication-Results: mail.example; "
        "spf=fail; dkim=pass; dmarc=fail\n"
        "From: test@example.com\n"
        "\n"
        "Hello"
    )

    result = analyse_headers(email)

    assert result["risk_score"] == 50
    assert result["results"]["spf"] == "fail"
    assert result["results"]["dkim"] == "pass"
    assert result["results"]["dmarc"] == "fail"
    assert result["trusted"] is False


# ==========================================
# TEST 6 - SUSPICIOUS EMAIL
# ==========================================

def test_suspicious_email():
    email = (
        "From: Microsoft Security <security@micros0ft.com>\n"
        "Subject: Urgent Account Verification\n"
        "\n"
        "Your account will be suspended. "
        "Verify your password immediately.\n"
        "Click here: "
        "https://microsoft.com.account-review.example/login"
    )

    result = analyse_full_email(email)

    assert result["risk_level"] == "High"
    assert result["risk_score"] >= 60
    assert len(result["warnings"]) > 0


# ==========================================
# TEST 7 - WARNING EXPLANATIONS
# ==========================================

def test_warning_explanations():
    email = (
        "Subject: Account Suspended\n"
        "\n"
        "Your account will be suspended. "
        "Verify your password immediately."
    )

    result = analyse_full_email(email)

    assert len(result["warning_details"]) > 0

    for detail in result["warning_details"]:
        assert detail["warning"]
        assert detail["explanation"]
        assert detail["recommendation"]


# ==========================================
# TEST 8 - HIGH RISK RECOMMENDATION
# ==========================================

def test_high_risk_recommendation():
    email = (
        "Subject: Account Suspended\n"
        "\n"
        "Your account will be suspended. "
        "Verify your password immediately."
    )

    result = analyse_full_email(email)

    assert result["risk_level"] == "High"
    assert (
        "High Risk"
        in result["overall_recommendation"]["title"]
    )


# ==========================================
# TEST 9 - LOW RISK RECOMMENDATION
# ==========================================

def test_low_risk_recommendation():
    email = (
        "Subject: Appointment\n"
        "\n"
        "Your appointment is confirmed for Monday."
    )

    result = analyse_full_email(email)

    assert result["risk_score"] == 0
    assert result["risk_level"] == "Low"
    assert (
        "Low Risk"
        in result["overall_recommendation"]["title"]
    )


# ==========================================
# TEST 10 - SCORE LIMIT
# ==========================================

def test_risk_score_limit():
    email = (
        "From: Microsoft Security <security@micros0ft.com>\n"
        "Subject: Urgent Account Suspension\n"
        "\n"
        "Your account will be suspended immediately. "
        "Verify your password and banking details. "
        "Click here to log in:\n"
        "https://microsoft.com.account-review.example/login"
    )

    result = analyse_full_email(email)

    assert 0 <= result["risk_score"] <= 100

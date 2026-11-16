
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


def test_subtle_paypal_impersonation():
    email = """From: PayPal Support <billing@paypa1-account.example>
To: student@example.com
Subject: Payment Receipt Review

Hello,

Thank you for using PayPal.

We have prepared a summary of your recent payment activity.
Please review your transaction details.

https://paypa1-account.example/account/review

If everything looks correct, no further action is required.

Kind regards,
PayPal Customer Support
"""

    result = analyse_full_email(email)

    assert result["risk_level"] == "High"
    assert result["risk_score"] >= 60

    assert any(
        "paypal impersonation" in warning.lower()
        for warning in result["warnings"]
    )


def test_eml_with_leading_blank_lines():
    from risk_analyser import analyse_full_email

    email = b"""
From: Microsoft Security <security@micros0ft-support.example>
To: student@example.com
Subject: Account Verification Required
Content-Type: text/plain; charset=UTF-8

Please verify your account immediately.
http://micros0ft-support.example/verify-account
"""

    result = analyse_full_email(email)

    assert result["subject"] == "Account Verification Required"
    assert "micros0ft-support.example" in result["sender"]
    assert result["risk_level"] == "High"


# ==========================================
# TEST - HTML-ONLY PHISHING EMAIL
# ==========================================

def test_html_only_phishing_email():
    email = """From: Microsoft Security <security@micros0ft-support.example>
To: student@example.com
Subject: Urgent Account Verification
MIME-Version: 1.0
Content-Type: text/html; charset=UTF-8

<html>
<body>
<p>Your account will be suspended immediately.</p>
<p>Verify your password to avoid suspension.</p>
<a href="http://micros0ft-support.example/verify-account">
Verify Account
</a>
</body>
</html>
"""

    result = analyse_full_email(email)

    assert result["subject"] == "Urgent Account Verification"
    assert result["risk_level"] == "High"
    assert result["risk_score"] >= 60
    assert len(result["warnings"]) > 0
    assert any(
        "http" in warning.lower()
        for warning in result["warnings"]
    )


# ==========================================
# TEST - MALFORMED EMAIL
# ==========================================

def test_malformed_email():
    email = b"""
This is not a properly formatted email.

There is no sender or subject.
Just some random text.
"""

    result = analyse_full_email(email)

    assert result["subject"] == "Pasted Email"
    assert result["sender"] == "Not available (pasted email)"
    assert 0 <= result["risk_score"] <= 100
    assert result["risk_level"] in ("Low", "Medium", "High")
    assert isinstance(result["warnings"], list)


# ==========================================
# TEST - SUSPICIOUS EMAIL ATTACHMENT
# ==========================================

def test_suspicious_attachment():
    email = """From: Unknown <sender@example.com>
To: student@example.com
Subject: Important Document
MIME-Version: 1.0
Content-Type: multipart/mixed; boundary="testboundary"

--testboundary
Content-Type: text/plain; charset=UTF-8

Please see the attached document.

--testboundary
Content-Type: application/octet-stream
Content-Disposition: attachment; filename="invoice.exe"
Content-Transfer-Encoding: base64

dGVzdA==

--testboundary--
"""

    result = analyse_full_email(email)

    assert len(result["analysis"]["attachments"]["warnings"]) > 0
    assert any(
        "attachment" in warning.lower()
        or "executable" in warning.lower()
        or ".exe" in warning.lower()
        for warning in result["warnings"]
    )

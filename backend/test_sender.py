
import pytest
from sender_analyser import analyse_sender


@pytest.mark.parametrize(
    "sender",
    [
        "Microsoft Security <security@microsoft.com>",
        "Google Security <security@google.com>",
        "PayPal Support <support@paypal.com>",
        "John Smith <john@gmail.com>",
    ],
)
def test_legitimate_senders(sender):
    result = analyse_sender(sender)

    assert result["risk_score"] == 0
    assert result["warnings"] == []


@pytest.mark.parametrize(
    "sender",
    [
        "Microsoft Support <support@micros0ft.com>",
        "PayPal <support@paypal-security.example>",
        "PayPal Support <billing@paypa1-account.example>",
    ],
)
def test_brand_impersonation(sender):
    result = analyse_sender(sender)

    assert result["risk_score"] >= 35
    assert result["status"] == "suspicious"
    assert any(
        "impersonation" in warning.lower()
        for warning in result["warnings"]
    )


def test_missing_sender():
    result = analyse_sender("")

    assert result["risk_score"] == 0
    assert result["status"] == "unavailable"


def test_invalid_sender():
    result = analyse_sender("invalid-email")

    assert result["risk_score"] == 20
    assert result["status"] == "invalid"

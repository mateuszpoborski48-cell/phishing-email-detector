
import re

# Suspicious patterns commonly found in phishing emails.
# Each pattern has a warning message and a weight.

PHISHING_PATTERNS = [
    {
        "pattern": r"\baccount (?:will be |has been )?(?:suspended|disabled|locked)\b",
        "warning": "Threat of account suspension or locking",
        "weight": 25,
    },
    {
        "pattern": r"\b(?:verify|confirm|update)\s+(?:your\s+)?(?:password|credentials|account details)\b",
        "warning": "Request to verify sensitive account information",
        "weight": 30,
    },
    {
        "pattern": r"\b(?:urgent|immediately|within 24 hours|act now)\b",
        "warning": "Urgent or pressuring language",
        "weight": 15,
    },
    {
        "pattern": r"\b(?:banking details|credit card details|payment information)\b",
        "warning": "Reference to sensitive financial information",
        "weight": 20,
    },
    {
        "pattern": r"\b(?:click here|click the link|follow this link)\b",
        "warning": "Instruction to click a link",
        "weight": 10,
    },
]


def analyse_email_content(email_text):
    """
    Analyse email text for common phishing indicators.

    Returns a preliminary risk score and detected warnings.
    """

    if not isinstance(email_text, str):
        raise ValueError("Email content must be text.")

    warnings = []
    score = 0

    for item in PHISHING_PATTERNS:
        if re.search(
            item["pattern"],
            email_text,
            flags=re.IGNORECASE,
        ):
            warnings.append(item["warning"])
            score += item["weight"]

    score = min(score, 100)

    if score >= 60:
        risk_level = "High"
    elif score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    return {
        "risk_score": score,
        "risk_level": risk_level,
        "warnings": warnings,
        "warning_count": len(warnings),
    }

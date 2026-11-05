import re

PHISHING_PATTERNS = [
    (r"\b(?:account|profile|access|service)\b.{0,85}\b(?:suspend(?:ed|sion)?|disable(?:d)?|lock(?:ed|ing)?|terminat(?:ed|ion)|deactivat(?:ed|ion))\b|\b(?:suspend(?:ed|sion)?|disable(?:d)?|lock(?:ed|ing)?|terminat(?:ed|ion))\b.{0,85}\b(?:account|access)\b", "Threat of account suspension or locking", 25),
    (r"\b(?:verify|confirm|update|provide|enter|submit|validate|re-enter)\b.{0,90}\b(?:password|credentials|account details|personal information|identity|login details)\b|\b(?:password|credentials)\b.{0,70}\b(?:verify|confirm|restore|prevent|access)\b", "Request for sensitive account information", 35),
    (r"\b(?:urgent|immediately|act now|right away|within\s+\d+\s*(?:hours?|days?)|failure to act|last chance|final warning|as soon as possible)\b", "Urgent or pressuring language", 10),
    (r"\b(?:banking details|bank account|credit card|debit card|payment information|financial details|card number)\b", "Reference to sensitive financial information", 25),
    (r"\b(?:click here|click (?:on )?(?:the |this )?link|follow (?:this |the )?link|visit (?:the |this )?(?:link|website)|open (?:the |this )?link)\b", "Instruction to click a link", 10),
    (r"\b(?:log\s*in|login|sign\s*in)\b.{0,70}\b(?:verify|restore|secure|unlock|confirm)\b|\b(?:verify|restore|secure|unlock)\b.{0,70}\b(?:log\s*in|login|sign\s*in)\b", "Request to log in for account verification", 25),
    (r"\b(?:gift cards?|wire transfer|cryptocurrency payment|bitcoin payment|send money)\b", "Potential financial scam indicator", 25),
    (r"\b(?:you have won|claim your prize|lottery winner|congratulations.{0,35}(?:won|prize))\b", "Suspicious prize or reward claim", 25),
]


def analyse_email_content(email_text):
    if not isinstance(email_text, str):
        raise ValueError("Email content must be text.")

    warnings = []
    score = 0
    for pattern, warning, weight in PHISHING_PATTERNS:
        if re.search(pattern, email_text, flags=re.IGNORECASE | re.DOTALL):
            warnings.append(warning)
            score += weight

    score = min(score, 100)
    risk_level = "High" if score >= 60 else "Medium" if score >= 30 else "Low"
    return {
        "risk_score": score,
        "risk_level": risk_level,
        "warnings": warnings,
        "warning_count": len(warnings),
    }
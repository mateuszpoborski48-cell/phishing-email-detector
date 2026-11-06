
from email.utils import parseaddr
from difflib import SequenceMatcher


# Known company domains for basic impersonation checks
TRUSTED_BRANDS = {
    "microsoft": ["microsoft.com"],
    "google": ["google.com"],
    "paypal": ["paypal.com"],
    "amazon": ["amazon.com"],
    "apple": ["apple.com"],
}


def analyse_sender(sender):
    """
    Analyse the sender address for phishing indicators.

    Missing sender information is treated as unavailable,
    not automatically suspicious.

    Suspicious sender domains and brand impersonation
    continue to generate phishing warnings.
    """

    warnings = []
    score = 0

    # Missing sender information
    if not sender or not sender.strip():
        return {
            "risk_score": 0,
            "warnings": [],
            "status": "unavailable",
            "summary": "Sender information is unavailable.",
        }

    display_name, address = parseaddr(sender)
    address = address.lower().strip()

    # Placeholder used for pasted emails
    if address == "unknown@example.invalid":
        return {
            "risk_score": 0,
            "warnings": [],
            "status": "unavailable",
            "summary": (
                "Sender information was not provided "
                "with the pasted email."
            ),
        }

    # Validate sender address
    if (
        address.count("@") != 1
        or not address.split("@")[0]
        or not address.split("@")[1]
    ):
        return {
            "risk_score": 20,
            "warnings": ["Invalid sender email address"],
            "status": "invalid",
            "summary": "The sender email address is invalid.",
        }

    domain = address.split("@")[1]

    # Detect possible brand impersonation
    for brand, trusted_domains in TRUSTED_BRANDS.items():
        if domain in trusted_domains:
            continue

        domain_label = domain.split(".")[0]

        similarity = SequenceMatcher(
            None,
            domain_label,
            brand
        ).ratio()

        if brand in domain or similarity >= 0.75:
            warnings.append(
                f"Possible {brand.title()} impersonation: {domain}"
            )
            score += 35
            break

    # Detect misleading display names
    if display_name:
        for brand in TRUSTED_BRANDS:
            if brand in display_name.lower():
                if domain not in TRUSTED_BRANDS[brand]:
                    warning = (
                        f"Display name mentions {brand.title()}, "
                        f"but sender domain is {domain}"
                    )

                    if warning not in warnings:
                        warnings.append(warning)
                        score += 20

                    break

    if warnings:
        status = "suspicious"
        summary = (
            "The sender address contains possible "
            "impersonation indicators."
        )
    else:
        status = "no_indicators"
        summary = (
            "No suspicious sender indicators were detected. "
            "This does not verify the sender's identity."
        )

    return {
        "risk_score": min(score, 100),
        "warnings": warnings,
        "status": status,
        "summary": summary,
    }

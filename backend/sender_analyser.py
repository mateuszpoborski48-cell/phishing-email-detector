
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
    warnings = []
    score = 0

    if not sender or not sender.strip():
        return {
            "risk_score": 0,
            "warnings": ["Sender address not available"],
        }

    display_name, address = parseaddr(sender)
    address = address.lower().strip()

    if address.count("@") != 1:
        return {
            "risk_score": 20,
            "warnings": ["Invalid sender email address"],
        }

    domain = address.split("@")[1]

    for brand, trusted_domains in TRUSTED_BRANDS.items():
        if domain in trusted_domains:
            continue

        domain_label = domain.split(".")[0]

        similarity = SequenceMatcher(
            None, domain_label, brand
        ).ratio()

        if brand in domain or similarity >= 0.75:
            warnings.append(
                f"Possible {brand.title()} impersonation: {domain}"
            )
            score += 35
            break

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

    return {
        "risk_score": min(score, 100),
        "warnings": warnings,
    }

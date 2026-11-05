
import re
import ipaddress
from urllib.parse import urlsplit

SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "is.gd",
    "cutt.ly",
    "tiny.cc",
    "rebrand.ly",
    "shorturl.at",
}

LOOKALIKE_DOMAINS = {
    "micros0ft.com": "Microsoft",
    "paypa1.com": "PayPal",
    "g00gle.com": "Google",
    "arnazon.com": "Amazon",
    "app1e.com": "Apple",
    "netf1ix.com": "Netflix",
}

TRUSTED_BRANDS = {
    "microsoft.com": "Microsoft",
    "paypal.com": "PayPal",
    "google.com": "Google",
    "amazon.com": "Amazon",
    "apple.com": "Apple",
    "netflix.com": "Netflix",
}

LOGIN_KEYWORDS = {
    "login",
    "signin",
    "sign-in",
    "verify",
    "verification",
    "password",
    "account",
    "secure",
    "authenticate",
}


def analyse_urls(email_text):
    if not isinstance(email_text, str):
        raise ValueError("Email content must be text.")

    urls = re.findall(
        r"""https?://[^\s<>"']+""",
        email_text,
        flags=re.IGNORECASE,
    )

    findings = []
    warnings = []
    total_score = 0
    seen_urls = set()

    for raw_url in urls:
        url = raw_url.rstrip(".,;!?)")

        if url in seen_urls:
            continue

        seen_urls.add(url)

        try:
            parsed = urlsplit(url)
            hostname = (parsed.hostname or "").lower().rstrip(".")
        except ValueError:
            continue

        if not hostname:
            continue

        score = 0
        reasons = []

        # 1. Unencrypted HTTP
        if parsed.scheme.lower() == "http":
            score += 10
            reasons.append("Unencrypted HTTP link")

        # 2. IP address instead of domain
        try:
            ipaddress.ip_address(hostname)
            score += 30
            reasons.append("URL uses an IP address")
        except ValueError:
            pass

        # 3. URL shortening services
        if hostname in SHORTENERS:
            score += 15
            reasons.append("URL shortening service")

        # 4. Known lookalike domains
        for domain, brand in LOOKALIKE_DOMAINS.items():
            if hostname == domain or hostname.endswith("." + domain):
                score += 45
                reasons.append(
                    f"Possible {brand} impersonation"
                )
                break

        # 5. Misleading brand subdomains
        for domain, brand in TRUSTED_BRANDS.items():
            if hostname == domain or hostname.endswith("." + domain):
                continue

            if hostname.startswith(domain + "."):
                score += 45
                reasons.append(
                    f"Misleading {brand} subdomain"
                )
                break

        # 6. URL userinfo (@)
        if parsed.username is not None:
            score += 30
            reasons.append("URL contains userinfo (@)")

        # 7. Punycode / internationalised domains
        if any(
            label.startswith("xn--")
            for label in hostname.split(".")
        ):
            score += 20
            reasons.append(
                "Internationalised domain (punycode)"
            )

        # 8. Suspicious login or verification links
        path_text = (
            parsed.path + " " + parsed.query
        ).lower()

        if any(
            keyword in path_text
            for keyword in LOGIN_KEYWORDS
        ):
            score += 10
            reasons.append(
                "URL contains login or verification keywords"
            )

        score = min(score, 100)
        total_score += score

        findings.append({
            "url": url,
            "risk_score": score,
            "warnings": reasons,
        })

        warnings.extend(reasons)

    return {
        "risk_score": min(total_score, 100),
        "url_count": len(findings),
        "urls": findings,
        "warnings": list(dict.fromkeys(warnings)),
    }

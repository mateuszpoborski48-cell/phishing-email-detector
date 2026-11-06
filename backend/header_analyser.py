
import re
from email import policy
from email.parser import BytesParser


AUTHENTICATION_MECHANISMS = ("spf", "dkim", "dmarc")

VALID_STATUSES = (
    "pass",
    "fail",
    "softfail",
    "neutral",
    "none",
    "temperror",
    "permerror",
)


def analyse_headers(raw_email):
    """
    Analyse authentication information in an email.

    Authentication-Results headers are unverified claims.
    They must not be treated as trusted proof unless the
    receiving mail server is known and trusted.

    The authentication score is informational and is not
    included in the overall phishing risk calculation.
    """

    if isinstance(raw_email, str):
        raw_email = raw_email.encode("utf-8")

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_email)

    warnings = []
    results = {}
    score = 0

    auth_headers = message.get_all(
        "Authentication-Results", []
    )

    # No authentication header available
    if not auth_headers:
        return {
            "risk_score": 0,
            "results": {
                "spf": "unknown",
                "dkim": "unknown",
                "dmarc": "unknown",
            },
            "warnings": [],
            "status": "unavailable",
            "summary": (
                "Authentication information is unavailable. "
                "This does not mean the email is malicious."
            ),
            "trusted": False,
        }

    # Only inspect the first header for this prototype.
    # It is not necessarily from a trusted mail server.
    auth_text = str(auth_headers[0]).lower()

    for mechanism in AUTHENTICATION_MECHANISMS:
        match = re.search(
            rf"\b{mechanism}\s*=\s*"
            r"(pass|fail|softfail|neutral|none|temperror|permerror)\b",
            auth_text,
        )

        if not match:
            results[mechanism] = "unknown"
            continue

        status = match.group(1)
        results[mechanism] = status

        if status == "fail":
            score += 25
            warnings.append(
                f"{mechanism.upper()} reported authentication failure "
                "(unverified header)"
            )

        elif status in ("softfail", "temperror", "permerror"):
            score += 10
            warnings.append(
                f"{mechanism.upper()} reported {status} "
                "(unverified header)"
            )

    if any(value == "fail" for value in results.values()):
        overall_status = "reported_failure"
        summary = (
            "One or more authentication checks report failure. "
            "These results have not been independently verified."
        )

    elif any(
        value in ("softfail", "temperror", "permerror")
        for value in results.values()
    ):
        overall_status = "reported_issue"
        summary = (
            "One or more authentication checks report an issue. "
            "The results are unverified."
        )

    elif any(value == "pass" for value in results.values()):
        overall_status = "reported_pass"
        summary = (
            "One or more authentication checks report success. "
            "This does not guarantee the email is safe."
        )

    else:
        overall_status = "inconclusive"
        summary = (
            "Authentication results are inconclusive."
        )

    return {
        "risk_score": min(score, 100),
        "results": results,
        "warnings": warnings,
        "status": overall_status,
        "summary": summary,
        "trusted": False,
    }


import re
from email import policy
from email.parser import BytesParser


def analyse_headers(raw_email):
    """
    Analyse authentication results from an .eml file.

    These results are unverified header claims, not proof
    that the sender passed authentication.
    """
    if isinstance(raw_email, str):
        raw_email = raw_email.encode("utf-8")

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_email)

    warnings = []
    score = 0
    results = {}

    auth_headers = message.get_all(
        "Authentication-Results", []
    )

    if not auth_headers:
        return {
            "risk_score": 0,
            "results": {},
            "warnings": [
                "No Authentication-Results header found"
            ],
        }

    # Use the first reported header for this prototype.
    # Production code must identify trusted mail servers.
    auth_text = str(auth_headers[0]).lower()

    for mechanism in ("spf", "dkim", "dmarc"):
        match = re.search(
            rf"\b{mechanism}\s*=\s*"
            r"(pass|fail|softfail|neutral|none|temperror|permerror)",
            auth_text,
        )

        if match:
            status = match.group(1)
            results[mechanism] = status

            if status == "fail":
                score += 25
                warnings.append(
                    f"{mechanism.upper()} reported failure"
                )
            elif status in (
                "softfail", "temperror", "permerror"
            ):
                score += 10
                warnings.append(
                    f"{mechanism.upper()} reported {status}"
                )
        else:
            results[mechanism] = "unknown"

    return {
        "risk_score": min(score, 100),
        "results": results,
        "warnings": warnings,
    }

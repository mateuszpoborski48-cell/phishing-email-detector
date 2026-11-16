
import re
from email import policy
from email.parser import BytesParser

from phishing_detector import analyse_email_content
from sender_analyser import analyse_sender
from header_analyser import analyse_headers
from attachment_analyser import analyse_attachments
from url_analyser import analyse_urls


HEADER_PATTERN = re.compile(
    r"^(?:From|Subject|To|Date|Reply-To|Message-ID|"
    r"MIME-Version|Content-Type|Cc|Bcc):\s*",
    re.IGNORECASE,
)


def _prepare_email(raw_email):
    """Prepare pasted email text or uploaded .eml bytes."""

    if not isinstance(raw_email, (str, bytes)):
        raise ValueError("Email must be text or bytes.")

    if isinstance(raw_email, bytes):
        return raw_email.lstrip(b"\r\n")

    text = raw_email.replace("\r\n", "\n").replace("\r", "\n")
    text = text.lstrip("\n")

    lines = text.split("\n")
    header_end = 0
    found_header = False
    has_separator = False

    for i, line in enumerate(lines):
        if not line.strip():
            if found_header:
                has_separator = True
            break

        if HEADER_PATTERN.match(line):
            found_header = True
            header_end = i + 1
        elif line.startswith((" ", "\t")) and found_header:
            header_end = i + 1
        else:
            break

    if found_header and not has_separator:
        lines.insert(header_end, "")
        text = "\n".join(lines)

    if not found_header:
        text = "Subject: Pasted Email\n\n" + text

    return text.encode("utf-8")


def explain_warning(warning):
    """
    Convert a detection warning into an explanation
    and a practical safety recommendation.
    """

    text = warning.lower()

    if "impersonation" in text or "display name mentions" in text:
        explanation = (
            "The sender appears to reference a recognised company, "
            "but the email domain may not match the company's "
            "official domain. This can indicate impersonation."
        )
        recommendation = (
            "Verify the sender through the company's official "
            "website or another trusted communication channel."
        )

    elif "misleading" in text or "subdomain" in text:
        explanation = (
            "The URL may contain a familiar company name while "
            "actually belonging to a different domain."
        )
        recommendation = (
            "Do not open the link. Navigate to the company's "
            "official website independently."
        )

    elif "login" in text or "verification" in text:
        explanation = (
            "The email or link requests account verification "
            "or login activity, which attackers may use "
            "to steal credentials."
        )
        recommendation = (
            "Avoid entering passwords through email links. "
            "Open the service directly using a trusted address."
        )

    elif "attachment" in text or "executable" in text:
        explanation = (
            "The email contains an attachment that may be "
            "unsafe or capable of executing malicious content."
        )
        recommendation = (
            "Do not open unexpected attachments. "
            "Verify the file and sender before downloading."
        )

    elif "authentication" in text or any(
        item in text for item in ("spf", "dkim", "dmarc")
    ):
        explanation = (
            "The email contains an authentication-related "
            "warning. Authentication headers can be forged "
            "and have not been independently verified."
        )
        recommendation = (
            "Verify the sender through a trusted channel. "
            "Do not rely on authentication claims alone."
        )

    elif "http" in text or "insecure" in text:
        explanation = (
            "The URL may use an unencrypted connection "
            "or another potentially unsafe link format."
        )
        recommendation = (
            "Avoid submitting sensitive information through "
            "untrusted or unencrypted websites."
        )

    elif "shortened" in text or "shortener" in text:
        explanation = (
            "A shortened URL can hide the actual destination "
            "from the recipient."
        )
        recommendation = (
            "Do not open unfamiliar shortened links. "
            "Verify the destination through a trusted source."
        )

    elif "ip address" in text:
        explanation = (
            "The link uses an IP address instead of a "
            "recognisable domain name, which can be suspicious."
        )
        recommendation = (
            "Avoid opening the link unless you can independently "
            "verify the destination."
        )

    elif "urgent" in text or "pressure" in text:
        explanation = (
            "The email uses urgency or pressure to encourage "
            "the recipient to act without checking the message."
        )
        recommendation = (
            "Take time to verify the request before "
            "clicking links or sharing information."
        )

    elif "suspension" in text or "locking" in text:
        explanation = (
            "The email threatens account suspension or "
            "restriction to pressure the recipient."
        )
        recommendation = (
            "Check your account directly through the "
            "official service instead of using email links."
        )

    elif "financial" in text or "bank" in text:
        explanation = (
            "The message references sensitive financial "
            "information that could be targeted by attackers."
        )
        recommendation = (
            "Never share banking details in response to "
            "an unexpected email request."
        )

    elif "sensitive" in text or "password" in text:
        explanation = (
            "The email requests sensitive information "
            "that could be used to compromise an account."
        )
        recommendation = (
            "Do not provide passwords, verification codes "
            "or personal information through email."
        )

    elif "click" in text or "link" in text:
        explanation = (
            "The email encourages the recipient to follow "
            "a link. The destination may require verification."
        )
        recommendation = (
            "Check the destination independently before "
            "opening links from unexpected messages."
        )

    else:
        explanation = (
            "This pattern was identified by the phishing "
            "detection system as a possible risk indicator."
        )
        recommendation = (
            "Review the message carefully and verify "
            "unexpected requests independently."
        )

    return {
        "warning": warning,
        "explanation": explanation,
        "recommendation": recommendation,
    }


def get_overall_recommendation(risk_level):
    """Provide advice based on the overall phishing risk."""

    if risk_level == "High":
        return {
            "title": "High Risk - Avoid Interaction",
            "message": (
                "This email contains strong phishing indicators. "
                "Do not click links, open unexpected attachments "
                "or provide personal information. Verify the "
                "message through an official channel."
            ),
        }

    if risk_level == "Medium":
        return {
            "title": "Medium Risk - Proceed With Caution",
            "message": (
                "This email contains suspicious indicators. "
                "Verify the sender and any requests before "
                "opening links or attachments."
            ),
        }

    return {
        "title": "Low Risk - No Major Indicators Detected",
        "message": (
            "The scan found few or no phishing indicators. "
            "This does not guarantee the email is safe. "
            "Remain cautious with unexpected links, "
            "attachments and requests."
        ),
    }


def analyse_full_email(raw_email):
    """Run all phishing detection checks."""

    raw_bytes = _prepare_email(raw_email)

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_bytes)

    sender = str(message.get("From", "")).strip()
    subject = str(message.get("Subject", "")).strip()

    if not subject:
        subject = "Pasted Email"

    if not sender:
        sender = "Not available (pasted email)"

    body_part = message.get_body(
        preferencelist=("plain", "html")
    )

    if body_part:
        try:
            body = body_part.get_content()
        except (LookupError, UnicodeError, ValueError):
            body = ""
    else:
        body = ""

    if not isinstance(body, str):
        body = ""

    content = subject + "\n" + body

    content_result = analyse_email_content(content)
    sender_result = analyse_sender(
        sender if message.get("From") else ""
    )
    header_result = analyse_headers(raw_bytes)
    attachment_result = analyse_attachments(raw_bytes)
    url_result = analyse_urls(content)

    scores = sorted(
        [
            content_result["risk_score"],
            sender_result["risk_score"],
            attachment_result["risk_score"],
            url_result["risk_score"],
        ],
        reverse=True,
    )

    # Authentication results are unverified and
    # excluded from the overall phishing score.
    total_score = min(
        100,
        scores[0] + min(20, scores[1] // 2)
    )

    if total_score >= 60:
        risk_level = "High"
    elif total_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    warnings = list(
        dict.fromkeys(
            content_result["warnings"]
            + sender_result["warnings"]
            + header_result["warnings"]
            + attachment_result["warnings"]
            + url_result["warnings"]
        )
    )

    warning_details = [
        explain_warning(warning)
        for warning in warnings
    ]

    overall_recommendation = get_overall_recommendation(
        risk_level
    )

    return {
        "subject": subject,
        "sender": sender,
        "risk_score": total_score,
        "risk_level": risk_level,
        "warnings": warnings,
        "warning_details": warning_details,
        "overall_recommendation": overall_recommendation,
        "analysis": {
            "content": content_result,
            "sender": sender_result,
            "headers": header_result,
            "attachments": attachment_result,
            "urls": url_result,
        },
    }

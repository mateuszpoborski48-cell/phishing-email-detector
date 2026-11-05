
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

    # Preserve uploaded .eml files.
    if isinstance(raw_email, bytes):
        return raw_email

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

    # Insert the required blank line between
    # email headers and the message body.
    if found_header and not has_separator:
        lines.insert(header_end, "")
        text = "\n".join(lines)

    # If no email headers exist, treat the
    # entire pasted text as the email body.
    if not found_header:
        text = (
            "Subject: Pasted Email\n"
            "\n"
            + text
        )

    return text.encode("utf-8")


def analyse_full_email(raw_email):
    """Run all phishing detection checks."""

    raw_bytes = _prepare_email(raw_email)

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_bytes)

    # Extract sender and subject.
    sender = str(message.get("From", "")).strip()
    subject = str(message.get("Subject", "")).strip()

    if not subject:
        subject = "Pasted Email"

    if not sender:
        sender = "Not available (pasted email)"

    # Extract email body.
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

    # 1. Analyse email content.
    content = subject + "\n" + body
    content_result = analyse_email_content(content)

    # 2. Analyse sender.
    sender_result = analyse_sender(
        sender if message.get("From") else ""
    )

    # 3. Analyse authentication headers.
    header_result = analyse_headers(raw_bytes)

    # 4. Analyse attachments.
    attachment_result = analyse_attachments(raw_bytes)

    # 5. Analyse URLs.
    url_result = analyse_urls(content)

    # 6. Combine risk scores.
    scores = sorted(
        [
            content_result["risk_score"],
            sender_result["risk_score"],
            attachment_result["risk_score"],
            url_result["risk_score"],
        ],
        reverse=True,
    )

    # Authentication results are not independently
    # verified, so their score is excluded.
    total_score = min(
        100,
        scores[0] + min(20, scores[1] // 2)
    )

    # 7. Determine risk level.
    if total_score >= 60:
        risk_level = "High"
    elif total_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    # 8. Combine warnings without duplicates.
    warnings = list(
        dict.fromkeys(
            content_result["warnings"]
            + sender_result["warnings"]
            + header_result["warnings"]
            + attachment_result["warnings"]
            + url_result["warnings"]
        )
    )

    # 9. Return complete analysis.
    return {
        "subject": subject,
        "sender": sender,
        "risk_score": total_score,
        "risk_level": risk_level,
        "warnings": warnings,
        "analysis": {
            "content": content_result,
            "sender": sender_result,
            "headers": header_result,
            "attachments": attachment_result,
            "urls": url_result,
        },
    }

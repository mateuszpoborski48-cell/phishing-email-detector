
from email import policy
from email.parser import BytesParser

from phishing_detector import analyse_email_content
from sender_analyser import analyse_sender
from header_analyser import analyse_headers
from attachment_analyser import analyse_attachments


def analyse_full_email(raw_email):
    if isinstance(raw_email, str):
        raw_email = raw_email.encode("utf-8")

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_email)

    sender = str(message.get("From", ""))
    subject = str(message.get("Subject", ""))

    body_part = message.get_body(
        preferencelist=("plain", "html")
    )

    if body_part:
        try:
            body = body_part.get_content()
        except (LookupError, UnicodeError):
            body = ""
    else:
        body = ""

    # Run the four separate analysers
    content_result = analyse_email_content(
        subject + "\n" + body
    )
    sender_result = analyse_sender(sender)
    header_result = analyse_headers(raw_email)
    attachment_result = analyse_attachments(raw_email)

    # Preliminary weighted risk scoring
    # Each category contributes a maximum amount.
    total_score = (
        min(content_result["risk_score"], 40)
        + min(sender_result["risk_score"], 25)
        + min(header_result["risk_score"], 20)
        + min(attachment_result["risk_score"], 15)
    )

    total_score = min(total_score, 100)

    if total_score >= 60:
        risk_level = "High"
    elif total_score >= 30:
        risk_level = "Medium"
    else:
        risk_level = "Low"

    warnings = (
        content_result["warnings"]
        + sender_result["warnings"]
        + header_result["warnings"]
        + attachment_result["warnings"]
    )

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
        },
    }

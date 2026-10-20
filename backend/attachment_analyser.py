
from email import policy
from email.parser import BytesParser
from pathlib import PurePath

DANGEROUS_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1",
    ".vbs", ".js", ".jse", ".wsf", ".hta",
    ".com", ".pif", ".lnk"
}

MACRO_EXTENSIONS = {
    ".docm", ".xlsm", ".pptm"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".iso"
}


def analyse_attachments(raw_email):
    if isinstance(raw_email, str):
        raw_email = raw_email.encode("utf-8")

    message = BytesParser(
        policy=policy.default
    ).parsebytes(raw_email)

    attachments = []
    warnings = []
    score = 0

    for part in message.walk():
        if part.is_multipart():
            continue

        filename = part.get_filename()

        if not filename:
            continue

        filename = str(filename)
        extension = PurePath(filename.lower()).suffix
        attachment_risk = 0
        reasons = []

        if extension in DANGEROUS_EXTENSIONS:
            attachment_risk = 50
            reasons.append(
                "Potentially executable or script attachment"
            )

        elif extension in MACRO_EXTENSIONS:
            attachment_risk = 30
            reasons.append(
                "Office document that may contain macros"
            )

        elif extension in ARCHIVE_EXTENSIONS:
            attachment_risk = 15
            reasons.append(
                "Archive may contain additional files"
            )

        # Detect disguised executable filenames.
        parts = filename.lower().split(".")

        if (
            len(parts) >= 3
            and "." + parts[-1] in DANGEROUS_EXTENSIONS
        ):
            attachment_risk = max(
                attachment_risk, 65
            )
            reasons.append(
                "Possible double-extension disguise"
            )

        score += attachment_risk

        attachments.append({
            "filename": filename,
            "risk_score": attachment_risk,
            "warnings": reasons,
        })

        for reason in reasons:
            warnings.append(f"{filename}: {reason}")

    return {
        "risk_score": min(score, 100),
        "attachment_count": len(attachments),
        "attachments": attachments,
        "warnings": warnings,
    }

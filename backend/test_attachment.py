
from email.message import EmailMessage
from attachment_analyser import analyse_attachments


def create_test_email(filename):
    message = EmailMessage()
    message["From"] = "sender@example.com"
    message["To"] = "user@example.com"
    message["Subject"] = "Attachment Test"
    message.set_content("Please see the attached file.")

    message.add_attachment(
        b"TEST DATA ONLY",
        maintype="application",
        subtype="octet-stream",
        filename=filename,
    )

    return message.as_bytes()


test_files = [
    "invoice.pdf",
    "invoice.pdf.exe",
    "document.docm",
    "photos.zip",
    "update.ps1",
]

for filename in test_files:
    print(f"\n=== TEST: {filename} ===")
    raw_email = create_test_email(filename)
    print(analyse_attachments(raw_email))

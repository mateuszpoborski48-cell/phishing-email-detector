
from email.message import EmailMessage
from pprint import pprint

from risk_analyser import analyse_full_email


def create_email(sender, subject, body, attachment=None):
    message = EmailMessage()

    message["From"] = sender
    message["To"] = "user@example.com"
    message["Subject"] = subject

    message.set_content(body)

    if attachment:
        message.add_attachment(
            b"TEST DATA ONLY",
            maintype="application",
            subtype="octet-stream",
            filename=attachment,
        )

    return message.as_bytes()


# Test 1: Normal email
normal_email = create_email(
    "John <john@gmail.com>",
    "Meeting Reminder",
    "Hi, our meeting is tomorrow at 10 AM."
)

# Test 2: Suspicious email with attachment
phishing_email = create_email(
    "Microsoft Support <support@micros0ft.com>",
    "URGENT: Account Suspended",
    """
    Your account will be suspended within 24 hours.
    Verify your password immediately.
    Click here to restore access.
    """,
    "invoice.pdf.exe"
)


print("=== NORMAL EMAIL ===")
pprint(analyse_full_email(normal_email))

print("\n=== PHISHING EMAIL ===")
pprint(analyse_full_email(phishing_email))


from phishing_detector import analyse_email_content

test_emails = {
    "Legitimate appointment": """
        Hello, your appointment is confirmed for Friday.
        Thank you for booking with us.
    """,

    "Fake Microsoft security email": """
        URGENT! Your account will be suspended
        within 24 hours.
        Verify your password immediately.
        Click here to restore access.
    """,

    "Fake banking email": """
        Your account has been locked.
        Confirm your banking details immediately.
        Click the link to unlock your account.
    """,

    "Prize scam": """
        Congratulations! You have won a prize.
        Claim your prize immediately.
        A cryptocurrency payment is required.
    """,

    "Legitimate security notice": """
        We detected a new sign-in.
        If this was not you, open your official
        banking app to review account activity.
    """,
}

for name, email in test_emails.items():
    result = analyse_email_content(email)

    print(f"\n=== {name} ===")
    print("Score:", result["risk_score"])
    print("Risk:", result["risk_level"])
    print("Warnings:", result["warnings"])


from phishing_detector import analyse_email_content

# Example phishing email
phishing_email = """
Your account will be suspended within 24 hours.
Verify your password immediately.
Click here to prevent account suspension.
"""

# Example legitimate email
legitimate_email = """
Hello John,

Your appointment is confirmed for Thursday at 2 PM.

Kind regards,
Reception Team
"""

print("=== PHISHING EMAIL TEST ===")
print(analyse_email_content(phishing_email))

print("\n=== LEGITIMATE EMAIL TEST ===")
print(analyse_email_content(legitimate_email))

# Test 3: Legitimate security notification
security_email = """
Hello,

We detected a login to your account.

If this wasn't you, please visit your account
settings using our official application.

Thank you,
Security Team
"""

# Test 4: Suspicious banking email
banking_email = """
URGENT: Your bank account has been locked.

You must confirm your banking details immediately.
Click the link to restore access.

Failure to act may result in account suspension.
"""

print("\n=== SECURITY NOTIFICATION TEST ===")
print(analyse_email_content(security_email))

print("\n=== BANKING PHISHING TEST ===")
print(analyse_email_content(banking_email))

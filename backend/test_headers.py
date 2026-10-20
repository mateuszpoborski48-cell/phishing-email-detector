
from header_analyser import analyse_headers

# Synthetic email with authentication failures
suspicious_email = """From: security@example.com
To: user@example.com
Subject: Account Warning
Authentication-Results: mail.example.net; spf=fail smtp.mailfrom=example.com; dkim=fail header.d=example.com; dmarc=fail header.from=example.com
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Your account requires verification.
"""

# Synthetic email with passing authentication
legitimate_email = """From: support@example.com
To: user@example.com
Subject: Account Information
Authentication-Results: mail.example.net; spf=pass smtp.mailfrom=example.com; dkim=pass header.d=example.com; dmarc=pass header.from=example.com
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Thank you for contacting support.
"""

print("=== SUSPICIOUS EMAIL HEADERS ===")
print(analyse_headers(suspicious_email))

print("\n=== PASSING EMAIL HEADERS ===")
print(analyse_headers(legitimate_email))

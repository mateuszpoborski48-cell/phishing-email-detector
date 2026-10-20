
from sender_analyser import analyse_sender

senders = [
    "Microsoft Security <security@microsoft.com>",
    "Microsoft Support <support@micros0ft.com>",
    "PayPal <support@paypal-security.example>",
    "John Smith <john@gmail.com>",
    "Google Security <security@google.com>",
]

for sender in senders:
    print("\nSender:", sender)
    print(analyse_sender(sender))

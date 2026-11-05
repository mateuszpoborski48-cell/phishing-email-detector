
from url_analyser import analyse_urls

tests = {
    "Normal HTTPS": "Visit https://example.com",
    "IP address": "Visit http://192.0.2.10/login",
    "Shortener": "Visit https://bit.ly/example",
    "Microsoft lookalike": "Visit https://micros0ft.com/login",
    "Disguised destination":
        "Visit https://microsoft.com@evil.example/login",
}

for name, text in tests.items():
    result = analyse_urls(text)
    print(f"\n=== {name} ===")
    print("Score:", result["risk_score"])
    print("Warnings:", result["warnings"])

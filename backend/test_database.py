
from database import (
    save_scan,
    get_scan_history,
    get_scan_statistics,
)

# Synthetic scan result
test_result = {
    "risk_score": 90,
    "risk_level": "High",
    "warnings": [
        "Threat of account suspension",
        "Request for sensitive information",
        "Possible Microsoft impersonation",
    ],
}

print("=== SAVING TEST SCAN ===")
scan_id = save_scan(test_result)
print("Saved scan ID:", scan_id)

print("\n=== SCAN HISTORY ===")
for scan in get_scan_history():
    print(scan)

print("\n=== DATABASE STATISTICS ===")
print(get_scan_statistics())

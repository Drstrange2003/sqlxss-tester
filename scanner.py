import requests
import json

class ScanResult:
    def __init__(self, payload, vulnerable, type):
        self.payload = payload
        self.vulnerable = vulnerable
        self.type = type

def scan_url(url):
    results = []
    with open("payloads.json", "r") as f:
        payloads = json.load(f)

    for payload in payloads:
        test_url = url + payload
        try:
            response = requests.get(test_url, timeout=30)
            content = response.text.lower()

            # SQLi detection
            if any(keyword in payload.lower() for keyword in ["select", "union", "drop", "' or", "\" or", "--", "#", "="]):
                vulnerable = any(error in content for error in [
                    "sql", "syntax", "mysql", "warning", "query failed", "ora-", "unclosed", "database error"
                ])
                results.append(ScanResult(payload, vulnerable, "SQLi"))

            # XSS detection
            elif any(keyword in payload.lower() for keyword in ["<script", "onerror", "alert(", "<img", "<svg", "<iframe", "<object", "<math", "<details"]):
                vulnerable = payload.lower() in content
                results.append(ScanResult(payload, vulnerable, "XSS"))

        except Exception as e:
            print(f"Error scanning {test_url}: {e}")

    return results

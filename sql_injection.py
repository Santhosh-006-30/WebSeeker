import requests

def test_sql_injection(url):
    sql_payloads = ["'", "\"", "' OR '1'='1", "\" OR \"1\"=\"1", "' OR 'a'='a"]
    vulnerabilities = []

    for payload in sql_payloads:
        test_url = f"{url}?id={payload}"  # Simulated SQL injection test
        print(f"  🔹 Testing payload: {payload}")
        
        try:
            response = requests.get(test_url, timeout=5)

            if "error" in response.text.lower() or "sql" in response.text.lower():
                vulnerabilities.append({
                    "type": "SQL Injection",
                    "payload": payload,
                    "recommendation": "Use parameterized queries to prevent SQL injection."
                })
                print("  ❌ Vulnerability Found!")

        except requests.exceptions.RequestException:
            print("  ⚠️ Connection Error. Skipping payload.")

    return vulnerabilities

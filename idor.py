import requests

def test_idor(url):
    """
    Tests for Insecure Direct Object References (IDOR)
    by modifying numerical object IDs in the URL.
    """
    vulnerabilities = []
    test_ids = [1, 2, 999, 1000]  # Modify these based on expected ID range

    for test_id in test_ids:
        test_url = url.replace("{id}", str(test_id))  # Replace {id} in URL with test values
        try:
            response = requests.get(test_url, allow_redirects=False)
            
            # Check if the response indicates unauthorized access
            if response.status_code != 403 and response.status_code != 401:
                vulnerabilities.append({
                    "type": "Insecure Direct Object Reference (IDOR)",
                    "payload": test_url,
                    "recommendation": "Implement proper authorization checks before granting access to resources."
                })
        
        except requests.RequestException as e:
            # Handle errors in requests
            print(f"Error while testing IDOR for {test_url}: {e}")
    
    return vulnerabilities

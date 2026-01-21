import requests
import time

# Configuration for rate limiting
MAX_ATTEMPTS = 5
BLOCK_TIME = 300  # Block time in seconds (5 minutes)
LOGIN_URL = "/login"  # Modify this URL to the actual login endpoint
LOGIN_PAYLOAD = {'username': 'admin', 'password': 'incorrect'}  # Modify this payload for testing

login_attempts = {}

def test_multiple_login_attempts(url):
    """
    Tests for brute-force attacks by making multiple failed login attempts
    and checking if rate limiting or blocking is applied.
    """
    vulnerabilities = []
    
    # Loop through multiple login attempts
    for attempt in range(MAX_ATTEMPTS + 1):  # We try one extra time to trigger the block
        try:
            response = requests.post(url + LOGIN_URL, data=LOGIN_PAYLOAD)

            # Introduce a small delay to avoid hitting rate limits
            time.sleep(1)  # Adjust this delay to fit the server's tolerance

            # Log failed attempts with timestamp
            ip_address = response.request.headers.get('X-Forwarded-For', '127.0.0.1')
            if ip_address not in login_attempts:
                login_attempts[ip_address] = []

            login_attempts[ip_address].append(time.time())

            # Check if the number of attempts exceeds the limit within the block time
            attempts_in_timeframe = [t for t in login_attempts[ip_address] if time.time() - t < BLOCK_TIME]
            login_attempts[ip_address] = attempts_in_timeframe  # Clean old attempts

            if len(login_attempts[ip_address]) > MAX_ATTEMPTS:
                vulnerabilities.append({
                    "type": "Brute Force / Multiple Login Attempts",
                    "payload": f"Too many login attempts detected from IP: {ip_address}",
                    "recommendation": "Implement rate limiting and blocking mechanisms for login attempts."
                })
                break  # If a block condition is met, we stop further testing

        except requests.exceptions.RequestException as e:
            print(f"Error during attempt {attempt + 1}: {e}")
            time.sleep(3)  # Wait for 3 seconds before retrying after a connection issue

    return vulnerabilities

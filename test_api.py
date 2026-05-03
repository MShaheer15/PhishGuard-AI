import requests
import json
import time

API_URL = "http://localhost:8000"

def test_api():
    print("Waiting for server to ensure it's up...")
    time.sleep(3)
    
    # Test 1: Scan Safe HTTPS URL (Whitelisted)
    print("\n--- Test 1: Safe HTTPS URL (google.com) ---")
    payload = {"url": "https://www.google.com"}
    try:
        response = requests.post(f"{API_URL}/scan", json=payload)
        print(f"Status Code: {response.status_code}")
        data = response.json()
        print(f"  is_phishing: {data['is_phishing']}")
        print(f"  confidence: {data['confidence']}")
        print(f"  whitelisted: {data['whitelisted']}")
        if 'security_details' in data and data['security_details']:
            sec = data['security_details']
            print(f"  --- Security Details ---")
            print(f"  SSL Valid: {sec.get('ssl_valid')}")
            print(f"  SSL Issuer: {sec.get('ssl_issuer')}")
            print(f"  SSL Expires In: {sec.get('ssl_expires_in_days')} days")
            print(f"  TLS Version: {sec.get('tls_version')}")
            print(f"  Domain Match: {sec.get('ssl_domain_match')}")
            print(f"  HSTS: {sec.get('has_hsts')}")
            print(f"  CSP: {sec.get('has_csp')}")
            print(f"  X-Frame-Options: {sec.get('has_x_frame_options')}")
            print(f"  HTTP→HTTPS Redirect: {sec.get('http_to_https_redirect')}")
            print(f"  Mixed Content: {sec.get('mixed_content')}")
            print(f"  Security Headers Score: {sec.get('security_headers_score')}")
            print(f"  Original ML Score: {sec.get('original_ml_score')}")
            print(f"  Score Adjustment: {sec.get('score_adjustment')}")
            print(f"  Adjusted Score: {sec.get('adjusted_score')}")
            print(f"  Penalties: {len(sec.get('penalties', []))}")
            for p in sec.get('penalties', []):
                print(f"    - {p['description']} (+{p['weight']})")
            print(f"  Bonuses: {len(sec.get('bonuses', []))}")
            for b in sec.get('bonuses', []):
                print(f"    - {b['description']} (-{b['weight']})")
        else:
            print("  No security_details in response")
    except Exception as e:
        print(f"Request failed: {e}")

    # Test 2: Scan Suspicious URL (IP address, no HTTPS)
    print("\n--- Test 2: Suspicious URL (IP + HTTP) ---")
    payload = {"url": "http://192.168.1.1/login-account-update-security-verify"} 
    try:
        response = requests.post(f"{API_URL}/scan", json=payload)
        print(f"Status Code: {response.status_code}")
        data = response.json()
        print(f"  is_phishing: {data['is_phishing']}")
        print(f"  confidence: {data['confidence']}")
        if 'security_details' in data and data['security_details']:
            sec = data['security_details']
            print(f"  SSL Valid: {sec.get('ssl_valid')}")
            print(f"  Score Adjustment: {sec.get('score_adjustment')}")
            print(f"  Original ML Score: {sec.get('original_ml_score')}")
            print(f"  Adjusted Score: {sec.get('adjusted_score')}")
            print(f"  Penalties: {[p['description'] for p in sec.get('penalties', [])]}")
    except Exception as e:
         print(f"Request failed: {e}")

    # Test 3: Scan HTTPS site (non-whitelisted)
    print("\n--- Test 3: HTTPS Site (github.com) ---")
    payload = {"url": "https://github.com"}
    try:
        response = requests.post(f"{API_URL}/scan", json=payload)
        print(f"Status Code: {response.status_code}")
        data = response.json()
        print(f"  is_phishing: {data['is_phishing']}")
        print(f"  confidence: {data['confidence']}")
        if 'security_details' in data and data['security_details']:
            sec = data['security_details']
            print(f"  SSL Valid: {sec.get('ssl_valid')}")
            print(f"  TLS Version: {sec.get('tls_version')}")
            print(f"  HSTS: {sec.get('has_hsts')}")
            print(f"  Score Adjustment: {sec.get('score_adjustment')}")
    except Exception as e:
        print(f"Request failed: {e}")

    # Test 4: History endpoint
    print("\n--- Test 4: History ---")
    try:
        response = requests.get(f"{API_URL}/history")
        print(f"Status Code: {response.status_code}")
        data = response.json()
        print(f"  Entries: {len(data)}")
    except Exception as e:
         print(f"Request failed: {e}")

    # Test 5: Stats endpoint
    print("\n--- Test 5: Stats ---")
    try:
        response = requests.get(f"{API_URL}/stats")
        print(f"Status Code: {response.status_code}")
        print(json.dumps(response.json(), indent=2))
    except Exception as e:
         print(f"Request failed: {e}")

if __name__ == "__main__":
    test_api()

"""
Website Existence Checker Module for PhishGuard AI
Performs DNS resolution and HTTP reachability checks to determine
whether a website actually exists and is accessible.
"""

import socket
import time
import requests
from urllib.parse import urlparse


# Standard browser-like headers
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
}


def check_website_exists(url: str, dns_timeout: float = 5.0, http_timeout: float = 8.0) -> dict:
    """
    Check whether a website exists and is reachable.

    Performs two checks:
        1. DNS Resolution — does the domain resolve to an IP address?
        2. HTTP Reachability — can we reach the server and get a response?

    Args:
        url: The URL to check (with or without scheme).
        dns_timeout: Timeout in seconds for DNS resolution.
        http_timeout: Timeout in seconds for the HTTP request.

    Returns:
        dict with:
            - exists: True if domain resolves AND server responds (any HTTP status)
            - dns_resolves: True if domain resolves to at least one IP
            - is_reachable: True if HTTP request got a response (any status code)
            - status_code: HTTP status code (0 if unreachable)
            - response_time_ms: Round-trip time in milliseconds (-1 if failed)
            - ip_address: Resolved IP address (or None)
            - error: Error message if check failed, else None
    """
    result = {
        'exists': False,
        'dns_resolves': False,
        'is_reachable': False,
        'status_code': 0,
        'response_time_ms': -1,
        'ip_address': None,
        'error': None,
    }

    # --- Normalize URL ---
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url

    try:
        parsed = urlparse(url)
        hostname = parsed.hostname
    except Exception:
        result['error'] = 'Invalid URL format'
        return result

    if not hostname:
        result['error'] = 'No hostname found in URL'
        return result

    # --- Step 1: DNS Resolution ---
    try:
        old_timeout = socket.getdefaulttimeout()
        socket.setdefaulttimeout(dns_timeout)
        try:
            addr_info = socket.getaddrinfo(hostname, None)
            if addr_info:
                result['dns_resolves'] = True
                # Get the first resolved IP
                result['ip_address'] = addr_info[0][4][0]
        finally:
            socket.setdefaulttimeout(old_timeout)
    except socket.gaierror:
        result['error'] = f'DNS resolution failed — domain "{hostname}" does not exist'
        return result
    except socket.timeout:
        result['error'] = f'DNS resolution timed out for "{hostname}"'
        return result
    except Exception as e:
        result['error'] = f'DNS check error: {str(e)}'
        return result

    # --- Step 2: HTTP Reachability ---
    try:
        start_time = time.time()

        # Try HEAD first (lightweight), fallback to GET
        try:
            response = requests.head(
                url,
                timeout=http_timeout,
                headers=REQUEST_HEADERS,
                allow_redirects=True,
                verify=False,  # Don't fail on SSL issues — we just want to check existence
            )
        except (requests.exceptions.ConnectionError, requests.exceptions.Timeout):
            # Some servers block HEAD, try GET
            response = requests.get(
                url,
                timeout=http_timeout,
                headers=REQUEST_HEADERS,
                allow_redirects=True,
                verify=False,
                stream=True,  # Don't download body
            )

        elapsed_ms = round((time.time() - start_time) * 1000, 1)

        result['is_reachable'] = True
        result['status_code'] = response.status_code
        result['response_time_ms'] = elapsed_ms
        result['exists'] = True

    except requests.exceptions.ConnectionError:
        result['error'] = 'Connection refused — server is not responding'
    except requests.exceptions.Timeout:
        result['error'] = f'HTTP request timed out after {http_timeout}s'
    except requests.exceptions.TooManyRedirects:
        result['error'] = 'Too many redirects — possible redirect loop'
    except requests.exceptions.SSLError:
        # SSL error but server exists
        result['is_reachable'] = True
        result['exists'] = True
        result['error'] = 'SSL certificate error (site exists but has cert issues)'
    except Exception as e:
        result['error'] = f'HTTP check error: {str(e)}'

    return result

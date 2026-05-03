"""
SSL/TLS Certificate Security Checker Module
Performs real-time SSL/TLS certificate validation for phishing detection.
Uses Python's ssl and socket stdlib — no external dependencies needed.
"""

import ssl
import socket
from datetime import datetime, timezone
from urllib.parse import urlparse


def check_ssl(hostname, port=443, timeout=5):
    """
    Perform SSL/TLS certificate validation on a hostname.
    
    Returns a dict with:
        - has_ssl: Whether the site has an SSL/TLS certificate
        - is_valid: Whether the certificate is currently valid
        - issuer: Certificate issuer organization
        - subject: Certificate subject (domain it's issued for)
        - expires_in_days: Days until expiry (negative if expired)
        - is_self_signed: Whether the cert is self-signed
        - domain_match: Whether the cert domain matches the hostname
        - cert_age_days: How old the certificate is
        - protocol_version: Negotiated TLS version string
        - tls_version_num: Encoded TLS version (1.3→3, 1.2→2, 1.1→1, 1.0→0, SSL→-1)
        - error: Error message if check failed, else None
    """
    result = _default_result()

    # Clean hostname
    hostname = _clean_hostname(hostname)
    if not hostname:
        result['error'] = 'Invalid hostname'
        return result

    # --- Step 1: Try to get certificate WITH validation ---
    cert_data = None
    protocol_version = None
    valid_cert = False

    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, port), timeout=timeout) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert_data = ssock.getpeercert()
                protocol_version = ssock.version()
                valid_cert = True
    except ssl.SSLCertVerificationError:
        # Certificate exists but failed validation — try without verification
        valid_cert = False
    except ssl.SSLError:
        valid_cert = False
    except (socket.timeout, socket.gaierror, ConnectionRefusedError, OSError):
        # No SSL at all or host unreachable
        result['error'] = 'Connection failed or no SSL'
        return result

    # --- Step 2: If validation failed, get cert without verification ---
    if cert_data is None:
        try:
            context = ssl._create_unverified_context()
            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert_data = ssock.getpeercert(binary_form=False)
                    protocol_version = ssock.version()
                    # If getpeercert() returns empty dict, try binary
                    if not cert_data:
                        cert_der = ssock.getpeercert(binary_form=True)
                        if cert_der:
                            result['has_ssl'] = True
                            result['is_valid'] = False
                            result['is_self_signed'] = True  # Likely self-signed
                            result['protocol_version'] = protocol_version or 'Unknown'
                            result['tls_version_num'] = _encode_tls_version(protocol_version)
                            return result
        except Exception:
            result['error'] = 'SSL certificate retrieval failed'
            return result

    if not cert_data:
        result['error'] = 'No certificate data available'
        return result

    # --- Step 3: Parse certificate data ---
    result['has_ssl'] = True
    result['is_valid'] = valid_cert

    # Issuer
    issuer_dict = _parse_cert_field(cert_data.get('issuer', ()))
    result['issuer'] = issuer_dict.get('organizationName', issuer_dict.get('commonName', 'Unknown'))

    # Subject
    subject_dict = _parse_cert_field(cert_data.get('subject', ()))
    result['subject'] = subject_dict.get('commonName', 'Unknown')

    # Self-signed check: issuer == subject
    issuer_cn = issuer_dict.get('commonName', '')
    subject_cn = subject_dict.get('commonName', '')
    issuer_org = issuer_dict.get('organizationName', '')
    subject_org = subject_dict.get('organizationName', '')
    result['is_self_signed'] = (issuer_cn == subject_cn and issuer_org == subject_org and issuer_cn != '')

    # Expiry
    not_after = cert_data.get('notAfter')
    not_before = cert_data.get('notBefore')
    now = datetime.now(timezone.utc)

    if not_after:
        try:
            expiry = _parse_cert_date(not_after)
            result['expires_in_days'] = (expiry - now).days
        except Exception:
            result['expires_in_days'] = -999

    if not_before:
        try:
            issued = _parse_cert_date(not_before)
            result['cert_age_days'] = (now - issued).days
        except Exception:
            result['cert_age_days'] = 0

    # Domain match
    san = cert_data.get('subjectAltName', ())
    cert_domains = [entry[1] for entry in san if entry[0] == 'DNS']
    if not cert_domains:
        cert_domains = [subject_cn]
    
    result['domain_match'] = _check_domain_match(hostname, cert_domains)

    # Protocol version
    result['protocol_version'] = protocol_version or 'Unknown'
    result['tls_version_num'] = _encode_tls_version(protocol_version)

    return result


def check_security_headers(response_headers):
    """
    Analyze HTTP response headers for security indicators.
    
    Args:
        response_headers: dict-like object of HTTP response headers
        
    Returns dict with:
        - has_hsts: Strict-Transport-Security present
        - has_csp: Content-Security-Policy present
        - has_x_frame_options: X-Frame-Options present
        - has_x_content_type_options: X-Content-Type-Options present
        - has_x_xss_protection: X-XSS-Protection present
        - security_headers_score: Count of security headers present (0-5)
    """
    headers = {k.lower(): v for k, v in response_headers.items()} if response_headers else {}

    has_hsts = 'strict-transport-security' in headers
    has_csp = 'content-security-policy' in headers
    has_xfo = 'x-frame-options' in headers
    has_xcto = 'x-content-type-options' in headers
    has_xxss = 'x-xss-protection' in headers

    score = sum([has_hsts, has_csp, has_xfo, has_xcto, has_xxss])

    return {
        'has_hsts': has_hsts,
        'has_csp': has_csp,
        'has_x_frame_options': has_xfo,
        'has_x_content_type_options': has_xcto,
        'has_x_xss_protection': has_xxss,
        'security_headers_score': score,
    }


def check_http_to_https_redirect(url, timeout=5):
    """
    Check if the HTTP version of a URL redirects to HTTPS.
    
    Returns:
        - redirects_to_https: True if HTTP redirects to HTTPS
        - redirect_chain_length: Number of redirects
    """
    import requests

    result = {'redirects_to_https': False, 'redirect_chain_length': 0}

    try:
        parsed = urlparse(url)
        http_url = f"http://{parsed.hostname}{parsed.path or '/'}"

        resp = requests.get(http_url, timeout=timeout, allow_redirects=True, verify=False,
                            headers={'User-Agent': 'Mozilla/5.0'})
        result['redirect_chain_length'] = len(resp.history)

        if resp.url.startswith('https://'):
            result['redirects_to_https'] = True

    except Exception:
        pass

    return result


def detect_mixed_content(soup, page_url):
    """
    Detect if an HTTPS page loads resources over HTTP (mixed content).
    
    Args:
        soup: BeautifulSoup parsed page
        page_url: The URL of the page
        
    Returns:
        - has_mixed_content: True if mixed content found
        - mixed_content_count: Number of HTTP resources on HTTPS page
    """
    result = {'has_mixed_content': False, 'mixed_content_count': 0}

    parsed = urlparse(page_url)
    if parsed.scheme != 'https':
        return result  # Only relevant for HTTPS pages

    http_resources = 0
    resource_tags = [
        ('img', 'src'), ('script', 'src'), ('link', 'href'),
        ('iframe', 'src'), ('embed', 'src'), ('object', 'data'),
        ('video', 'src'), ('audio', 'src'), ('source', 'src'),
    ]

    for tag_name, attr in resource_tags:
        for tag in soup.find_all(tag_name):
            val = tag.get(attr, '')
            if val.startswith('http://'):
                http_resources += 1

    if http_resources > 0:
        result['has_mixed_content'] = True
        result['mixed_content_count'] = http_resources

    return result


# ─── Internal Helpers ────────────────────────────────────────────────

def _default_result():
    return {
        'has_ssl': False,
        'is_valid': False,
        'issuer': 'N/A',
        'subject': 'N/A',
        'expires_in_days': -1,
        'is_self_signed': False,
        'domain_match': False,
        'cert_age_days': 0,
        'protocol_version': 'None',
        'tls_version_num': -1,
        'error': None,
    }


def _clean_hostname(hostname):
    """Extract clean hostname from various input formats."""
    if not hostname:
        return None
    hostname = hostname.strip()
    if '://' in hostname:
        hostname = urlparse(hostname).hostname
    if hostname and hostname.startswith('www.'):
        pass  # Keep www. for SSL check — cert must match
    return hostname


def _parse_cert_field(field_tuple):
    """Parse SSL certificate field (issuer/subject) into a flat dict."""
    result = {}
    for entry in field_tuple:
        for key, value in entry:
            result[key] = value
    return result


def _parse_cert_date(date_str):
    """Parse SSL certificate date string to datetime."""
    # OpenSSL format: 'Mar  1 12:00:00 2025 GMT'
    for fmt in ('%b %d %H:%M:%S %Y %Z', '%b  %d %H:%M:%S %Y %Z'):
        try:
            dt = datetime.strptime(date_str, fmt)
            return dt.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    raise ValueError(f"Cannot parse date: {date_str}")


def _check_domain_match(hostname, cert_domains):
    """Check if hostname matches any certificate domain (including wildcards)."""
    hostname = hostname.lower()
    for cert_domain in cert_domains:
        cert_domain = cert_domain.lower()
        if cert_domain == hostname:
            return True
        # Wildcard matching: *.example.com matches sub.example.com
        if cert_domain.startswith('*.'):
            wildcard_base = cert_domain[2:]  # Remove *.
            if hostname.endswith(wildcard_base):
                # Ensure only one level of subdomain matches
                prefix = hostname[:-len(wildcard_base)].rstrip('.')
                if '.' not in prefix:
                    return True
    return False


def _encode_tls_version(version_str):
    """Encode TLS version string to numeric value."""
    if not version_str:
        return -1
    version_str = version_str.upper()
    if 'TLSV1.3' in version_str or 'TLS1.3' in version_str:
        return 3
    elif 'TLSV1.2' in version_str or 'TLS1.2' in version_str:
        return 2
    elif 'TLSV1.1' in version_str or 'TLS1.1' in version_str:
        return 1
    elif 'TLSV1' in version_str or 'TLS1.0' in version_str or 'TLS1' in version_str:
        return 0
    elif 'SSL' in version_str:
        return -1
    return -1

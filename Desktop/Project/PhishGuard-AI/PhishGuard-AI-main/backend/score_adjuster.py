"""
Score Adjustment Module for PhishGuard AI
Adjusts ML model confidence based on SSL/TLS and protocol security signals.

Final Score = ML_Score + penalties - bonuses, clamped to [0.0, 1.0]
"""


# ─── Penalty Rules (increase phishing probability) ───────────────────

PENALTIES = {
    'no_ssl': {
        'weight': 0.15,
        'description': 'No SSL certificate detected',
    },
    'self_signed': {
        'weight': 0.12,
        'description': 'Self-signed certificate',
    },
    'expired_cert': {
        'weight': 0.10,
        'description': 'Expired SSL certificate',
    },
    'domain_mismatch': {
        'weight': 0.15,
        'description': 'Certificate domain does not match hostname',
    },
    'no_hsts': {
        'weight': 0.03,
        'description': 'Missing HSTS header',
    },
    'mixed_content': {
        'weight': 0.05,
        'description': 'HTTPS page loads HTTP resources',
    },
    'deprecated_tls': {
        'weight': 0.08,
        'description': 'Deprecated TLS version (≤1.1)',
    },
    'new_cert_suspicious': {
        'weight': 0.05,
        'description': 'Certificate issued very recently on suspicious domain',
    },
    'expiring_soon': {
        'weight': 0.03,
        'description': 'Certificate expiring within 30 days',
    },
}

# ─── Bonus Rules (decrease phishing probability) ─────────────────────

BONUSES = {
    'valid_ssl_trusted': {
        'weight': 0.05,
        'description': 'Valid SSL certificate from trusted issuer',
    },
    'full_security_headers': {
        'weight': 0.05,
        'description': 'All security headers present (HSTS + CSP + X-Frame-Options)',
    },
    'tls_1_3': {
        'weight': 0.02,
        'description': 'Using TLS 1.3 (latest protocol)',
    },
    'http_to_https_redirect': {
        'weight': 0.02,
        'description': 'HTTP redirects to HTTPS',
    },
}

# Trusted certificate issuers (large CAs that phishing sites rarely use for long)
TRUSTED_ISSUERS = {
    "let's encrypt", "digicert", "comodo", "sectigo", "globalsign",
    "godaddy", "entrust", "geotrust", "thawte", "verisign",
    "amazon", "google trust services", "microsoft", "cloudflare",
    "apple", "baltimore", "usertrust", "isrg root",
}


def adjust_score(ml_score, ssl_info, security_headers, redirect_info, mixed_content_info, is_whitelisted=False):
    """
    Adjust the ML model's phishing confidence score based on security signals.
    
    Args:
        ml_score: float — Raw ML model phishing probability [0.0, 1.0]
        ssl_info: dict — Output from ssl_checker.check_ssl()
        security_headers: dict — Output from ssl_checker.check_security_headers()
        redirect_info: dict — Output from ssl_checker.check_http_to_https_redirect()
        mixed_content_info: dict — Output from ssl_checker.detect_mixed_content()
        is_whitelisted: bool — Whether the domain is whitelisted
        
    Returns:
        dict with:
            - adjusted_score: Final adjusted phishing probability
            - original_ml_score: The original ML score
            - total_adjustment: Net adjustment applied
            - penalties_applied: List of penalty dicts with name, weight, description
            - bonuses_applied: List of bonus dicts with name, weight, description
    """
    if is_whitelisted:
        return {
            'adjusted_score': 0.0,
            'original_ml_score': ml_score,
            'total_adjustment': 0.0,
            'penalties_applied': [],
            'bonuses_applied': [],
        }

    penalties_applied = []
    bonuses_applied = []

    # ─── Evaluate Penalties ───────────────────────────────────────

    # No SSL certificate
    if not ssl_info.get('has_ssl', False):
        penalties_applied.append({
            'name': 'no_ssl',
            'weight': PENALTIES['no_ssl']['weight'],
            'description': PENALTIES['no_ssl']['description'],
        })

    # Self-signed certificate
    if ssl_info.get('is_self_signed', False) and ssl_info.get('has_ssl', False):
        penalties_applied.append({
            'name': 'self_signed',
            'weight': PENALTIES['self_signed']['weight'],
            'description': PENALTIES['self_signed']['description'],
        })

    # Expired certificate
    expires_in = ssl_info.get('expires_in_days', -1)
    if ssl_info.get('has_ssl', False) and expires_in < 0:
        penalties_applied.append({
            'name': 'expired_cert',
            'weight': PENALTIES['expired_cert']['weight'],
            'description': PENALTIES['expired_cert']['description'],
        })

    # Certificate domain mismatch
    if ssl_info.get('has_ssl', False) and not ssl_info.get('domain_match', True):
        penalties_applied.append({
            'name': 'domain_mismatch',
            'weight': PENALTIES['domain_mismatch']['weight'],
            'description': PENALTIES['domain_mismatch']['description'],
        })

    # No HSTS header
    if not security_headers.get('has_hsts', False):
        penalties_applied.append({
            'name': 'no_hsts',
            'weight': PENALTIES['no_hsts']['weight'],
            'description': PENALTIES['no_hsts']['description'],
        })

    # Mixed content
    if mixed_content_info.get('has_mixed_content', False):
        penalties_applied.append({
            'name': 'mixed_content',
            'weight': PENALTIES['mixed_content']['weight'],
            'description': PENALTIES['mixed_content']['description'],
        })

    # Deprecated TLS version
    tls_num = ssl_info.get('tls_version_num', -1)
    if ssl_info.get('has_ssl', False) and tls_num <= 1:
        penalties_applied.append({
            'name': 'deprecated_tls',
            'weight': PENALTIES['deprecated_tls']['weight'],
            'description': PENALTIES['deprecated_tls']['description'],
        })

    # New certificate on suspicious domain (cert < 30 days old + ML already suspicious)
    cert_age = ssl_info.get('cert_age_days', 0)
    if ssl_info.get('has_ssl', False) and cert_age < 30 and ml_score > 0.3:
        penalties_applied.append({
            'name': 'new_cert_suspicious',
            'weight': PENALTIES['new_cert_suspicious']['weight'],
            'description': PENALTIES['new_cert_suspicious']['description'],
        })

    # Certificate expiring soon (within 30 days)
    if ssl_info.get('has_ssl', False) and 0 < expires_in <= 30:
        penalties_applied.append({
            'name': 'expiring_soon',
            'weight': PENALTIES['expiring_soon']['weight'],
            'description': PENALTIES['expiring_soon']['description'],
        })

    # ─── Evaluate Bonuses ─────────────────────────────────────────

    # Valid SSL from trusted issuer
    if ssl_info.get('is_valid', False) and ssl_info.get('has_ssl', False):
        issuer = ssl_info.get('issuer', '').lower()
        if any(trusted in issuer for trusted in TRUSTED_ISSUERS):
            bonuses_applied.append({
                'name': 'valid_ssl_trusted',
                'weight': BONUSES['valid_ssl_trusted']['weight'],
                'description': BONUSES['valid_ssl_trusted']['description'],
            })

    # Full security headers (HSTS + CSP + X-Frame-Options)
    if (security_headers.get('has_hsts', False) and 
        security_headers.get('has_csp', False) and 
        security_headers.get('has_x_frame_options', False)):
        bonuses_applied.append({
            'name': 'full_security_headers',
            'weight': BONUSES['full_security_headers']['weight'],
            'description': BONUSES['full_security_headers']['description'],
        })

    # TLS 1.3
    if ssl_info.get('has_ssl', False) and tls_num >= 3:
        bonuses_applied.append({
            'name': 'tls_1_3',
            'weight': BONUSES['tls_1_3']['weight'],
            'description': BONUSES['tls_1_3']['description'],
        })

    # HTTP to HTTPS redirect
    if redirect_info.get('redirects_to_https', False):
        bonuses_applied.append({
            'name': 'http_to_https_redirect',
            'weight': BONUSES['http_to_https_redirect']['weight'],
            'description': BONUSES['http_to_https_redirect']['description'],
        })

    # ─── Calculate Final Score ────────────────────────────────────

    total_penalty = sum(p['weight'] for p in penalties_applied)
    total_bonus = sum(b['weight'] for b in bonuses_applied)
    total_adjustment = total_penalty - total_bonus

    adjusted_score = max(0.0, min(1.0, ml_score + total_adjustment))

    return {
        'adjusted_score': round(adjusted_score, 4),
        'original_ml_score': round(ml_score, 4),
        'total_adjustment': round(total_adjustment, 4),
        'penalties_applied': penalties_applied,
        'bonuses_applied': bonuses_applied,
    }

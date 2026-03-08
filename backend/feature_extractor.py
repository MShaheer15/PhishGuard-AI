import re
import math
import socket
import requests
from urllib.parse import urlparse
from bs4 import BeautifulSoup
import tldextract
import ipaddress

from ssl_checker import check_ssl, check_security_headers, check_http_to_https_redirect, detect_mixed_content

# Known brand names for embedded brand detection
BRAND_NAMES = {
    'paypal', 'apple', 'google', 'microsoft', 'amazon', 'facebook', 'instagram',
    'netflix', 'linkedin', 'twitter', 'chase', 'wellsfargo', 'bankofamerica',
    'citibank', 'ebay', 'dropbox', 'adobe', 'yahoo', 'outlook', 'icloud',
    'spotify', 'walmart', 'target', 'costco', 'bestbuy', 'samsung', 'whatsapp',
    'telegram', 'discord', 'snapchat', 'tiktok', 'uber', 'airbnb', 'booking',
    'coinbase', 'binance', 'robinhood', 'venmo', 'stripe', 'square',
}

# Standard headers to avoid being blocked
REQUEST_HEADERS = {
    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 '
                  '(KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
    'Accept-Language': 'en-US,en;q=0.5',
}


class FeatureExtractor:
    def __init__(self):
        self.features = {
            'NumDots': 0, 'SubdomainLevel': 0, 'PathLevel': 0, 'UrlLength': 0, 'NumDash': 0,
            'NumDashInHostname': 0, 'AtSymbol': 0, 'TildeSymbol': 0, 'NumUnderscore': 0, 'NumPercent': 0,
            'NumQueryComponents': 0, 'NumAmpersand': 0, 'NumHash': 0, 'NumNumericChars': 0, 'NoHttps': 0,
            'RandomString': 0, 'IpAddress': 0, 'DomainInSubdomains': 0, 'DomainInPaths': 0, 'HttpsInHostname': 0,
            'HostnameLength': 0, 'PathLength': 0, 'QueryLength': 0, 'DoubleSlashInPath': 0, 'NumSensitiveWords': 0,
            'EmbeddedBrandName': 0, 'PctExtHyperlinks': 0.0, 'PctExtResourceUrls': 0.0, 'ExtFavicon': 0,
            'InsecureForms': 0, 'RelativeFormAction': 0, 'ExtFormAction': 0, 'AbnormalFormAction': 0,
            'PctNullSelfRedirectHyperlinks': 0.0, 'FrequentDomainNameMismatch': 0, 'FakeLinkInStatusBar': 0,
            'RightClickDisabled': 0, 'PopUpWindow': 0, 'SubmitInfoToEmail': 0, 'IframeOrFrame': 0,
            'MissingTitle': 0, 'ImagesOnlyInForm': 0, 'SubdomainLevelRT': 0, 'UrlLengthRT': 0,
            'PctExtResourceUrlsRT': 0, 'AbnormalExtFormActionR': 0, 'ExtMetaScriptLinkRT': 0,
            'PctExtNullSelfRedirectHyperlinksRT': 0,
            # --- SSL/TLS & Protocol Security Features ---
            'SSLValid': 0, 'SSLSelfSigned': 0, 'SSLExpiringSoon': 0, 'SSLExpired': 0,
            'SSLDomainMismatch': 0, 'SSLCertAgeDays': 0, 'HasHSTS': 0, 'HasCSP': 0,
            'HasXFrameOptions': 0, 'HttpToHttpsRedirect': 0, 'MixedContent': 0,
            'TLSVersion': -1, 'SecurityHeadersScore': 0,
        }
        # Store last scan's security details for API consumption
        self.last_ssl_info = {}
        self.last_security_headers = {}
        self.last_redirect_info = {}
        self.last_mixed_content_info = {}

    def extract(self, url):
        self._reset_features()
        self.last_ssl_info = {}
        self.last_security_headers = {}
        self.last_redirect_info = {}
        self.last_mixed_content_info = {}
        
        # Ensure URL schema
        if not url.startswith(('http://', 'https://')):
            url = 'http://' + url

        try:
            parsed_url = urlparse(url)
            ext = tldextract.extract(url)
            domain = f"{ext.domain}.{ext.suffix}"
            hostname = parsed_url.hostname or ""
            path = parsed_url.path
            query = parsed_url.query
            
            # --- URL Structure Features ---
            self.features['UrlLength'] = len(url)
            self.features['NumDots'] = url.count('.')
            self.features['NumDash'] = url.count('-')
            self.features['NumDashInHostname'] = hostname.count('-')
            self.features['AtSymbol'] = url.count('@')
            self.features['TildeSymbol'] = url.count('~')
            self.features['NumUnderscore'] = url.count('_')
            self.features['NumPercent'] = url.count('%')
            self.features['NumQueryComponents'] = len(query.split('&')) if query else 0
            self.features['NumAmpersand'] = url.count('&')
            self.features['NumHash'] = url.count('#')
            self.features['NumNumericChars'] = sum(c.isdigit() for c in url)
            self.features['NoHttps'] = 0 if parsed_url.scheme == 'https' else 1
            
            # Subdomain/Path Level
            self.features['SubdomainLevel'] = len(ext.subdomain.split('.')) if ext.subdomain else 0
            self.features['PathLevel'] = len(path.split('/')) - 1 if path != '/' else 0
            
            # IP Address Check
            try:
                ipaddress.ip_address(hostname)
                self.features['IpAddress'] = 1
            except ValueError:
                self.features['IpAddress'] = 0

            self.features['HostnameLength'] = len(hostname)
            self.features['PathLength'] = len(path)
            self.features['QueryLength'] = len(query)
            self.features['DoubleSlashInPath'] = 1 if '//' in path else 0
            self.features['HttpsInHostname'] = 1 if 'https' in hostname else 0
            
            # --- RandomString Detection (entropy-based) ---
            self.features['RandomString'] = self._detect_random_string(hostname)
            
            # --- EmbeddedBrandName Detection ---
            self.features['EmbeddedBrandName'] = self._detect_embedded_brand(ext, hostname, path)
            
            # --- DomainInSubdomains / DomainInPaths ---
            self.features['DomainInSubdomains'] = self._detect_domain_in_subdomains(ext)
            self.features['DomainInPaths'] = self._detect_domain_in_paths(path)
            
            # --- SSL/TLS Certificate Check ---
            try:
                ssl_info = check_ssl(hostname)
            except Exception:
                ssl_info = {'has_ssl': False, 'is_valid': False, 'is_self_signed': False,
                            'domain_match': False, 'expires_in_days': -1, 'cert_age_days': 0,
                            'tls_version_num': -1, 'protocol_version': 'None', 'issuer': 'N/A',
                            'subject': 'N/A', 'error': 'Check failed'}
            self.last_ssl_info = ssl_info

            self.features['SSLValid'] = 1 if ssl_info.get('is_valid', False) else 0
            self.features['SSLSelfSigned'] = 1 if ssl_info.get('is_self_signed', False) else 0
            self.features['SSLDomainMismatch'] = 1 if (ssl_info.get('has_ssl', False) and not ssl_info.get('domain_match', True)) else 0
            self.features['SSLCertAgeDays'] = ssl_info.get('cert_age_days', 0)
            self.features['TLSVersion'] = ssl_info.get('tls_version_num', -1)

            expires_in = ssl_info.get('expires_in_days', -1)
            if ssl_info.get('has_ssl', False):
                self.features['SSLExpired'] = 1 if expires_in < 0 else 0
                self.features['SSLExpiringSoon'] = 1 if 0 < expires_in <= 30 else 0

            # --- HTTP to HTTPS Redirect Check ---
            try:
                redirect_info = check_http_to_https_redirect(url)
            except Exception:
                redirect_info = {'redirects_to_https': False, 'redirect_chain_length': 0}
            self.last_redirect_info = redirect_info
            self.features['HttpToHttpsRedirect'] = 1 if redirect_info.get('redirects_to_https', False) else 0

            # --- Content Based Features (Fetching) ---
            try:
                # Try with certificate verification first, fallback to unverified
                try:
                    response = requests.get(url, timeout=5, headers=REQUEST_HEADERS,
                                             allow_redirects=True, verify=True)
                except requests.exceptions.SSLError:
                    response = requests.get(url, timeout=5, headers=REQUEST_HEADERS,
                                             allow_redirects=True, verify=False)
                soup = BeautifulSoup(response.content, 'html.parser')
                
                # Title
                self.features['MissingTitle'] = 0 if soup.title and soup.title.string else 1
                
                # Forms
                forms = soup.find_all('form')
                for form in forms:
                    action = form.get('action', '').lower()
                    if not action or action == "" or action == "about:blank":
                        self.features['AbnormalFormAction'] = 1
                    elif not action.startswith(('http', '//')):
                        self.features['RelativeFormAction'] = 1
                    elif domain not in action:
                         self.features['ExtFormAction'] = 1
                         
                    if action.startswith('http') and 'https' not in action:
                        self.features['InsecureForms'] = 1
                    
                    # SubmitInfoToEmail — detect mailto: in form actions
                    if 'mailto:' in action:
                        self.features['SubmitInfoToEmail'] = 1

                # Iframe
                if soup.find_all('iframe') or soup.find_all('frame'):
                    self.features['IframeOrFrame'] = 1
                    
                # Hyperlinks & Resources
                links = soup.find_all('a', href=True)
                total_links = len(links)
                ext_links = 0
                null_links = 0
                domain_mismatch_count = 0
                
                for link in links:
                    href = link['href']
                    if href == '#' or href == '' or href.startswith('javascript:void(0)'):
                        null_links += 1
                    elif href.startswith(('http', '//')):
                        if domain not in href:
                            ext_links += 1
                        # Count domain mismatches for FrequentDomainNameMismatch
                        try:
                            link_ext = tldextract.extract(href)
                            link_domain = f"{link_ext.domain}.{link_ext.suffix}"
                            if link_domain != domain and link_ext.domain:
                                domain_mismatch_count += 1
                        except Exception:
                            pass
                
                if total_links > 0:
                    self.features['PctExtHyperlinks'] = ext_links / total_links
                    self.features['PctNullSelfRedirectHyperlinks'] = null_links / total_links
                    # FrequentDomainNameMismatch — if >50% of links go to different domains
                    if domain_mismatch_count / total_links > 0.5:
                        self.features['FrequentDomainNameMismatch'] = 1
                
                # Resources (Images, Scripts, CSS)
                resources = soup.find_all(['img', 'script', 'link'], src=True)
                total_resources = len(resources)
                ext_resources = 0
                for res in resources:
                    src = res.get('src') or res.get('href', '')
                    if src.startswith(('http', '//')) and domain not in src:
                        ext_resources += 1

                if total_resources > 0:
                    self.features['PctExtResourceUrls'] = ext_resources / total_resources
                
                # Favicon
                favicon = soup.find('link', rel=lambda x: x and 'icon' in x.lower())
                if favicon:
                    href = favicon.get('href', '')
                    if href.startswith(('http', '//')) and domain not in href:
                        self.features['ExtFavicon'] = 1

                # Sensitive Words
                text = soup.get_text().lower()
                sensitive_words = ['login', 'signin', 'sign-in', 'bank', 'confirm', 'account', 
                                   'verify', 'password', 'security', 'update', 'banking',
                                   'suspend', 'restrict', 'unauthorized', 'expire', 'urgent']
                self.features['NumSensitiveWords'] = sum(1 for word in sensitive_words if word in text)

                # Right Click disabled
                page_text = response.text
                if 'event.button==2' in page_text or 'oncontextmenu' in page_text:
                   self.features['RightClickDisabled'] = 1
                
                # PopUpWindow — detect window.open() in scripts
                if 'window.open' in page_text:
                    self.features['PopUpWindow'] = 1
                
                # FakeLinkInStatusBar — detect onmouseover status bar manipulation
                if 'onmouseover' in page_text and ('window.status' in page_text or 'status=' in page_text):
                    self.features['FakeLinkInStatusBar'] = 1
                
                # ExtMetaScriptLinkRT — check external meta/script/link tags
                meta_script_links = soup.find_all(['meta', 'script', 'link'])
                total_msl = len(meta_script_links)
                ext_msl = 0
                for tag in meta_script_links:
                    src = tag.get('src') or tag.get('href') or ''
                    if src.startswith(('http', '//')) and domain not in src:
                        ext_msl += 1
                if total_msl > 0:
                    self.features['ExtMetaScriptLinkRT'] = 1 if (ext_msl / total_msl) > 0.5 else -1
                
                # ImagesOnlyInForm — check if forms contain only images
                for form in forms:
                    children = form.find_all(True)
                    if children:
                        img_count = len(form.find_all('img'))
                        input_count = len(form.find_all('input'))
                        if img_count > 0 and input_count == 0:
                            self.features['ImagesOnlyInForm'] = 1

                # --- Security Headers Check ---
                try:
                    sec_headers = check_security_headers(response.headers)
                except Exception:
                    sec_headers = {'has_hsts': False, 'has_csp': False, 'has_x_frame_options': False,
                                   'has_x_content_type_options': False, 'has_x_xss_protection': False,
                                   'security_headers_score': 0}
                self.last_security_headers = sec_headers

                self.features['HasHSTS'] = 1 if sec_headers.get('has_hsts', False) else 0
                self.features['HasCSP'] = 1 if sec_headers.get('has_csp', False) else 0
                self.features['HasXFrameOptions'] = 1 if sec_headers.get('has_x_frame_options', False) else 0
                self.features['SecurityHeadersScore'] = sec_headers.get('security_headers_score', 0)

                # --- Mixed Content Detection ---
                try:
                    mixed_info = detect_mixed_content(soup, url)
                except Exception:
                    mixed_info = {'has_mixed_content': False, 'mixed_content_count': 0}
                self.last_mixed_content_info = mixed_info
                self.features['MixedContent'] = 1 if mixed_info.get('has_mixed_content', False) else 0

            except requests.RequestException:
                pass # Fallback to structure-only features

            # --- Derived RT Features ---
            self.features['UrlLengthRT'] = 1 if self.features['UrlLength'] > 75 else (0 if self.features['UrlLength'] > 54 else -1)
            self.features['SubdomainLevelRT'] = 1 if self.features['SubdomainLevel'] > 1 else (0 if self.features['SubdomainLevel'] == 1 else -1)
            self.features['PctExtResourceUrlsRT'] = 1 if self.features['PctExtResourceUrls'] > 0.5 else -1
            self.features['PctExtNullSelfRedirectHyperlinksRT'] = 1 if self.features['PctExtNullSelfRedirectHyperlinks'] > 0.3 else -1
            self.features['AbnormalExtFormActionR'] = 1 if self.features['ExtFormAction'] == 1 else -1

        except Exception as e:
            print(f"Extraction Error: {e}")
            
        return self.features

    def _detect_random_string(self, hostname):
        """Detect random-looking hostnames using character entropy."""
        try:
            # Remove TLD parts, focus on subdomain/domain portion
            parts = hostname.split('.')
            if len(parts) < 2:
                return 0
            
            # Check the domain portion (excluding TLD)
            test_str = '.'.join(parts[:-1]) if len(parts) > 1 else parts[0]
            test_str = test_str.replace('.', '').replace('-', '')
            
            if len(test_str) < 5:
                return 0
            
            # Calculate Shannon entropy
            freq = {}
            for c in test_str:
                freq[c] = freq.get(c, 0) + 1
            
            entropy = 0.0
            for count in freq.values():
                p = count / len(test_str)
                if p > 0:
                    entropy -= p * math.log2(p)
            
            # High entropy (>3.5) suggests random strings
            # Also check consonant-to-vowel ratio
            vowels = sum(1 for c in test_str.lower() if c in 'aeiou')
            consonants = sum(1 for c in test_str.lower() if c.isalpha() and c not in 'aeiou')
            
            if consonants > 0 and vowels > 0:
                ratio = consonants / vowels
                if entropy > 3.5 and ratio > 4:
                    return 1
            elif vowels == 0 and len(test_str) > 6:
                return 1
            
            # Check digit ratio
            digits = sum(1 for c in test_str if c.isdigit())
            if len(test_str) > 0 and digits / len(test_str) > 0.5:
                return 1
                
            return 0
        except Exception:
            return 0

    def _detect_embedded_brand(self, ext, hostname, path):
        """Detect brand names in the URL that don't match the actual domain."""
        try:
            actual_domain = ext.domain.lower()
            check_text = (hostname + path).lower()
            
            for brand in BRAND_NAMES:
                if brand != actual_domain and brand in check_text:
                    return 1
            return 0
        except Exception:
            return 0

    def _detect_domain_in_subdomains(self, ext):
        """Detect if a known domain name appears in subdomain (e.g., google.evil.com)."""
        try:
            subdomain = ext.subdomain.lower()
            if not subdomain:
                return 0
            for brand in BRAND_NAMES:
                if brand in subdomain:
                    return 1
            return 0
        except Exception:
            return 0

    def _detect_domain_in_paths(self, path):
        """Detect if a known domain name appears in the URL path."""
        try:
            path_lower = path.lower()
            for brand in BRAND_NAMES:
                if brand in path_lower:
                    return 1
            return 0
        except Exception:
            return 0

    def _reset_features(self):
        for key in self.features:
            if isinstance(self.features[key], float):
                self.features[key] = 0.0
            else:
                self.features[key] = 0

    def extract_domain(self, url):
        """Helper to extract domain.suffix from a URL"""
        try:
            if not url.startswith(('http://', 'https://')):
                url = 'http://' + url
            ext = tldextract.extract(url)
            return f"{ext.domain}.{ext.suffix}".lower()
        except Exception:
            return ""

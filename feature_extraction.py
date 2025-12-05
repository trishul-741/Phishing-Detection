import re
import math
import socket
import ssl
import whois
import tldextract
import ipaddress
import logging
import unicodedata
from datetime import datetime, timezone
from urllib.parse import urlparse

# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

SHORTENERS = {
    "bit.ly", "tinyurl.com", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "adf.ly", "bit.do", "t.co", "lnkd.in", "db.tt", "qr.ae"
}

SUSPICIOUS_TLDS = {
    "xyz", "top", "work", "loan", "club", "online", "vip", "win", "gq", "cf", "ga"
}

def is_ip_address(domain: str) -> int:
    try:
        ipaddress.ip_address(domain)
        return 1
    except ValueError:
        return 0

def has_shortening_service(domain: str) -> int:
    return 1 if domain.lower() in SHORTENERS else 0

def suspicious_tld(tld: str) -> int:
    return 1 if tld.lower() in SUSPICIOUS_TLDS else 0

def is_homograph_attack(domain: str) -> int:
    try:
        domain.encode('ascii')
        return 0 
    except UnicodeEncodeError:
        return 1

def calculate_entropy(text: str) -> float:
    if not text: return 0.0
    probabilities = [text.count(c) / len(text) for c in set(text)]
    return -sum(p * math.log2(p) for p in probabilities)

def extract_lexical_features(url: str) -> dict:
    """
    Extracts ONLY string-based features for the ML model.
    Includes normalization to handle trailing slashes.
    """
    features = {}
    
    # --- CRITICAL FIX START ---
    # Normalize URL: remove whitespace and trailing slash
    # This prevents 'google.com/' from looking different than 'google.com'
    if url:
        url = url.strip()
        if url.endswith('/'):
            url = url[:-1]
    # --- CRITICAL FIX END ---
    
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    
    parsed = urlparse(url)
    ext = tldextract.extract(url)
    domain = ext.registered_domain
    
    # 1. URL Length Features
    features['url_length'] = len(url)
    features['domain_length'] = len(domain)
    
    # 2. Count Features
    features['special_char_count'] = sum(1 for c in url if not c.isalnum())
    features['digit_count'] = sum(c.isdigit() for c in url)
    features['letter_count'] = sum(c.isalpha() for c in url)
    
    # 3. Advanced Lexical Features
    features['entropy'] = calculate_entropy(url)
    features['is_ip'] = is_ip_address(domain)
    features['is_shortener'] = has_shortening_service(domain)
    features['suspicious_tld'] = suspicious_tld(ext.suffix)
    features['homograph_risk'] = is_homograph_attack(domain)
    features['dot_count'] = url.count('.')
    features['has_at_symbol'] = 1 if '@' in url else 0
    
    return features

def ensure_tz_aware(dt):
    """Helper to ensure datetime is timezone-aware for subtraction."""
    if dt.tzinfo is None:
        return dt.replace(tzinfo=timezone.utc)
    return dt

def extract_network_features(url: str) -> dict:
    risks = []
    ext = tldextract.extract(url)
    domain = ext.registered_domain
    
    network_data = {
        'domain_age_days': 3650, # Assume old/safe by default
        'ssl_valid': False,
        'risks': []
    }

    # 1. SSL Check (Already fixed previously)
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.socket(), server_hostname=domain) as s:
            s.settimeout(3.0)
            s.connect((domain, 443))
            cert = s.getpeercert()
            not_after = cert['notAfter']
            expire_date = datetime.strptime(not_after, '%b %d %H:%M:%S %Y %Z')
            if expire_date < datetime.utcnow():
                network_data['risks'].append("SSL Certificate Expired")
            else:
                network_data['ssl_valid'] = True
    except Exception:
        pass 

    # 2. WHOIS Domain Age (CRITICAL FIX HERE)
    try:
        if is_ip_address(domain):
             network_data['risks'].append("Host is an IP Address (Suspicious)")
        else:
            try:
                w = whois.whois(domain)
                creation_date = w.creation_date
                
                if isinstance(creation_date, list):
                    creation_date = creation_date[0]
                
                if creation_date:
                    now_aware = datetime.now(timezone.utc)
                    creation_aware = ensure_tz_aware(creation_date)
                    age_days = (now_aware - creation_aware).days
                    
                    network_data['domain_age_days'] = age_days
                    
                    if age_days < 14:
                        network_data['risks'].append(f"CRITICAL: Domain is very new ({age_days} days old)")
                    elif age_days < 30:
                        network_data['risks'].append(f"Domain is new ({age_days} days old)")
            except Exception as e:
                logger.warning(f"WHOIS lookup failed for {domain}: {e}")
                
    except Exception as e:
        logger.warning(f"General network check failed: {e}")
    
    return network_data
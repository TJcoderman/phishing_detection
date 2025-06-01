import re
import math
from urllib.parse import urlparse
from collections import Counter

def extract_features(url):
    features = []
    
    # Basic Features
    features.append(len(url))  # Length of URL
    features.append(len(urlparse(url).netloc))  # Length of domain
    features.append(url.count('.'))  # Count of dots in URL

    # Presence of HTTPS
    features.append(1 if url.startswith("https") else 0)  # HTTPS presence

    # Special Characters
    features.append(url.count('-'))  # Count of hyphens
    features.append(url.count('@'))  # Count of '@'
    features.append(url.count('?'))  # Count of '?'
    features.append(url.count('%'))  # Count of '%'
    features.append(url.count('='))  # Count of '='
    features.append(url.count('/'))  # Count of '/'

    # Length of Path, Query, and Fragment
    parsed_url = urlparse(url)
    features.append(len(parsed_url.path))  # Length of path
    features.append(len(parsed_url.query))  # Length of query
    features.append(len(parsed_url.fragment))  # Length of fragment

    # Check for IP Address in URL
    features.append(1 if re.match(r'(\d{1,3}\.){3}\d{1,3}', parsed_url.netloc) else 0)

    # Count of Digits in Domain
    features.append(sum(c.isdigit() for c in parsed_url.netloc))

    # Suspicious TLDs (Top-Level Domains)
    suspicious_tlds = ['.zip', '.exe', '.app', '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq']
    features.append(1 if any(tld in url for tld in suspicious_tlds) else 0)

    # Presence of Suspicious Words
    suspicious_words = ['login', 'verify', 'secure', 'update', 'bank', 'free', 'account', 
                       'password', 'confirm', 'alert', 'limited', 'pay', 'billing', 'recover']
    features.append(1 if any(word in url.lower() for word in suspicious_words) else 0)

    # Subdomain Analysis
    subdomains = parsed_url.netloc.split('.')
    features.append(len(subdomains) - 2 if len(subdomains) > 2 else 0)  # Number of subdomains
    
    # ENHANCED FEATURES
    domain = parsed_url.netloc
    
    # URL shortening detection
    shortening_services = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'ow.ly', 'buff.ly']
    features.append(1 if any(service in domain for service in shortening_services) else 0)
    
    # Character distribution analysis (entropy)
    domain_entropy = calculate_entropy(domain)
    features.append(domain_entropy)
    
    # Abnormal URL structure
    features.append(1 if domain.count('-') > 2 else 0)  # Excessive hyphens in domain
    
    # Domain length categories
    domain_length = len(domain)
    features.append(1 if domain_length > 30 else 0)  # Very long domain
    
    # Special character ratio in domain
    special_char_count = sum(1 for c in domain if not c.isalnum() and c != '.' and c != '-')
    features.append(special_char_count / max(1, domain_length))  # Ratio of special chars
    
    # Consecutive digits in domain
    features.append(1 if re.search(r'\d{4,}', domain) else 0)  # 4+ consecutive digits
    
    # Path depth (number of directories)
    path_depth = len([p for p in parsed_url.path.split('/') if p])
    features.append(path_depth)
    
    # Query parameter count
    query_params = len(parsed_url.query.split('&')) if parsed_url.query else 0
    features.append(query_params)
    
    # Presence of encoded characters
    features.append(1 if '%' in url else 0)
    
    # Presence of double slashes not part of protocol
    features.append(1 if '//' in url.replace('://', '') else 0)
    
    return features

def calculate_entropy(text):
    """Calculate Shannon entropy of text (measure of randomness)"""
    if not text:
        return 0
    
    # Calculate frequency of each character
    freq = Counter(text)
    text_len = len(text)
    
    # Calculate entropy
    entropy = 0
    for count in freq.values():
        p_x = count / text_len
        entropy += -p_x * math.log2(p_x)
    
    return entropy

def get_url_risk_factors(url):
    """Extract human-readable risk factors from a URL"""
    risk_factors = []
    parsed_url = urlparse(url)
    domain = parsed_url.netloc
    
    # Check for IP address
    if re.match(r'(\d{1,3}\.){3}\d{1,3}', domain):
        risk_factors.append("IP address used instead of domain name")
    
    # Check URL length
    if len(url) > 75:
        risk_factors.append("Unusually long URL")
    
    # Check for HTTPS
    if not url.startswith("https"):
        risk_factors.append("Not using HTTPS secure protocol")
    
    # Check for suspicious TLDs
    suspicious_tlds = ['.zip', '.exe', '.app', '.xyz', '.tk', '.ml', '.ga', '.cf', '.gq']
    found_tlds = [tld for tld in suspicious_tlds if tld in url]
    if found_tlds:
        risk_factors.append(f"Suspicious top-level domain: {', '.join(found_tlds)}")
    
    # Check for suspicious words
    suspicious_words = ['login', 'verify', 'secure', 'update', 'bank', 'free', 'account', 
                       'password', 'confirm', 'alert', 'limited', 'pay', 'billing', 'recover']
    found_words = [word for word in suspicious_words if word in url.lower()]
    if found_words:
        risk_factors.append(f"Contains suspicious keywords: {', '.join(found_words)}")
    
    # Check for URL shorteners
    shortening_services = ['bit.ly', 'goo.gl', 'tinyurl.com', 't.co', 'is.gd', 'ow.ly', 'buff.ly']
    if any(service in domain for service in shortening_services):
        risk_factors.append("Uses a URL shortening service")
    
    # Check for excessive subdomains
    subdomains = domain.split('.')
    if len(subdomains) > 3:
        risk_factors.append(f"Excessive number of subdomains: {len(subdomains)-2}")
    
    # Check for excessive special characters
    special_char_count = sum(1 for c in domain if not c.isalnum() and c != '.' and c != '-')
    if special_char_count > 2:
        risk_factors.append("Excessive special characters in domain")
    
    # Check for excessive hyphens
    if domain.count('-') > 2:
        risk_factors.append("Excessive hyphens in domain name")
    
    # Check for encoded characters
    if '%' in url:
        risk_factors.append("Contains encoded characters")
    
    # Check for double slashes not in protocol
    if '//' in url.replace('://', ''):
        risk_factors.append("Contains double slashes in unusual places")
    
    return risk_factors

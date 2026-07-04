import re
from urllib.parse import urlparse

def extract_features(url):
    features = {}
    parsed = urlparse(url)
    domain = parsed.netloc.lower()
    path = parsed.path.lower()

    # Shorteners list
    shorteners = ['bit.ly', 'tinyurl.com', 'goo.gl', 't.co', 'ow.ly', 'is.gd']

    # Suspicious keywords
    suspicious_keywords = ['login', 'verify', 'update', 'secure', 'account',
                           'banking', 'confirm', 'password', 'signin', 'webscr',
                           'paypal', 'ebayisapi', 'free-', 'lucky']

    # 1. UsingIP — 1=phishing, -1=safe
    features['UsingIP'] = 1 if re.match(r'^\d+\.\d+\.\d+\.\d+', domain) else -1

    # 2. LongURL — 1=long, -1=short
    length = len(url)
    features['LongURL'] = -1 if length < 54 else (0 if length <= 75 else 1)

    # 3. ShortURL — 1=shortener, -1=safe
    features['ShortURL'] = 1 if any(s in domain for s in shorteners) else -1

    # 4. Symbol@ — 1=has @, -1=safe
    features['Symbol@'] = 1 if '@' in url else -1

    # 5. Redirecting// — 1=redirecting, -1=safe
    features['Redirecting//'] = 1 if url.count('//') > 1 else -1

    # 6. PrefixSuffix- — 1=has dash in domain, -1=safe
    features['PrefixSuffix-'] = 1 if '-' in domain else -1

    # 7. SubDomains
    clean_domain = domain.replace('www.', '')
    dots = clean_domain.count('.')
    features['SubDomains'] = -1 if dots == 1 else (0 if dots == 2 else 1)

    # 8. HTTPS — 1=has https(safe), -1=no https(phishing)
    features['HTTPS'] = 1 if parsed.scheme == 'https' else -1

    # 9-30: defaults based on legitimate URL averages
    features['DomainRegLen'] = -1
    features['Favicon'] = 1
    features['NonStdPort'] = 1
    features['HTTPSDomainURL'] = 1
    features['RequestURL'] = 1
    features['AnchorURL'] = 1
    features['LinksInScriptTags'] = 0
    features['ServerFormHandler'] = -1
    features['InfoEmail'] = 1
    features['AbnormalURL'] = 1
    features['WebsiteForwarding'] = 0
    features['StatusBarCust'] = 1
    features['DisableRightClick'] = 1
    features['UsingPopupWindow'] = 1
    features['IframeRedirection'] = 1
    features['AgeofDomain'] = 0
    features['DNSRecording'] = 1
    features['WebsiteTraffic'] = 1
    features['PageRank'] = -1
    features['GoogleIndex'] = 1
    features['LinksPointingToPage'] = 1
    features['StatsReport'] = 1

    # Override defaults for clear phishing signals
    if features['UsingIP'] == 1:
        features['AgeofDomain'] = -1
        features['DNSRecording'] = -1
        features['WebsiteTraffic'] = -1
        features['GoogleIndex'] = -1
        features['PageRank'] = -1

    if features['PrefixSuffix-'] == 1 and features['HTTPS'] == -1:
        features['AbnormalURL'] = -1
        features['AgeofDomain'] = -1

    keyword_hits = [kw for kw in suspicious_keywords if kw in path]
    if keyword_hits:
        features['AbnormalURL'] = -1
        features['ServerFormHandler'] = 1

    return features, keyword_hits
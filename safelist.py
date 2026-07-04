# Known legitimate domains - expandable
SAFE_DOMAINS = {
    # Tech
    'google.com', 'youtube.com', 'github.com', 'stackoverflow.com',
    'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
    'twitter.com', 'x.com', 'linkedin.com', 'instagram.com',
    'reddit.com', 'wikipedia.org', 'netflix.com', 'spotify.com',
    'dropbox.com', 'adobe.com', 'salesforce.com', 'slack.com',
    'zoom.us', 'notion.so', 'figma.com', 'canva.com',
    # Education
    'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org',
    'kaggle.com', 'medium.com', 'dev.to',
    # Finance
    'paypal.com', 'stripe.com', 'visa.com', 'mastercard.com',
    # News
    'bbc.com', 'cnn.com', 'nytimes.com', 'theguardian.com',
    # Known dash domains
    'coca-cola.com', 'google-analytics.com', 'youtube-nocookie.com',
    'microsoft-edge.com', 'open-ai.com', 'chat-gpt.com',
}

def is_safe_domain(domain):
    domain = domain.lower().replace('www.', '')
    # Check exact match
    if domain in SAFE_DOMAINS:
        return True
    # Check if it's a subdomain of a safe domain
    for safe in SAFE_DOMAINS:
        if domain.endswith('.' + safe):
            return True
    return False
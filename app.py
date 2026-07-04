import streamlit as st
import joblib
import numpy as np
import time
from features import extract_features
from urllib.parse import urlparse

st.set_page_config(page_title="PhishGuard", page_icon="terminal", layout="centered")

st.markdown("""
<style>
@import url('https://fonts.googleapis.com/css2?family=Share+Tech+Mono&family=Inter:wght@300;400;500&display=swap');

html, body, [class*="css"] {
    background-color: #0a0a0a;
    color: #e0e0e0;
    font-family: 'Inter', sans-serif;
}

.terminal-header {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.75rem;
    color: #00ff41;
    margin-bottom: 0.25rem;
    letter-spacing: 0.1em;
}

.main-title {
    font-family: 'Share Tech Mono', monospace;
    font-size: 2.4rem;
    font-weight: 400;
    color: #ffffff;
    letter-spacing: -1px;
    margin-bottom: 0.25rem;
}

.main-title span {
    color: #00ff41;
}

.subtitle {
    font-size: 0.85rem;
    color: #555;
    margin-bottom: 2.5rem;
    font-family: 'Share Tech Mono', monospace;
}

.stTextInput > div > div > input {
    background: #0f0f0f !important;
    border: 1px solid #1f1f1f !important;
    border-radius: 4px !important;
    color: #00ff41 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.9rem !important;
    padding: 0.85rem 1rem !important;
    caret-color: #00ff41;
}

.stTextInput > div > div > input:focus {
    border: 1px solid #00ff41 !important;
    box-shadow: 0 0 0 1px #00ff4133 !important;
}

.stFormSubmitButton > button {
    width: 100%;
    background: #00ff41 !important;
    color: #000 !important;
    font-family: 'Share Tech Mono', monospace !important;
    font-size: 0.85rem !important;
    font-weight: 400 !important;
    letter-spacing: 0.1em !important;
    border: none !important;
    border-radius: 4px !important;
    padding: 0.7rem !important;
    transition: all 0.2s !important;
}

.stFormSubmitButton > button:hover {
    background: #00cc33 !important;
    color: #000 !important;
}

.result-box {
    border-radius: 4px;
    padding: 1.5rem;
    margin: 1.5rem 0;
    font-family: 'Share Tech Mono', monospace;
    border-left: 3px solid;
}

.result-safe {
    background: #050f05;
    border-color: #00ff41;
}

.result-danger {
    background: #0f0505;
    border-color: #ff3333;
}

.result-warning {
    background: #0f0a03;
    border-color: #ffaa00;
}

.result-status {
    font-size: 0.7rem;
    letter-spacing: 0.15em;
    margin-bottom: 0.5rem;
}

.result-label {
    font-size: 1.5rem;
    font-weight: 400;
    margin-bottom: 0.5rem;
}

.result-advice {
    font-size: 0.8rem;
    color: #666;
    font-family: 'Inter', sans-serif;
}

.section-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.7rem;
    color: #444;
    letter-spacing: 0.15em;
    margin-bottom: 0.75rem;
    margin-top: 1.5rem;
}

.flag-item {
    background: #0f0f0f;
    border: 1px solid #1a1a1a;
    border-radius: 3px;
    padding: 0.5rem 0.85rem;
    margin: 0.25rem 0;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.8rem;
    color: #ff6666;
}

.flag-item::before {
    content: '> ';
    color: #ff3333;
}

.history-row {
    background: #0a0a0a;
    border: 1px solid #141414;
    border-radius: 3px;
    padding: 0.6rem 1rem;
    margin: 0.3rem 0;
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.78rem;
    display: flex;
    justify-content: space-between;
}

.safe-text { color: #00ff41; }
.danger-text { color: #ff3333; }
.warning-text { color: #ffaa00; }

.divider {
    border: none;
    border-top: 1px solid #141414;
    margin: 1.5rem 0;
}

.confidence-label {
    font-family: 'Share Tech Mono', monospace;
    font-size: 0.78rem;
    color: #555;
    margin-top: -0.5rem;
}

.stProgress > div > div > div > div {
    background: #00ff41 !important;
}

.scanning-text {
    font-family: 'Share Tech Mono', monospace;
    color: #00ff41;
    font-size: 0.85rem;
}
</style>
""", unsafe_allow_html=True)

# Known safe domains
SAFE_DOMAINS = {
    'google.com', 'youtube.com', 'github.com', 'stackoverflow.com',
    'microsoft.com', 'apple.com', 'amazon.com', 'facebook.com',
    'twitter.com', 'x.com', 'linkedin.com', 'instagram.com',
    'reddit.com', 'wikipedia.org', 'netflix.com', 'spotify.com',
    'dropbox.com', 'adobe.com', 'salesforce.com', 'slack.com',
    'zoom.us', 'notion.so', 'figma.com', 'canva.com',
    'coursera.org', 'udemy.com', 'edx.org', 'khanacademy.org',
    'kaggle.com', 'medium.com', 'dev.to', 'paypal.com',
    'stripe.com', 'visa.com', 'mastercard.com', 'bbc.com',
    'cnn.com', 'nytimes.com', 'theguardian.com', 'coca-cola.com',
    'google-analytics.com', 'youtube-nocookie.com',
}

def is_safe_domain(domain):
    domain = domain.lower().replace('www.', '')
    if domain in SAFE_DOMAINS:
        return True
    for safe in SAFE_DOMAINS:
        if domain.endswith('.' + safe):
            return True
    return False

# Load model
model = joblib.load('model.pkl')

# Session history
if 'history' not in st.session_state:
    st.session_state.history = []

# Header
st.markdown('<div class="terminal-header">// PHISHGUARD v1.0 — URL THREAT ANALYZER</div>', unsafe_allow_html=True)
st.markdown('<div class="main-title">Phish<span>Guard</span></div>', unsafe_allow_html=True)
st.markdown('<div class="subtitle">_ paste a url. get the truth.</div>', unsafe_allow_html=True)

# Input form
with st.form(key='scan_form'):
    url = st.text_input("", placeholder="https://target-url.com", label_visibility="collapsed")
    scan = st.form_submit_button("[ SCAN URL ]")

if scan and url:
    with st.spinner(""):
        placeholder = st.empty()
        messages = [
            "_ resolving domain...",
            "_ extracting features...",
            "_ running classifier...",
            "_ generating report..."
        ]
        for msg in messages:
            placeholder.markdown(f'<div class="scanning-text">{msg}</div>', unsafe_allow_html=True)
            time.sleep(0.4)
        placeholder.empty()

    try:
        features, keyword_hits = extract_features(url)
        domain = urlparse(url).netloc.lower().replace('www.', '')
        domain_is_safe = is_safe_domain(domain)

        # Rule-based override
        override = None
        override_reasons = []

        if not domain_is_safe:
            if features['UsingIP'] == 1:
                override = 'phishing'
                override_reasons.append('IP address used instead of domain')

            if features['ShortURL'] == 1:
                override = 'phishing'
                override_reasons.append('URL shortener detected')

            if features['Symbol@'] == 1:
                override = 'phishing'
                override_reasons.append('@ symbol in URL')

            if features['PrefixSuffix-'] == 1:
                override = 'phishing'
                override_reasons.append('Dashes in domain — possible brand impersonation')

            if len(keyword_hits) >= 2:
                override = 'phishing'
                override_reasons.append(f'Multiple suspicious keywords: {", ".join(keyword_hits)}')

        feature_values = list(features.values())
        X = np.array([feature_values])
        prediction = model.predict(X)[0]
        probability = model.predict_proba(X)[0]
        confidence = max(probability) * 100

        # Apply override
        if override == 'phishing':
            prediction = 0
            confidence = min(95.0 + (len(override_reasons) * 1.5), 99.9)
            keyword_hits = keyword_hits + override_reasons

        # Risk level
        if prediction == 0 and confidence >= 80:
            risk = "DANGEROUS"
            box_class = "result-danger"
            badge_class = "danger-text"
            label = "Phishing Detected"
            advice = "Do not visit this website or enter any personal information."
            status = "THREAT LEVEL: HIGH"
        elif prediction == 0 and confidence < 80:
            risk = "SUSPICIOUS"
            box_class = "result-warning"
            badge_class = "warning-text"
            label = "Suspicious URL"
            advice = "Proceed with caution. Some phishing indicators detected."
            status = "THREAT LEVEL: MEDIUM"
        else:
            risk = "SAFE"
            box_class = "result-safe"
            badge_class = "safe-text"
            label = "No Threat Detected"
            advice = "URL appears legitimate. No phishing indicators found."
            status = "THREAT LEVEL: NONE"

        # Result card
        st.markdown(f"""
        <div class="result-box {box_class}">
            <div class="result-status {badge_class}">{status}</div>
            <div class="result-label">{label}</div>
            <div class="result-advice">{advice}</div>
        </div>
        """, unsafe_allow_html=True)

        # Confidence
        st.markdown('<div class="section-label">// CONFIDENCE SCORE</div>', unsafe_allow_html=True)
        st.progress(int(confidence))
        st.markdown(f'<div class="confidence-label">{confidence:.1f}% model confidence</div>', unsafe_allow_html=True)

        # Flagged indicators
        flagged = {k: v for k, v in features.items() if v == 1 and k in [
            'UsingIP', 'ShortURL', 'Symbol@', 'Redirecting//',
            'PrefixSuffix-', 'NonStdPort', 'HTTPSDomainURL'
        ]}
        all_flags = list(flagged.keys()) + keyword_hits

        st.markdown('<div class="section-label">// FLAGGED INDICATORS</div>', unsafe_allow_html=True)
        if all_flags:
            for f in all_flags:
                st.markdown(f'<div class="flag-item">{f}</div>', unsafe_allow_html=True)
        else:
            st.markdown('<div class="flag-item" style="color:#444;">none detected</div>', unsafe_allow_html=True)

        # Scan report
        st.markdown('<div class="section-label">// SCAN REPORT</div>', unsafe_allow_html=True)
        result_text = f"PHISHGUARD SCAN REPORT\n{'='*40}\nURL: {url}\nVerdict: {label}\nRisk: {risk}\nConfidence: {confidence:.1f}%\n{'='*40}"
        st.code(result_text, language=None)

        # Add to history
        st.session_state.history.insert(0, {
            "url": url[:45] + "..." if len(url) > 45 else url,
            "verdict": risk,
            "badge": badge_class,
            "confidence": f"{confidence:.1f}%"
        })
        if len(st.session_state.history) > 5:
            st.session_state.history = st.session_state.history[:5]

    except Exception as e:
        st.error(f"Analysis failed: {e}")

elif scan and not url:
    st.markdown('<div class="scanning-text">_ error: no url provided.</div>', unsafe_allow_html=True)

# Recent scans
if st.session_state.history:
    st.markdown('<hr class="divider">', unsafe_allow_html=True)
    st.markdown('<div class="section-label">// RECENT SCANS</div>', unsafe_allow_html=True)
    for item in st.session_state.history:
        st.markdown(f"""
        <div class="history-row">
            <span style="color:#444;">{item['url']}</span>
            <span class="{item['badge']}">{item['verdict']} — {item['confidence']}</span>
        </div>
        """, unsafe_allow_html=True)
"""Rule engine: fast, offline, explainable. Runs BEFORE the LLM so the verdict
never depends on a model being up (same idea as the rules layer in my UPI fraud
ensemble, Sentinel)."""
import re
from urllib.parse import urlparse

# (id, regex, weight, human label)
SIGNALS = [
    ("ask_secret", r"\b(otp|upi\s*pin|mpin|cvv|card\s*number|password)\b.{0,40}\b(share|send|enter|bata|batao|dalo|bhejo|tell)\b|\b(share|send|enter|bata|batao|dalo|bhejo)\b.{0,40}\b(otp|upi\s*pin|mpin|cvv)\b", 40, "Asks for OTP/PIN/CVV. No real bank ever does."),
    ("pin_to_receive", r"(enter|dalo|daalo).{0,25}pin.{0,40}(receive|credit|refund|paisa aayega|milenge)|pin.{0,20}(enter|dalo|daalo).{0,30}(receive|credit|refund|milenge)", 45, "'Enter PIN to RECEIVE money' - receiving never needs a PIN."),
    ("urgency", r"\b(urgent|immediately|within\s*\d+\s*(hours?|hrs?|mins?|minutes?)|last\s*chance|abhi|turant|aaj hi|today only|expire[sd]?)\b", 15, "Fake urgency to stop you from thinking."),
    ("threat", r"(account|card|sim|number|connection|upi).{0,30}(block|suspend|deactivat|band|disconnect|freeze)|\bkyc\b.{0,30}(update|expire|pending|incomplete)", 25, "Threatens to block/disconnect unless you act (KYC/bill scare)."),
    ("prize", r"\b(lottery|lucky\s*draw|kbc|jackpot|you\s*(have\s*)?won|congratulations|cashback\s*of|inaam)\b", 25, "Prize/lottery bait."),
    ("task_job", r"(part[- ]?time|work from home|wfh).{0,60}(earn|income|per day|daily|\u20b9|rs\.?\s*\d)|\b(like|subscribe).{0,30}(youtube|video).{0,30}(earn|pay)", 30, "Fake part-time job / task scam pattern."),
    ("remote_app", r"\b(anydesk|teamviewer|quicksupport|rustdesk|screen\s*share)\b", 40, "Asks you to install a remote-access app."),
    ("apk", r"\.apk\b|install.{0,20}(app|apk)|download.{0,20}apk", 35, "Pushes an APK install (classic malware route)."),
    ("digital_arrest", r"\b(cbi|ncb|customs|narcotics|cyber\s*cell|police|ed\b|trai).{0,80}(arrest|case|warrant|parcel|video\s*call|fir)", 40, "'Digital arrest' / fake agency pattern. Police never video-call to arrest."),
    ("parcel", r"(parcel|courier|package).{0,50}(held|seized|customs|fee|pay|stuck)", 25, "Fake courier/customs fee."),
    ("collect_req", r"(collect\s*request|payment\s*request|request\s*money|approve.{0,15}request)", 20, "Pushes you to approve a collect request."),
    ("refund_bait", r"\b(refund|reversal|wrong\s*transfer|galti se)\b.{0,60}\b(send back|return|wapas|bhej)", 30, "'Sent money by mistake, send it back' scam."),
]

SHORTENERS = {"bit.ly", "tinyurl.com", "t.co", "cutt.ly", "rb.gy", "is.gd", "shorturl.at", "tiny.cc", "wa.link"}
BAD_TLDS = (".xyz", ".top", ".click", ".icu", ".shop", ".buzz", ".live", ".cfd", ".sbs", ".vip", ".work")
BRANDS = {  # brand keyword -> real domains
    "sbi": ["sbi.co.in", "onlinesbi.sbi", "sbicard.com"],
    "hdfc": ["hdfcbank.com"], "icici": ["icicibank.com"], "axis": ["axisbank.com"],
    "paytm": ["paytm.com"], "phonepe": ["phonepe.com"], "gpay": ["pay.google.com"],
    "npci": ["npci.org.in"], "irctc": ["irctc.co.in"], "uidai": ["uidai.gov.in"],
    "aadhaar": ["uidai.gov.in"], "incometax": ["incometax.gov.in"],
    "amazon": ["amazon.in", "amazon.com"], "flipkart": ["flipkart.com"],
}
URL_RE = re.compile(r"(?:https?://|www\.)[^\s<>\"']+|\b[a-z0-9-]+(?:\.[a-z0-9-]+)*\.(?:com|in|xyz|top|click|icu|shop|buzz|live|cfd|sbs|vip|work|co\.in|link|me|ly)\b/?[^\s]*", re.I)


def extract_urls(text):
    out = []
    for m in URL_RE.findall(text):
        u = m.rstrip(".,);]")
        if u not in out:
            out.append(u)
    return out


def host_of(url):
    p = urlparse(url if "://" in url else "http://" + url)
    return (p.hostname or "").lower().removeprefix("www.")


def check_url(url):
    """Return list of (weight, reason) for one URL."""
    h = host_of(url)
    found = []
    if h in SHORTENERS:
        found.append((20, f"{h} is a link shortener - hides the real destination."))
    if h.endswith(BAD_TLDS):
        found.append((20, f"{h} uses a cheap TLD common in scam sites."))
    if re.fullmatch(r"[\d.]+", h):
        found.append((25, "Link goes to a raw IP address."))
    for brand, real in BRANDS.items():
        if brand in h and not any(h == r or h.endswith("." + r) for r in real):
            found.append((35, f"{h} imitates '{brand}' but isn't {real[0]}."))
            break
    if h.count("-") >= 2:
        found.append((10, f"{h} has many hyphens (lookalike-domain habit)."))
    return found


def analyze(text):
    t = text.lower()
    score, hits = 0, []
    for sid, rx, w, label in SIGNALS:
        if re.search(rx, t, re.I | re.S):
            score += w
            hits.append({"id": sid, "weight": w, "why": label})
    urls = extract_urls(text)
    for u in urls:
        for w, why in check_url(u):
            score += w
            hits.append({"id": "url", "weight": w, "why": why})
    if len(hits) >= 3:  # combos are worse than the sum of parts
        score += 10
    score = min(score, 100)
    verdict = "DHOKHA" if score >= 60 else "SHAKI" if score >= 30 else "LAGTA SAFE"
    return {"score": score, "verdict": verdict, "signals": hits, "urls": urls}

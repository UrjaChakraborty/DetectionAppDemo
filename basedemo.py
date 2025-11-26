import re
import joblib

# loading a very simple model
clf = joblib.load("spam_classifier.joblib")
vectorizer = joblib.load("vectorizer.joblib")

# safety checker for URLs
BLACKLISTED_DOMAINS = {"badsite.ru", "scam-link.com", "malware-download.net"}

def check_url_safety(url):
    domain = re.sub(r"https?://", "", url).split("/")[0]

    if domain in BLACKLISTED_DOMAINS:
        return "malicious"

    if re.search(r"%[0-9A-Fa-f]{2}", url):   # URL encoding → often obfuscation
        return "suspicious"

    if len(domain.split(".")) > 3:           # many subdomains → suspicious pattern
        return "suspicious"

    return "safe"


# attachment check
def check_attachment(filename):
    if filename.endswith((".exe", ".bat", ".scr")):
        return "malicious"
    return "safe"


# scanning function
def analyze_email(subject, body, urls=None, attachments=None):
    results = {"spam_model": None, "urls": {}, "attachments": {}}

    # ML classification
    prediction = clf.predict(vectorizer.transform([subject + " " + body]))
    results["spam_model"] = prediction[0]  # "spam" or "ham"

    # URL checks
    if urls:
        for url in urls:
            results["urls"][url] = check_url_safety(url)

    # Attachment checks
    if attachments:
        for att in attachments:
            results["attachments"][att] = check_attachment(att)

    return results


# testing the function
if __name__ == "__main__":
    demo_subject = "URGENT! Your account is locked"
    demo_body = "Click here immediately to restore access: http://badsite.ru/login"
    demo_urls = ["http://badsite.ru/login"]
    demo_files = ["invoice.pdf", "setup.exe"]

    scan = analyze_email(demo_subject, demo_body, demo_urls, demo_files)
    print("\n--- DEMO EMAIL SCAN RESULTS ---")
    print(scan)

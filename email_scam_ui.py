from flask import Flask, request, redirect, url_for, render_template_string
import re
from urllib.parse import urlparse

app = Flask(__name__)

BLACKLISTED_DOMAINS = {
    "badsite.ru",
    "scam-link.com",
    "malware-download.net",
}

SUSPICIOUS_TLDS = {
    ".ru", ".cn", ".tk", ".xyz", ".top", ".club", ".work"
}

SCAM_KEYWORDS = {
    "urgent",
    "verify your account",
    "account locked",
    "click here",
    "password",
    "login",
    "bank",
    "credit card",
    "ssn",
    "social security",
    "limited time",
    "win",
    "winner",
    "prize",
    "lottery",
    "gift card",
}


def extract_urls(text: str):
    pattern = re.compile(r"https?://[^\s]+", re.IGNORECASE)
    return pattern.findall(text)


def get_domain(url: str) -> str:
    return urlparse(url).netloc.lower()


def check_url_safety(url: str) -> str:
    domain = get_domain(url)

    if domain in BLACKLISTED_DOMAINS:
        return "malicious"

    if re.search(r"%[0-9A-Fa-f]{2}", url):
        return "suspicious"

    if len(domain.split(".")) > 3:
        return "suspicious"

    for tld in SUSPICIOUS_TLDS:
        if domain.endswith(tld):
            return "suspicious"

    return "safe"


def contains_scam_keywords(text: str) -> bool:
    lowered = text.lower()
    return any(kw in lowered for kw in SCAM_KEYWORDS)


def analyze_email(subject: str, body: str):
    full = subject + "\n" + body
    urls = extract_urls(full)
    url_results = {u: check_url_safety(u) for u in urls}
    has_keywords = contains_scam_keywords(full)

    if any(v == "malicious" for v in url_results.values()):
        overall = "scam"
    elif any(v == "suspicious" for v in url_results.values()) and has_keywords:
        overall = "likely scam"
    elif has_keywords:
        overall = "suspicious"
    else:
        overall = "probably safe"

    return {
        "overall": overall,
        "urls": url_results,
        "has_scam_keywords": has_keywords,
    }

# Test cases
EMAILS = [
    {
        "id": 1,
        "name": "Inbox 1",
        "subject": "URGENT: Verify your account",
        "body": (
            "Dear user,\n\n"
            "Your account is locked due to suspicious activity.\n"
            "Click here to restore access: http://badsite.ru/login\n\n"
            "Best,\nSecurity Team"
        ),
    },
    {
        "id": 2,
        "name": "Inbox 2",
        "subject": "You won a $500 gift card!",
        "body": (
            "Congratulations!\n\n"
            "You are the winner of a $500 gift card.\n"
            "Verify your account at https://secure-login.bank-support.xyz/claim\n\n"
            "Offer valid for a limited time only."
        ),
    },
    {
        "id": 3,
        "name": "Inbox 3",
        "subject": "Team meeting schedule",
        "body": (
            "Hi,\n\n"
            "Here is the Zoom link for our meeting tomorrow:\n"
            "https://zoom.us/j/123456789\n\n"
            "Thanks!"
        ),
    },
    {
        "id": 4,
        "name": "Inbox 4",
        "subject": "Your monthly bill is ready",
        "body": (
            "Hello,\n\n"
            "Your energy bill for this month is ready.\n"
            "View it at https://utility-bills.com/account\n\n"
            "Have a nice day."
        ),
    },
    {
        "id": 5,
        "name": "Inbox 5",
        "subject": "Account password reset",
        "body": (
            "We received a request to reset your password.\n"
            "If this was you, click here: https://example.com/reset?token=ABCD\n"
            "If not, ignore this email."
        ),
    },
    {
        "id": 6,
        "name": "Inbox 6",
        "subject": "Random promo email",
        "body": (
            "Hey!\n\n"
            "Check out our random deals at https://promo.example.com.\n\n"
            "Cheers!"
        ),
    },
    {
        "id": 7,
        "name": "Inbox 7",
        "subject": "Suspicious security alert",
        "body": (
            "Security alert:\n\n"
            "We noticed suspicious activity.\n"
            "Login at https://my.bank-secure-login.tk/auth now.\n\n"
            "Bank Security."
        ),
    },
    {
        "id": 8,
        "name": "Inbox 8",
        "subject": "Welcome to our service!",
        "body": (
            "Welcome!\n\n"
            "Thanks for signing up. Visit https://goodapp.com/dashboard to get started.\n"
        ),
    },
    {
        "id": 9,
        "name": "Inbox 9",
        "subject": "Lottery winner notification",
        "body": (
            "You are the winner of our international lottery!\n"
            "Send your bank details to claim your prize.\n"
        ),
    },
    {
        "id": 10,
        "name": "Inbox 10",
        "subject": "Receipt for your payment",
        "body": (
            "Hi,\n\n"
            "Thank you for your payment. Your receipt is attached.\n"
            "No links in this email.\n"
        ),
    },
]


def get_email(email_id: int):
    for e in EMAILS:
        if e["id"] == email_id:
            return e
    return None




TEMPLATE = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>G-mail Page with Scam Detector</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0;
            font-family: system-ui, -apple-system, BlinkMacSystemFont,
                         "Segoe UI", Roboto, sans-serif; }

        body {
            background: #f7f5fb;
            color: #1f1f2e;
            height: 100vh;
            display: flex;
            flex-direction: column;
        }

        .top {
            height: 40px;
            background: #000;
        }

        .main {
            flex: 1;
            display: flex;
        }

        /* Left sidebar */
        .sidebar {
            width: 260px;
            background: #f3ecff;
            padding: 24px 16px;
            display: flex;
            flex-direction: column;
            gap: 24px;
        }

        .logo-text {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 8px;
        }

        .compose-btn {
            display: inline-flex;
            align-items: center;
            justify-content: center;
            gap: 8px;
            padding: 10px 24px;
            border-radius: 24px;
            border: none;
            background: #ece2ff;
            box-shadow: 0 3px 8px rgba(0,0,0,0.08);
            cursor: pointer;
            font-size: 14px;
        }

        .compose-btn span.icon {
            width: 18px;
            height: 18px;
            border-radius: 50%;
            border: 2px solid #6c5ce7;
        }

        .section-title {
            font-size: 12px;
            color: #7b7c8c;
            margin-bottom: 8px;
        }

        .nav-item {
            display: flex;
            align-items: center;
            justify-content: space-between;
            padding: 10px 14px;
            border-radius: 18px;
            font-size: 14px;
            cursor: pointer;
            color: #5a4c7c;
        }

        .nav-item.active {
            background: #e3d8ff;
            font-weight: 600;
            color: #3b2a78;
        }

        .nav-item span.left {
            display: flex;
            align-items: center;
            gap: 10px;
        }

        .nav-icon-box {
            width: 22px;
            height: 16px;
            border-radius: 4px;
            border: 2px solid #7f6dd9;
        }

        .nav-label-icon {
            width: 16px;
            height: 12px;
            border-radius: 2px;
            border: 2px solid #7f6dd9;
        }

        .nav-count {
            font-size: 12px;
            color: #7b7c8c;
        }

        .divider {
            height: 1px;
            background: #e0d6f5;
            margin: 12px 0;
        }

        /* Center area */
        .center {
            flex: 1;
            padding: 24px 32px;
            display: flex;
            flex-direction: column;
        }

        .top-bar {
            display: flex;
            align-items: center;
            gap: 16px;
            margin-bottom: 24px;
        }

        .menu-icon {
            width: 32px;
            height: 32px;
            border-radius: 50%;
            background: #f3ecff;
            display: flex;
            align-items: center;
            justify-content: center;
            cursor: pointer;
        }

        .search-box {
            flex: 1;
            display: flex;
            align-items: center;
            padding: 10px 20px;
            border-radius: 24px;
            background: #f3ecff;
            font-size: 14px;
            color: #8c7fb1;
            gap: 10px;
        }

        .search-box input {
            border: none;
            background: transparent;
            width: 100%;
            outline: none;
            font-size: 14px;
            color: #5a4c7c;
        }

        .profile-badge {
            width: 40px;
            height: 40px;
            border-radius: 50%;
            background: #e3d8ff;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 20px;
            color: #5a4c7c;
        }

        .tabs {
            display: grid;
            grid-template-columns: repeat(3, 1fr);
            background: #f7f0ff;
            border-radius: 6px 6px 0 0;
            padding: 8px 0;
            font-size: 14px;
            text-align: center;
            color: #8c7fb1;
        }

        .tab.active {
            color: #6c5ce7;
            font-weight: 600;
            border-bottom: 2px solid #6c5ce7;
        }

        .list-panel {
            background: #ffffff;
            border-radius: 0 0 6px 6px;
            box-shadow: 0 3px 12px rgba(0,0,0,0.06);
            overflow: hidden;
            display: flex;
        }

        .email-list {
            width: 45%;
            min-width: 320px;
            border-right: 1px solid #eeeeee;
            max-height: 70vh;
            overflow-y: auto;
        }

        .row {
            display: grid;
            grid-template-columns: 40px 1fr;
            align-items: center;
            padding: 10px 16px;
            background: #e6e6e6;
            border-bottom: 4px solid #ffffff;
            cursor: pointer;
        }

        .row .check-cell {
            display: flex;
            justify-content: center;
        }

        .checkbox {
            width: 18px;
            height: 18px;
            border-radius: 3px;
            border: 2px solid #6c5ce7;
            background: #6c5ce7;
        }

        .row.selected {
            background: #d3ccff;
        }

        .row-title {
            font-size: 14px;
            color: #333;
            display: flex;
            align-items: center;
            justify-content: space-between;
        }

        .risk-tag {
            font-size: 11px;
            padding: 2px 8px;
            border-radius: 999px;
            margin-left: 8px;
            text-transform: uppercase;
            letter-spacing: 0.04em;
        }
        .risk-safe {
            background: #e6f4ea;
            color: #137333;
        }
        .risk-suspicious {
            background: #fef7e0;
            color: #b06a00;
        }
        .risk-likely {
            background: #fff4ce;
            color: #b06a00;
        }
        .risk-scam {
            background: #fce8e6;
            color: #c5221f;
        }

        /* Detail panel */
        .detail {
            flex: 1;
            padding: 16px 20px;
        }

        .detail-title {
            font-size: 18px;
            font-weight: 600;
            margin-bottom: 6px;
        }

        .detail-meta {
            font-size: 13px;
            color: #666;
            margin-bottom: 12px;
        }

        .detail-body {
            background: #f7f5fb;
            border-radius: 6px;
            padding: 12px;
            font-size: 14px;
            white-space: pre-wrap;
        }

        .detail-verdict {
            margin-top: 12px;
            font-size: 14px;
            font-weight: 600;
        }

        .detail-verdict.safe { color: #137333; }
        .detail-verdict.suspicious { color: #b06a00; }
        .detail-verdict.likely { color: #b06a00; }
        .detail-verdict.scam { color: #c5221f; }

        .detail-urls {
            margin-top: 8px;
            font-size: 13px;
        }

        .detail-urls ul {
            margin-top: 4px;
            padding-left: 18px;
        }

        .detail-actions {
            margin-top: 10px;
            display: flex;
            gap: 8px;
        }

        .btn {
            padding: 6px 10px;
            border-radius: 4px;
            border: 1px solid #ccc;
            font-size: 12px;
            cursor: pointer;
        }
        .btn-report {
            background: #fce8e6;
            border-color: #f28b82;
        }
        .btn-spam {
            background: #fff4ce;
            border-color: #fbbc04;
        }

        .detail-status {
            margin-top: 6px;
            font-size: 12px;
            font-style: italic;
            color: #666;
        }

        .email-list::-webkit-scrollbar {
            width: 8px;
        }
        .email-list::-webkit-scrollbar-thumb {
            background: #c4c4c4;
            border-radius: 4px;
        }

        /* Toast popup */
        .toast {
        position: fixed;
        top: 50%;
        left: 50%;
        transform: translate(-50%, -40%);
        width: 420px;                         /* Bigger width */
        padding: 20px 28px;                   /* Bigger padding */
        background: #323232;
        color: #fff;
        border-radius: 16px;                  /* Softer rounding */
        font-size: 16px;                      /* Larger text */
        display: flex;
        align-items: center;
        justify-content: space-between;       /* Space text + button */
        gap: 16px;
        box-shadow: 0 6px 20px rgba(0,0,0,0.35);
        opacity: 0;
        pointer-events: none;
        transition: opacity 0.25s ease, transform 0.25s ease;
        z-index: 9999;
    }

    .toast.show {
        opacity: 1;
        pointer-events: auto;
        transform: translate(-50%, -50%);
    }

    .toast button {
        border: none;
        background: transparent;
        color: #8ab4f8;
        font-weight: 600;
        cursor: pointer;
        font-size: 15px;
    }

    </style>
</head>
<body>
    <div class="top"></div>
    <div class="main">
        <!-- Sidebar -->
        <aside class="sidebar">
            <div>
                <div class="logo-text">Mail</div>
                <button class="compose-btn">
                    <span class="icon"></span>
                    Compose
                </button>
            </div>

            <div>
                <div class="nav-item active">
                    <span class="left">
                        <span class="nav-icon-box"></span>
                        Inbox
                    </span>
                    <span class="nav-count">24</span>
                </div>
                <div class="nav-item">
                    <span class="left">
                        <span>▶</span>
                        Outbox
                    </span>
                </div>
                <div class="nav-item">
                    <span class="left">
                        <span>♥</span>
                        Favorites
                    </span>
                </div>
                <div class="nav-item">
                    <span class="left">
                        <span>🗑</span>
                        Trash
                    </span>
                </div>
            </div>

            <div>
                <div class="section-title">Labels</div>
                <div class="nav-item">
                    <span class="left">
                        <span class="nav-label-icon"></span>
                        Label
                    </span>
                </div>
                <div class="nav-item">
                    <span class="left">
                        <span class="nav-label-icon"></span>
                        Label
                    </span>
                </div>
                <div class="nav-item">
                    <span class="left">
                        <span class="nav-label-icon"></span>
                        Label
                    </span>
                </div>
                <div class="divider"></div>
                <div class="nav-item">
                    <span class="left">
                        <span class="nav-label-icon"></span>
                        Label
                    </span>
                </div>
            </div>
        </aside>

        <!-- Center content -->
        <section class="center">
            <div class="top-bar">
                <div class="menu-icon">☰</div>
                <div class="search-box">
                    <span>Hinted search text</span>
                    <input type="text" placeholder="" />
                    <span>🔍</span>
                </div>
                <div class="profile-badge">👤</div>
            </div>

            <div class="tabs">
                <div class="tab active">Primary</div>
                <div class="tab">Promotions</div>
                <div class="tab">Social</div>
            </div>

            <div class="list-panel">
                <!-- Email list -->
                <div class="email-list">
                    {% for email in emails %}
                    {% set analysis = analyses[email.id] %}
                    {% set overall = analysis.overall %}
                    {% if overall == 'scam' %}
                        {% set tag_class = 'risk-scam' %}
                        {% set tag_text = 'Scam' %}
                    {% elif overall == 'likely scam' %}
                        {% set tag_class = 'risk-likely' %}
                        {% set tag_text = 'Likely scam' %}
                    {% elif overall == 'suspicious' %}
                        {% set tag_class = 'risk-suspicious' %}
                        {% set tag_text = 'Suspicious' %}
                    {% else %}
                        {% set tag_class = 'risk-safe' %}
                        {% set tag_text = 'Safe' %}
                    {% endif %}
                    <a href="{{ url_for('inbox', email_id=email.id) }}" style="text-decoration:none;">
                        <div class="row {% if selected and selected.id == email.id %}selected{% endif %}">
                            <div class="check-cell">
                                <div class="checkbox"></div>
                            </div>
                            <div class="row-title">
                                <span>{{ email.name }}</span>
                                <span class="risk-tag {{ tag_class }}">{{ tag_text }}</span>
                            </div>
                        </div>
                    </a>
                    {% endfor %}
                </div>

                <!-- Detail panel -->
                <div class="detail">
                    {% if selected %}
                        {% set ana = analyses[selected.id] %}
                        {% set overall = ana.overall %}
                        <div class="detail-title">{{ selected.subject }}</div>
                        <div class="detail-meta">Email #{{ selected.id }}</div>
                        <div class="detail-body">{{ selected.body }}</div>

                        <div class="detail-verdict
                            {% if overall == 'scam' %}scam
                            {% elif overall == 'likely scam' %}likely
                            {% elif overall == 'suspicious' %}suspicious
                            {% else %}safe{% endif %}
                        ">
                            Verdict: {{ overall }}
                        </div>

                        <div class="detail-urls">
                            {% if ana.urls %}
                                <div><strong>URLs detected:</strong></div>
                                <ul>
                                {% for u, status in ana.urls.items() %}
                                    <li>{{ u }} → {{ status }}</li>
                                {% endfor %}
                                </ul>
                            {% else %}
                                <div><strong>No URLs detected.</strong></div>
                            {% endif %}
                        </div>

                        <form method="post" action="{{ url_for('action') }}">
                            <input type="hidden" name="email_id" value="{{ selected.id }}">
                            <div class="detail-actions">
                                <button class="btn btn-report" type="submit" name="action" value="report">
                                    Report as scam
                                </button>
                                <button class="btn btn-spam" type="submit" name="action" value="spam">
                                    Move to spam
                                </button>
                            </div>
                        </form>

                        <div class="detail-status">
                            {% if selected.id in reported and selected.id in spam %}
                                Reported as scam and moved to spam.
                            {% elif selected.id in reported %}
                                Reported as scam.
                            {% elif selected.id in spam %}
                                Marked as spam.
                            {% else %}
                                No user action taken yet.
                            {% endif %}
                        </div>
                    {% else %}
                        <div style="color:#777;font-size:14px;">Select an email on the left to view details.</div>
                    {% endif %}
                </div>
            </div>
        </section>
    </div>

    {% if toast_type == 'reported' %}
<div id="toast" class="toast show">
    <span>Email #{{ toast_email_id }} reported as scam.</span>
    <form method="post" action="{{ url_for('action') }}">
        <input type="hidden" name="email_id" value="{{ toast_email_id }}">
        <button type="submit" name="action" value="undo_report">Undo</button>
    </form>
</div>

{% elif toast_type == 'spam' %}
<div id="toast" class="toast show">
    <span>Email #{{ toast_email_id }} moved to spam.</span>
    <form method="post" action="{{ url_for('action') }}">
        <input type="hidden" name="email_id" value="{{ toast_email_id }}">
        <button type="submit" name="action" value="undo_spam">Undo</button>
    </form>
</div>

    {% elif toast_type == 'undo_report' %}
    <div id="toast" class="toast show">
        <span>Undo successful — report removed for email #{{ toast_email_id }}.</span>
    </div>

    {% elif toast_type == 'undo_spam' %}
    <div id="toast" class="toast show">
        <span>Undo successful — removed from spam for email #{{ toast_email_id }}.</span>
    </div>
    {% endif %}


    <script>
        // Auto-hide toast after 5 seconds
        window.addEventListener("load", function() {
            var toast = document.getElementById("toast");
            if (toast) {
                setTimeout(function() {
                    toast.classList.remove("show");
                }, 5000);
            }
        });
    </script>
</body>
</html>
"""

REPORTED = set()
SPAM = set()


@app.route("/", methods=["GET"])
def inbox():
    email_id = request.args.get("email_id", type=int)
    if email_id is None:
        email_id = EMAILS[0]["id"]

    selected = get_email(email_id)


    analyses = {}
    for e in EMAILS:
        analyses[e["id"]] = analyze_email(e["subject"], e["body"])

    toast_type = request.args.get("toast")
    toast_email_id = request.args.get("toast_email_id", type=int)

    return render_template_string(
        TEMPLATE,
        emails=EMAILS,
        selected=selected,
        analyses=analyses,
        reported=REPORTED,
        spam=SPAM,
        toast_type=toast_type,
        toast_email_id=toast_email_id,
    )


@app.route("/action", methods=["POST"])
def action():
    email_id = int(request.form["email_id"])
    act = request.form.get("action")

    # REPORT
    if act == "report":
        REPORTED.add(email_id)
        print(f"[REPORT] Email {email_id} reported as scam.")
        return redirect(url_for(
            "inbox",
            email_id=email_id,
            toast="reported",
            toast_email_id=email_id
        ))

    # SPAM
    elif act == "spam":
        SPAM.add(email_id)
        print(f"[SPAM] Email {email_id} moved to spam.")
        return redirect(url_for(
            "inbox",
            email_id=email_id,
            toast="spam",
            toast_email_id=email_id
        ))

    # UNDO REPORT
    elif act == "undo_report":
        if email_id in REPORTED:
            REPORTED.discard(email_id)
            print(f"[UNDO] Report removed for email {email_id}.")
        return redirect(url_for(
            "inbox",
            email_id=email_id,
            toast="undo_report",
            toast_email_id=email_id
        ))

    # UNDO SPAM
    elif act == "undo_spam":
        if email_id in SPAM:
            SPAM.discard(email_id)
            print(f"[UNDO] Spam removed for email {email_id}.")
        return redirect(url_for(
            "inbox",
            email_id=email_id,
            toast="undo_spam",
            toast_email_id=email_id
        ))

    return redirect(url_for("inbox", email_id=email_id))

if __name__ == "__main__":
    app.run(debug=True)

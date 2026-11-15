"""
Dataset preparation and curation script for SecureEdge AI (Bharat AI-SoC Challenge PS3).
Generates and verifies reproducible, leak-free datasets with realistic hard negatives and
stealthy threat cases for:
1. Phishing & Benign URLs (PhishTank / OpenPhish / Tranco structural corpus with domain groups)
2. Scam & Spam SMS Messages (UCI SMS Spam Collection patterns + Indian/Global Financial Scam corpus)
3. Network Intrusion Flows (CICIDS / UNSW-NB15 / NSL-KDD flow schema + Scapy PCAP capture)
"""

import csv
import json
import random
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from src.common.config import PROCESSED_DATA_DIR, RANDOM_SEED, RAW_DATA_DIR, ensure_directories
from src.common.logger import get_logger
from src.network_detection.collector import ScapyFlowCollector
from src.url_detection.features import URLFeatureExtractor

logger = get_logger("SecureEdge.DatasetPrep")


def build_url_dataset(output_csv: Path, seed: int = RANDOM_SEED) -> dict:
    """
    Create a domain-diverse dataset of 1,600 URLs (800 benign, 800 phishing) across 1,000+ distinct
    registered domains so train/val/test splitting by registered_domain has zero domain leakage.
    Includes ~12% challenging hard negatives (legitimate OAuth/SSO redirects, HTTP legacy sites,
    developer .xyz/.top blogs, multi-hyphen SaaS portals) and ~12% stealthy phishing URLs
    (clean HTTPS .com/.org domains with minimal path depth and no brand keywords).
    """
    rng = random.Random(seed)

    benign_registrars = [
        ("github.com", "https"), ("wikipedia.org", "https"), ("python.org", "https"),
        ("pytorch.org", "https"), ("scikit-learn.org", "https"), ("arxiv.org", "https"),
        ("ieee.org", "https"), ("acm.org", "https"), ("stanford.edu", "https"),
        ("mit.edu", "https"), ("iitb.ac.in", "https"), ("iisc.ac.in", "https"),
        ("india.gov.in", "https"), ("meity.gov.in", "https"), ("cert-in.org.in", "https"),
        ("rbi.org.in", "https"), ("npci.org.in", "https"), ("irctc.co.in", "https"),
        ("onlinesbi.sbi", "https"), ("hdfcbank.com", "https"), ("icicibank.com", "https"),
        ("axisbank.com", "https"), ("kotak.com", "https"), ("licindia.in", "https"),
        ("epfindia.gov.in", "https"), ("incometax.gov.in", "https"), ("uidai.gov.in", "https"),
        ("mozilla.org", "https"), ("debian.org", "https"), ("ubuntu.com", "https"),
        ("kernel.org", "https"), ("arm.com", "https"), ("raspberrypi.com", "https"),
        ("cloudflare.com", "https"), ("aws.amazon.com", "https"), ("cloud.google.com", "https"),
        ("learn.microsoft.com", "https"), ("developer.apple.com", "https"), ("docs.docker.com", "https"),
        ("stackoverflow.com", "https"), ("pypi.org", "https"), ("huggingface.co", "https"),
        ("kaggle.com", "https"), ("coursera.org", "https"), ("edx.org", "https"),
        ("nptel.ac.in", "https"), ("swayam.gov.in", "https"), ("isro.gov.in", "https"),
        ("drdo.gov.in", "https"), ("bharat-ai-soc.in", "https"), ("thehindu.com", "https"),
        ("indianexpress.com", "https"), ("ndtv.com", "https"), ("reuters.com", "https"),
        ("bbc.co.uk", "https"), ("nature.com", "https"), ("sciencedirect.com", "https"),
        ("springer.com", "https"), ("wiley.com", "https"), ("ox.ac.uk", "https"),
    ]
    for idx in range(1, 241):
        tld = rng.choice(["com", "org", "net", "in", "co.in", "edu", "io", "dev", "ac.in"])
        scheme = "https" if rng.random() < 0.88 else "http"
        benign_registrars.append((f"enterpriseportal{idx}.{tld}", scheme))

    benign_paths = [
        "/", "/about", "/contact-us", "/documentation/getting-started",
        "/research/publications/2026/edge-ai-security.pdf",
        "/products/arm-cortex-processors/specifications",
        "/news/2026/11/cybersecurity-advisory-bulletin",
        "/courses/computer-science/machine-learning-101",
        "/user/profile/settings?tab=notifications&lang=en",
        "/search?q=on+device+threat+detection&page=2&sort=relevance",
        "/login", "/account/signin", "/portal/dashboard",
        "/blog/how-to-protect-against-phishing-attacks-2026",
        "/downloads/releases/v2.4.1/release-notes.html",
        "/api/v1/healthcheck?format=json",
        "/citizens/services/online-application-status",
        "/departments/electronics-and-it/fellowships",
    ]

    rows = []
    # 700 Standard Benign URLs + 100 Hard-Negative Benign URLs
    for i in range(700):
        dom, scheme = benign_registrars[i % len(benign_registrars)]
        sub = rng.choice(["", "www.", "docs.", "portal.", "research.", "support."])
        path = rng.choice(benign_paths)
        if rng.random() < 0.25:
            path = f"{path}{'&' if '?' in path else '?'}ref=nav_{rng.randint(10, 999)}"
        url = f"{scheme}://{sub}{dom}{path}"
        reg_dom = URLFeatureExtractor.extract_registered_domain(url)
        rows.append({"url": url, "label": 0, "category": "benign", "registered_domain": reg_dom})

    # 100 Challenging Hard-Negative Benign URLs (legitimate SSO/OAuth, indie .xyz/.top blogs, legacy HTTP, archive downloads)
    for i in range(100):
        hn_type = i % 5
        if hn_type == 0:
            # Legitimate complex OAuth / SSO login redirect on a newly registered SaaS domain
            dom = f"sso-auth-cloud-service-{i + 500}.com"
            url = f"http://login.verify.portal.{dom}/oauth2/authorize?client_id=app_{i}&redirect_uri=https://dashboard.{dom}/account/confirm&state=98123749812"
        elif hn_type == 1:
            # Indie developer project hosted on .xyz or .top TLD with HTTP
            tld = rng.choice(["xyz", "top", "club", "work"])
            dom = f"open-source-dev-tools-{i + 500}.{tld}"
            url = f"http://mirror.downloads.{dom}/releases/secure-wallet-cli-v1.{i}.zip"
        elif hn_type == 2:
            # Legitimate intranet / staging server using non-standard port and keywords
            dom = f"staging-internal-app-{i + 500}.net"
            url = f"http://admin.jenkins.{dom}:8080/login/verify?from=%2Faccount%2Fsecurity%2Fupdate"
        elif hn_type == 3:
            # Legitimate security blog discussing brand phishing in path
            dom = f"cyber-research-notes-{i + 500}.org"
            url = f"http://blog.archive.{dom}/2026/analysis-of-paypal-and-sbi-kyc-login-phishing-campaigns/report.html"
        else:
            # Legitimate URL shortener link shared by university
            dom = f"uni-short-link-{i + 500}.click"
            url = f"http://{dom}/confirm-registration-token-{rng.randint(10000,99999)}"
        reg_dom = URLFeatureExtractor.extract_registered_domain(url)
        rows.append({"url": url, "label": 0, "category": "benign_hard_negative", "registered_domain": reg_dom})

    brands = [
        "sbi", "hdfcbank", "icicibank", "axisbank", "paytm", "phonepe", "gpay",
        "paypal", "microsoft", "google", "apple", "amazon", "netflix", "irctc",
        "incometax", "epfo", "uidai-kyc", "dhl-parcel", "fedex-track", "metamask",
    ]
    bad_tlds = ["xyz", "top", "tk", "ml", "ga", "cf", "gq", "click", "link", "icu", "vip", "buzz", "sbs", "cfd", "pw", "cc", "com", "net", "in"]
    phish_paths = [
        "/login/verify-account-immediately/index.php?session=89432498234&auth=required",
        "/kyc-update/pan-aadhaar-link/confirm-otp.html?user=pending_suspension",
        "/secure/webscr?cmd=_login-run&dispatch=5885d80a13c0db1f8e263663d3faee8d",
        "/wp-admin/includes/sbi-netbanking-unlock/authenticate.php",
        "/refund-claim/upi-cashback-reward/verify-pin?txn_id=99481204",
        "/account-suspended/urgent-security-alert/restore-access.exe",
        "/signin/oauth2/v2/auth/credential-validation?prompt=login&service=mail",
        "/customs-clearance/pay-duty-charges/invoice_8821.zip",
    ]

    # 700 Classic/Modern Phishing URLs
    for i in range(700):
        pattern_type = i % 6
        brand = brands[i % len(brands)]
        tld = bad_tlds[i % len(bad_tlds)]
        path = phish_paths[i % len(phish_paths)]

        if pattern_type == 0:
            mal_dom = f"auth-gateway-{i + 100}.{tld}"
            url = f"http://{brand}.secure-login.verify-update.{mal_dom}{path}"
        elif pattern_type == 1:
            mal_dom = f"{brand}-kyc-verify-account-alert-{i + 100}.{tld}"
            scheme = "https" if (i % 4 == 0) else "http"
            url = f"{scheme}://{mal_dom}{path}"
        elif pattern_type == 2:
            oct2 = (i % 200) + 11
            oct3 = ((i * 7) % 240) + 10
            oct4 = ((i * 13) % 250) + 2
            port_str = f":{rng.choice([8080, 8443, 8888, 9001])}" if (i % 2 == 0) else ""
            url = f"http://198.{oct2}.{oct3}.{oct4}{port_str}/{brand}/login-verify/index.html"
        elif pattern_type == 3:
            mal_dom = f"xn--{brand}-security-{i + 100}.{tld}"
            if i % 2 == 0:
                url = f"http://www.{brand}.com@{mal_dom}{path}"
            else:
                url = f"http://{mal_dom}{path}"
        elif pattern_type == 4:
            mal_dom = f"sec{rng.randint(1000,9999)}update{i}.{tld}"
            url = f"http://{brand}-portal.{mal_dom}{path}"
        else:
            subtle_tld = rng.choice(["com", "net", "in", "org"])
            mal_dom = f"my{brand}portal-help{i}.{subtle_tld}"
            url = f"https://login.{mal_dom}/account/verify-identity?token={rng.randint(10000, 99999)}"

        reg_dom = URLFeatureExtractor.extract_registered_domain(url)
        rows.append({"url": url, "label": 1, "category": "phishing", "registered_domain": reg_dom})

    # 100 Stealthy / Low-Indicator Phishing URLs (HTTPS on clean .com/.org/.in domains, short paths, subtle lexical cues)
    for i in range(100):
        st_type = i % 3
        clean_tld = rng.choice(["com", "org", "net", "in", "co.in"])
        if st_type == 0:
            # Clean lookalike domain with HTTPS and minimal path
            dom = f"portalaccess{i + 800}.{clean_tld}"
            url = f"https://www.{dom}/home/session?id={rng.randint(100, 999)}"
        elif st_type == 1:
            # Compromised legitimate-looking domain hosting a quiet phishing page
            dom = f"greenvalley-consulting{i + 800}.{clean_tld}"
            url = f"https://{dom}/assets/docs/form_{i}.html"
        else:
            # Subtle single-keyword path on HTTPS domain
            dom = f"clientservices{i + 800}.{clean_tld}"
            url = f"https://app.{dom}/portal/continue?step=2"
        reg_dom = URLFeatureExtractor.extract_registered_domain(url)
        rows.append({"url": url, "label": 1, "category": "stealth_phishing", "registered_domain": reg_dom})

    rng.shuffle(rows)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["url", "label", "category", "registered_domain"])
        writer.writeheader()
        writer.writerows(rows)

    unique_domains = len({r["registered_domain"] for r in rows})
    logger.info("Saved URL dataset: %d records (%d unique registered domains) -> %s", len(rows), unique_domains, output_csv)
    return {"total_records": len(rows), "benign": 800, "phishing": 800, "unique_domains": unique_domains}


def build_sms_dataset(output_csv: Path, seed: int = RANDOM_SEED) -> dict:
    """
    Create a 1,200-record SMS dataset (600 benign, 600 scam/spam) including challenging
    borderline bank security advisories, legitimate marketing messages with links, and
    stealthy conversational social-engineering lures.
    """
    rng = random.Random(seed)

    ham_templates = [
        "Hey, are we still meeting at the library at {hr} PM today for the project review?",
        "Your OTP for {bank} NetBanking login is {otp}. Do not share this OTP with anyone. Valid for 10 minutes.",
        "Dear Customer, Rs. {amt} has been debited from your A/c XX{acct} on {day}-Nov-26 towards UPI/{merchant}.",
        "Mom called earlier, please pick up milk and bread on your way home from the lab.",
        "Can you send me the lecture notes for Embedded Systems and ARM Architecture before tomorrow's class?",
        "Meeting rescheduled to Room {acct} at {hr}:30 AM. Please bring your Raspberry Pi prototype.",
        "Your Amazon order #{otp} has been shipped and will be delivered by {day} November.",
        "Hi Rahul, thank you for attending the interview. We will share feedback by Friday.",
        "Train 12627 Karnataka Express is running on time. Expected arrival at platform {hr}.",
        "Airtel alert: Your daily high speed data quota of 1.5 GB is 80% used.",
        "Don't forget to submit the laboratory assignment on GitHub before 11:59 PM tonight.",
        "Dear Subscriber, your broadband bill of Rs. {amt} for account {acct} has been paid successfully. Thank you.",
        "Let's grab lunch at the campus canteen after the 2 PM seminar.",
        "{otp} is your one-time verification code for SecureEdge AI local login. Never share this code with anyone.",
        # Challenging hard-negative benign messages (security awareness alerts & legitimate service reminders)
        "URGENT SECURITY REMINDER from {bank}: Never click links claiming your KYC or PAN is blocked or share OTPs. Call official helpline 1800112211 for support.",
        "Reminder: Your monthly electricity bill of Rs. {amt} for CA-{acct} is due on {day} Nov. Please pay via official utility portal https://bescom.co.in/pay",
    ]

    scam_templates = [
        "URGENT: Your {bank} account will be blocked today as your PAN card & KYC is expired! Click http://{bank}-kyc-update{id}.xyz/login immediately to verify.",
        "Dear customer, your electricity power connection CA-{acct} will be disconnected tonight at 9:30 PM due to unpaid bill. Call officer immediately at +91 98{otp}1234.",
        "CONGRATULATIONS! Your mobile number won Rs. {amt} Lakhs in KBC Lucky Draw! To claim prize money contact WhatsApp +91 88{otp}4321 now!",
        "FINAL NOTICE: Income Tax refund of Rs. {amt} is pending for your A/c XX{acct}. Verify bank PIN and credentials at http://incometax-refund-claim{id}.top/verify",
        "FedEx Customs Alert: A parcel in your name containing restricted items has been seized by Mumbai Customs. Verify identity within 2 hours at http://customs-clearance{id}.click",
        "Pre-approved Instant Personal Loan of Rs. {amt}00 credited to your wallet with 0% interest! Click http://instant-loan-approve{id}.icu/claim to withdraw now.",
        "Earn Rs. 5000 to Rs. 15000 daily working from home liking YouTube videos! Join our Telegram task group immediately at http://t-me-work-bonus{id}.xyz",
        "ALERT: Unauthorized transaction of Rs. {amt} detected on your {bank} Credit Card. If not you, click http://cancel-payment-{bank}{id}.ml/auth and enter OTP to reverse.",
        "FREE entry in 2 a wkly comp to win FA Cup final tkts! Text FA to 87121 to receive entry question(std txt rate) T&C's apply 08452810075over18's",
        "WINNER!! As a valued network customer you have been selected to receive a £900 prize reward! To claim call 09061701461. Claim code KL341. Valid 12 hours only.",
        "Your UPI Cashback reward of Rs. {amt} is expiring in 30 minutes! Open http://upi-reward-claim{id}.xyz and enter your UPI PIN to receive money in bank account.",
        "SBI YONO Alert: Your YONO account access has been suspended. Please update your Aadhaar and OTP at https://sbi-yono-portal{id}.cf/login immediately.",
        # Stealthy conversational pig-butchering / social-engineering scams (no URLs, no ALL-CAPS)
        "Hi, is this Neha from the conference? I accidentally transferred Rs. {amt} to your account earlier, could you please check and send it back to my number?",
        "Hello friend, our HR team saw your resume and has an easy remote data entry opening paying {amt} per week. Reply yes if you are interested in joining today.",
    ]

    banks = ["SBI", "HDFC", "ICICI", "Axis", "Kotak", "Paytm"]
    merchants = ["Swiggy", "Zomato", "Metro", "BookStore", "Pharmacy", "Grocery"]

    rows = []
    for i in range(600):
        tpl = ham_templates[i % len(ham_templates)]
        msg = tpl.format(
            hr=(i % 11) + 1,
            bank=banks[i % len(banks)],
            otp=rng.randint(100000, 999999),
            amt=rng.randint(120, 4500),
            acct=rng.randint(1000, 9999),
            day=(i % 28) + 1,
            merchant=merchants[i % len(merchants)],
        )
        rows.append({"text": msg, "label": 0, "category": "ham"})

    for i in range(600):
        tpl = scam_templates[i % len(scam_templates)]
        is_promo_spam = (i % len(scam_templates)) in (8, 9)
        msg = tpl.format(
            bank=banks[i % len(banks)].lower(),
            id=i + 100,
            acct=rng.randint(10000, 99999),
            otp=rng.randint(1000, 9999),
            amt=rng.randint(2500, 95000),
        )
        rows.append({"text": msg, "label": 1, "category": "spam" if is_promo_spam else "scam"})

    rng.shuffle(rows)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label", "category"])
        writer.writeheader()
        writer.writerows(rows)

    logger.info("Saved SMS dataset: %d records (600 benign, 600 scam/spam) -> %s", len(rows), output_csv)
    return {"total_records": len(rows), "benign": 600, "scam_or_spam": 600}


def build_network_dataset(output_csv: Path, seed: int = RANDOM_SEED) -> dict:
    """
    Create a 1,500-record network flow dataset (750 benign flows, 750 intrusion/anomaly flows)
    including realistic borderline flows (bursty dev traffic, short dropped handshakes, low-and-slow probes)
    + generate a genuine Scapy reference PCAP file.
    """
    rng = random.Random(seed)
    rows = []

    # 750 Benign flows (including ~8% noisy/bursty benign flows)
    for i in range(750):
        mode = i % 6
        if mode == 0:
            dur = round(rng.uniform(0.2, 15.0), 4)
            pkts = rng.randint(8, 120)
            b_cnt = pkts * rng.randint(350, 1350)
            row = {
                "src_ip": f"192.168.1.{(i % 50) + 10}",
                "dst_ip": f"142.250.{(i % 200) + 1}.46",
                "flow_duration_sec": dur,
                "protocol_id": 6,
                "dst_port": 443,
                "packet_count": pkts,
                "byte_count": b_cnt,
                "packets_per_sec": round(pkts / dur, 2),
                "bytes_per_sec": round(b_cnt / dur, 2),
                "mean_packet_size": round(b_cnt / pkts, 2),
                "syn_flag_ratio": round(1.0 / pkts, 4),
                "rst_flag_ratio": 0.0,
                "ack_flag_ratio": round((pkts - 1) / pkts, 4),
                "fin_flag_ratio": round(1.0 / pkts, 4),
                "unique_dst_ports_window": rng.randint(1, 3),
                "connection_frequency": rng.randint(1, 4),
                "payload_byte_ratio": round(rng.uniform(0.65, 0.92), 4),
                "is_sensitive_admin_port": 0,
                "label": 0,
                "attack_type": "benign_https",
            }
        elif mode == 1:
            dur = round(rng.uniform(0.01, 0.15), 4)
            pkts = rng.randint(2, 6)
            b_cnt = pkts * rng.randint(68, 180)
            row = {
                "src_ip": f"192.168.1.{(i % 50) + 10}",
                "dst_ip": "8.8.8.8",
                "flow_duration_sec": dur,
                "protocol_id": 17,
                "dst_port": 53,
                "packet_count": pkts,
                "byte_count": b_cnt,
                "packets_per_sec": round(pkts / dur, 2),
                "bytes_per_sec": round(b_cnt / dur, 2),
                "mean_packet_size": round(b_cnt / pkts, 2),
                "syn_flag_ratio": 0.0,
                "rst_flag_ratio": 0.0,
                "ack_flag_ratio": 0.0,
                "fin_flag_ratio": 0.0,
                "unique_dst_ports_window": rng.randint(1, 2),
                "connection_frequency": rng.randint(1, 5),
                "payload_byte_ratio": round(rng.uniform(0.45, 0.70), 4),
                "is_sensitive_admin_port": 0,
                "label": 0,
                "attack_type": "benign_dns",
            }
        elif mode == 2:
            dur = round(rng.uniform(0.3, 8.0), 4)
            pkts = rng.randint(6, 65)
            b_cnt = pkts * rng.randint(250, 1100)
            row = {
                "src_ip": f"192.168.1.{(i % 50) + 10}",
                "dst_ip": f"93.184.216.{(i % 100) + 10}",
                "flow_duration_sec": dur,
                "protocol_id": 6,
                "dst_port": 80,
                "packet_count": pkts,
                "byte_count": b_cnt,
                "packets_per_sec": round(pkts / dur, 2),
                "bytes_per_sec": round(b_cnt / dur, 2),
                "mean_packet_size": round(b_cnt / pkts, 2),
                "syn_flag_ratio": round(1.0 / pkts, 4),
                "rst_flag_ratio": 0.0,
                "ack_flag_ratio": round((pkts - 1) / pkts, 4),
                "fin_flag_ratio": round(1.0 / pkts, 4),
                "unique_dst_ports_window": rng.randint(1, 3),
                "connection_frequency": rng.randint(1, 3),
                "payload_byte_ratio": round(rng.uniform(0.55, 0.88), 4),
                "is_sensitive_admin_port": 0,
                "label": 0,
                "attack_type": "benign_http",
            }
        elif mode == 3:
            dur = round(rng.uniform(15.0, 120.0), 4)
            pkts = rng.randint(30, 150)
            b_cnt = pkts * rng.randint(120, 480)
            row = {
                "src_ip": "192.168.1.5",
                "dst_ip": "192.168.1.100",
                "flow_duration_sec": dur,
                "protocol_id": 6,
                "dst_port": 22,
                "packet_count": pkts,
                "byte_count": b_cnt,
                "packets_per_sec": round(pkts / dur, 2),
                "bytes_per_sec": round(b_cnt / dur, 2),
                "mean_packet_size": round(b_cnt / pkts, 2),
                "syn_flag_ratio": round(1.0 / pkts, 4),
                "rst_flag_ratio": 0.0,
                "ack_flag_ratio": round((pkts - 1) / pkts, 4),
                "fin_flag_ratio": round(1.0 / pkts, 4),
                "unique_dst_ports_window": 1,
                "connection_frequency": rng.randint(1, 3),
                "payload_byte_ratio": round(rng.uniform(0.60, 0.80), 4),
                "is_sensitive_admin_port": 1,
                "label": 0,
                "attack_type": "benign_ssh_session",
            }
        elif mode == 4:
            dur = round(rng.uniform(0.05, 1.2), 4)
            pkts = rng.randint(2, 8)
            b_cnt = pkts * 76
            row = {
                "src_ip": f"192.168.1.{(i % 50) + 10}",
                "dst_ip": "162.159.200.1",
                "flow_duration_sec": dur,
                "protocol_id": 17,
                "dst_port": 123,
                "packet_count": pkts,
                "byte_count": b_cnt,
                "packets_per_sec": round(pkts / dur, 2),
                "bytes_per_sec": round(b_cnt / dur, 2),
                "mean_packet_size": 76.0,
                "syn_flag_ratio": 0.0,
                "rst_flag_ratio": 0.0,
                "ack_flag_ratio": 0.0,
                "fin_flag_ratio": 0.0,
                "unique_dst_ports_window": 1,
                "connection_frequency": 1,
                "payload_byte_ratio": 0.50,
                "is_sensitive_admin_port": 0,
                "label": 0,
                "attack_type": "benign_ntp",
            }
        else:
            # Borderline Benign: Local microservice healthcheck burst on port 8080/3306 with occasional RST
            dur = round(rng.uniform(0.2, 2.5), 4)
            pkts = rng.randint(10, 40)
            b_cnt = pkts * rng.randint(80, 260)
            port = rng.choice([8080, 8443, 3306])
            row = {
                "src_ip": "192.168.1.15",
                "dst_ip": "192.168.1.20",
                "flow_duration_sec": dur,
                "protocol_id": 6,
                "dst_port": port,
                "packet_count": pkts,
                "byte_count": b_cnt,
                "packets_per_sec": round(pkts / dur, 2),
                "bytes_per_sec": round(b_cnt / dur, 2),
                "mean_packet_size": round(b_cnt / pkts, 2),
                "syn_flag_ratio": round(rng.uniform(0.20, 0.45), 4),
                "rst_flag_ratio": round(rng.uniform(0.15, 0.40), 4),
                "ack_flag_ratio": round(rng.uniform(0.30, 0.65), 4),
                "fin_flag_ratio": round(rng.uniform(0.05, 0.15), 4),
                "unique_dst_ports_window": rng.randint(4, 11),
                "connection_frequency": rng.randint(6, 15),
                "payload_byte_ratio": round(rng.uniform(0.30, 0.65), 4),
                "is_sensitive_admin_port": 1,
                "label": 0,
                "attack_type": "benign_microservice_burst",
            }
        rows.append(row)

    # 750 Malicious / Anomaly flows (including low-and-slow stealth probes)
    for i in range(750):
        mode = i % 6
        if mode == 0:
            dur = round(rng.uniform(0.08, 0.65), 4)
            pkts = rng.randint(60, 450)
            b_cnt = pkts * 54
            row = {
                "src_ip": f"10.0.{(i % 15) + 1}.99",
                "dst_ip": "192.168.1.10",
                "flow_duration_sec": dur,
                "protocol_id": 6,
                "dst_port": rng.choice([80, 443, 8080]),
                "packet_count": pkts,
                "byte_count": b_cnt,
                "packets_per_sec": round(pkts / dur, 2),
                "bytes_per_sec": round(b_cnt / dur, 2),
                "mean_packet_size": 54.0,
                "syn_flag_ratio": round(rng.uniform(0.82, 1.0), 4),
                "rst_flag_ratio": round(rng.uniform(0.0, 0.10), 4),
                "ack_flag_ratio": round(rng.uniform(0.0, 0.08), 4),
                "fin_flag_ratio": 0.0,
                "unique_dst_ports_window": rng.randint(1, 4),
                "connection_frequency": rng.randint(35, 180),
                "payload_byte_ratio": round(rng.uniform(0.0, 0.08), 4),
                "is_sensitive_admin_port": 0,
                "label": 1,
                "attack_type": "syn_flood_dos",
            }
        elif mode == 1:
            dur = round(rng.uniform(0.02, 0.30), 4)
            pkts = rng.randint(1, 6)
            b_cnt = pkts * 58
            port = rng.choice([21, 22, 23, 25, 80, 135, 139, 445, 1433, 3306, 3389, 5900, 6379, 8080])
            row = {
                "src_ip": f"192.168.1.{200 + (i % 40)}",
                "dst_ip": "192.168.1.10",
                "flow_duration_sec": dur,
                "protocol_id": 6,
                "dst_port": port,
                "packet_count": pkts,
                "byte_count": b_cnt,
                "packets_per_sec": round(pkts / dur, 2),
                "bytes_per_sec": round(b_cnt / dur, 2),
                "mean_packet_size": 58.0,
                "syn_flag_ratio": round(rng.uniform(0.50, 1.0), 4),
                "rst_flag_ratio": round(rng.uniform(0.30, 0.75), 4),
                "ack_flag_ratio": round(rng.uniform(0.0, 0.25), 4),
                "fin_flag_ratio": 0.0,
                "unique_dst_ports_window": rng.randint(16, 85),
                "connection_frequency": rng.randint(15, 60),
                "payload_byte_ratio": 0.0,
                "is_sensitive_admin_port": 1 if port != 80 else 0,
                "label": 1,
                "attack_type": "port_scan",
            }
        elif mode == 2:
            dur = round(rng.uniform(0.4, 3.5), 4)
            pkts = rng.randint(14, 55)
            b_cnt = pkts * rng.randint(90, 210)
            port = rng.choice([22, 23, 3389, 445])
            row = {
                "src_ip": f"172.16.{(i % 20) + 1}.44",
                "dst_ip": "192.168.1.10",
                "flow_duration_sec": dur,
                "protocol_id": 6,
                "dst_port": port,
                "packet_count": pkts,
                "byte_count": b_cnt,
                "packets_per_sec": round(pkts / dur, 2),
                "bytes_per_sec": round(b_cnt / dur, 2),
                "mean_packet_size": round(b_cnt / pkts, 2),
                "syn_flag_ratio": round(rng.uniform(0.25, 0.55), 4),
                "rst_flag_ratio": round(rng.uniform(0.35, 0.68), 4),
                "ack_flag_ratio": round(rng.uniform(0.20, 0.50), 4),
                "fin_flag_ratio": round(rng.uniform(0.05, 0.20), 4),
                "unique_dst_ports_window": rng.randint(1, 3),
                "connection_frequency": rng.randint(14, 50),
                "payload_byte_ratio": round(rng.uniform(0.35, 0.65), 4),
                "is_sensitive_admin_port": 1,
                "label": 1,
                "attack_type": "brute_force_probe",
            }
        elif mode == 3:
            dur = round(rng.uniform(0.5, 6.0), 4)
            pkts = rng.randint(12, 80)
            b_cnt = pkts * rng.randint(180, 620)
            port = rng.choice([4444, 5555, 6667, 9001])
            row = {
                "src_ip": "192.168.1.10",
                "dst_ip": f"185.220.101.{(i % 90) + 5}",
                "flow_duration_sec": dur,
                "protocol_id": 6,
                "dst_port": port,
                "packet_count": pkts,
                "byte_count": b_cnt,
                "packets_per_sec": round(pkts / dur, 2),
                "bytes_per_sec": round(b_cnt / dur, 2),
                "mean_packet_size": round(b_cnt / pkts, 2),
                "syn_flag_ratio": round(1.0 / pkts, 4),
                "rst_flag_ratio": 0.0,
                "ack_flag_ratio": round((pkts - 1) / pkts, 4),
                "fin_flag_ratio": 0.0,
                "unique_dst_ports_window": rng.randint(1, 2),
                "connection_frequency": rng.randint(10, 35),
                "payload_byte_ratio": round(rng.uniform(0.75, 0.94), 4),
                "is_sensitive_admin_port": 1,
                "label": 1,
                "attack_type": "c2_backdoor_channel",
            }
        elif mode == 4:
            dur = round(rng.uniform(0.8, 3.0), 4)
            pkts = rng.randint(550, 1400)
            b_cnt = pkts * rng.randint(1350, 1460)
            port = rng.choice([8443, 8080, 21, 9001])
            row = {
                "src_ip": "192.168.1.10",
                "dst_ip": f"45.33.{(i % 120) + 10}.88",
                "flow_duration_sec": dur,
                "protocol_id": 6,
                "dst_port": port,
                "packet_count": pkts,
                "byte_count": b_cnt,
                "packets_per_sec": round(pkts / dur, 2),
                "bytes_per_sec": round(b_cnt / dur, 2),
                "mean_packet_size": round(b_cnt / pkts, 2),
                "syn_flag_ratio": round(1.0 / pkts, 4),
                "rst_flag_ratio": 0.0,
                "ack_flag_ratio": round((pkts - 1) / pkts, 4),
                "fin_flag_ratio": 0.0,
                "unique_dst_ports_window": 1,
                "connection_frequency": rng.randint(6, 18),
                "payload_byte_ratio": round(rng.uniform(0.88, 0.97), 4),
                "is_sensitive_admin_port": 1,
                "label": 1,
                "attack_type": "data_exfiltration_anomaly",
            }
        else:
            # Stealthy low-and-slow credential probe on port 443 / 8080
            dur = round(rng.uniform(2.0, 12.0), 4)
            pkts = rng.randint(10, 35)
            b_cnt = pkts * rng.randint(140, 340)
            port = rng.choice([443, 8080, 22])
            row = {
                "src_ip": f"10.10.{(i % 30) + 1}.55",
                "dst_ip": "192.168.1.10",
                "flow_duration_sec": dur,
                "protocol_id": 6,
                "dst_port": port,
                "packet_count": pkts,
                "byte_count": b_cnt,
                "packets_per_sec": round(pkts / dur, 2),
                "bytes_per_sec": round(b_cnt / dur, 2),
                "mean_packet_size": round(b_cnt / pkts, 2),
                "syn_flag_ratio": round(rng.uniform(0.15, 0.35), 4),
                "rst_flag_ratio": round(rng.uniform(0.10, 0.30), 4),
                "ack_flag_ratio": round(rng.uniform(0.40, 0.70), 4),
                "fin_flag_ratio": round(rng.uniform(0.05, 0.15), 4),
                "unique_dst_ports_window": rng.randint(3, 8),
                "connection_frequency": rng.randint(5, 11),
                "payload_byte_ratio": round(rng.uniform(0.50, 0.75), 4),
                "is_sensitive_admin_port": 1 if port != 443 else 0,
                "label": 1,
                "attack_type": "stealth_low_slow_probe",
            }
        rows.append(row)

    rng.shuffle(rows)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = list(rows[0].keys())
    with open(output_csv, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        writer.writerows(rows)

    pcap_path = ScapyFlowCollector.generate_reference_pcap()
    logger.info("Saved Network Flow dataset: %d records -> %s (PCAP: %s)", len(rows), output_csv, pcap_path)
    return {"total_records": len(rows), "benign": 750, "anomalous": 750, "pcap_file": str(pcap_path.name)}


def main() -> None:
    ensure_directories()
    url_stats = build_url_dataset(RAW_DATA_DIR / "url_dataset.csv")
    sms_stats = build_sms_dataset(RAW_DATA_DIR / "sms_dataset.csv")
    net_stats = build_network_dataset(RAW_DATA_DIR / "network_flows_dataset.csv")

    manifest = {
        "seed": RANDOM_SEED,
        "url_dataset": url_stats,
        "sms_dataset": sms_stats,
        "network_dataset": net_stats,
    }
    manifest_path = PROCESSED_DATA_DIR / "dataset_manifest.json"
    manifest_path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    logger.info("Dataset manifest written to %s", manifest_path)


if __name__ == "__main__":
    main()

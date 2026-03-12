import whoisit
import pandas as pd
import numpy as np
from datetime import datetime
import socket
import ipinfo
import time
from urllib.parse import urlparse

df = pd.read_csv("../data/lexical_features.csv")
df = df.sample(n=2_000, random_state=42)

# Load API keys
def load_key(path):
    with open(path, "r") as f:
        return f.read().strip()

IPINFO_KEY = load_key("../keys/API_TOKEN.txt")
handler = ipinfo.getHandler(IPINFO_KEY)


def extract_domain(url):
    try:
        if not url.startswith(("http://", "https://")):
            url = "http://" + url
        parsed = urlparse(url)
        domain = parsed.netloc
        if domain.startswith("www."):
            domain = domain[4:]
        return domain if domain else None
    except Exception:
        return None

df["domain"] = df["url"].apply(extract_domain)
print(f"Domains extracted: {df['domain'].notna().sum()} / {len(df)}")


whoisit.bootstrap()  # load IANA bootstrap data once
whois_cache = {}

def get_domain_age(domain):
    if not domain:
        return -1
    if domain in whois_cache:
        return whois_cache[domain]
    try:
        r = whoisit.domain(domain)
        creation = r.get('registration_date')
        age = (datetime.now(creation.tzinfo) - creation).days if creation else -1
    except Exception:
        age = -1

    whois_cache[domain] = age
    time.sleep(0.1)
    return age

df["domain_age_days"] = df["domain"].apply(get_domain_age)
print(f"WHOIS done. Non-(-1) results: {(df['domain_age_days'] != -1).sum()}")


def resolve_ip(domain):
    if not domain:
        return None
    try:
        return socket.gethostbyname(domain)
    except Exception:
        return None

df["ip"] = df["domain"].apply(resolve_ip)
print(f"IPs resolved: {df['ip'].notna().sum()} / {len(df)}")


from concurrent.futures import ThreadPoolExecutor, as_completed

def get_ip_osint(ip):
    if not ip:
        return (None, None, None)
    try:
        details = handler.getDetails(ip)
        return (details.org, details.country, details.region)
    except Exception:
        return (None, None, None)

ips = df["ip"].tolist()
results = [None] * len(ips)

with ThreadPoolExecutor(max_workers=20) as executor:
    future_to_idx = {executor.submit(get_ip_osint, ip): i for i, ip in enumerate(ips)}
    for future in as_completed(future_to_idx):
        i = future_to_idx[future]
        results[i] = future.result()

df["asn_org"]  = [r[0] for r in results]
df["country"]  = [r[1] for r in results]
df["region"]   = [r[2] for r in results]
print(f"IPInfo done. ASN results: {df['asn_org'].notna().sum()} / {len(df)}")


df["is_dga_like"] = (df["domain_entropy"] > 3.8).astype(int)

df["suspicious_domain"] = (
    (df["domain_age_days"] >= 0) &   # only flag when WHOIS data is available
    (df["domain_age_days"] < 30) &
    (df["is_dga_like"] == 1)
).astype(int)


from pathlib import Path

output_file = Path("../data/Passive_features.csv")
if output_file.exists():
    output_file.unlink()

df.to_csv(output_file, index=False)
print(f"Saved to {output_file}  |  shape: {df.shape}")
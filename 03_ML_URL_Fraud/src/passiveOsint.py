import whoisit
import pandas as pd
import numpy as np
from datetime import datetime
import socket
import ipinfo
import vt
import time

df = pd.read_csv("../data/lexical_features.csv")
df = df.sample(n=2_000, random_state=42)

#load API keys

def load_key(path):
    with open(path, "r") as f:
        return f.read().strip()

IPINFO_KEY = load_key("../keys/API_TOKEN.txt")
VT_API_KEY = load_key("../keys/VT_API.txt")

handler = ipinfo.getHandler(IPINFO_KEY)
client = vt.Client(VT_API_KEY)


# WHOIS domain age

whois_cache = {}

def get_domain_age(domain):
    if domain in whois_cache:
        return whois_cache[domain]

    try:
        w = whois.whois(domain)
        creation = w.creation_date
        if isinstance(creation, list):
            creation = creation[0]
        age = (datetime.now() - creation).days if creation else -1
    except Exception:
        age = -1

    whois_cache[domain] = age
    time.sleep(0.1)
    return age

df["domain_age_days"] = df["domain"].apply(get_domain_age)


# DNS -→ IP

def resolve_ip(domain):
    try:
        return socket.gethostbyname(domain)
    except:
        return None

df["ip"] = df["domain"].apply(resolve_ip)

# IP OSINT

def get_ip_osint(ip):
    if not ip:
        return pd.Series([None, None, None])
    try:
        details = handler.getDetails(ip)
        return pd.Series([details.org, details.country, details.region])
    except:
        return pd.Series([None, None, None])

df[["asn_org", "country", "region"]] = df["ip"].apply(get_ip_osint)


# VirusTotal : the key limit to amount of data 

vt_cache = {}

def vt_domain_score(domain):
    if domain in vt_cache:
        return vt_cache[domain]

    try:
        obj = client.get_object(f"/domains/{domain}")
        stats = obj.last_analysis_stats
        result = (stats["malicious"], stats["suspicious"])

    except vt.error.APIError as e:
        print(f"[VT ERROR] {domain}: {e.code} - {e}")  # see what's actually failing
        if e.code == "NotFoundError":
            result = (0, 0) 
        else:
            result = (-1, -1)

    except Exception as e:
        print(f"[UNEXPECTED] {domain}: {e}")
        result = (-1, -1)

    vt_cache[domain] = result
    time.sleep(15)  
    return result

# Derived intelligence

df["is_dga_like"] = (df["domain_entropy"] > 3.8).astype(int)

df["suspicious_domain"] = (
    (df["domain_age_days"] < 30) &
    (df["is_dga_like"] == 1)
).astype(int)



from pathlib import Path


output_file = Path("../data/Passive_features.csv")

if output_file.exists():
    output_file.unlink()

# Save the new file
df.to_csv(output_file, index=False)


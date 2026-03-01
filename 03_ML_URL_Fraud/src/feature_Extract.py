import ssl
import socket
import json
import time
import logging
from pathlib import Path
from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import dns.resolver
import dns.exception
import tldextract
import ipinfo
import pandas as pd


INPUT_CSV  = "../data/lexical_features.csv"
OUTPUT_CSV = "../data/cyber_features.csv"
CACHE_FILE  = "../data/cyber_cache.json"
IPINFO_KEY  = open("../keys/API_TOKEN.txt").read().strip()

MAX_WORKERS = 20 # to run in parallel to reduce run time 
DNS_TIMEOUT = 3       
TLS_TIMEOUT = 4       

CLOUDFLARE_ORGS = {"cloudflare"}
HOSTING_KEYWORDS = {"amazonaws", "digitalocean", "linode", "vultr", "ovh",
                    "hetzner", "hostgator", "bluehost", "namecheap", "godaddy"}

HIGH_RISK_ASNS = {"as3267", "as9009", "as59796", "as204655", "as48721"}

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")
log = logging.getLogger(__name__)

def load_cache(path: str) -> dict:
    p = Path(path)
    if p.exists():
        try:
            return json.loads(p.read_text())
        except Exception:
            return {}
    return {}

def save_cache(cache: dict, path: str):
    Path(path).write_text(json.dumps(cache, indent=2))

#extract registered domain from any URL format
def extract_domain(url: str) -> str:
    if not isinstance(url, str):
        return ""
    ext = tldextract.extract(url)
    if ext.domain and ext.suffix:
        return f"{ext.domain}.{ext.suffix}"
    return ext.domain or "" # fallback padding to prevent NONE

# this is for DNS lookup extracting hostname and subdomains
def extract_fqdn(url: str) -> str:
    ext = tldextract.extract(url)
    parts = [p for p in [ext.subdomain, ext.domain, ext.suffix] if p]
    return ".".join(parts)

def get_dns_features(fqdn: str) -> dict:
    features = {
        "has_a_record":0,
        "a_record_count":0,
        "resolved_ip":None,
        "has_mx_record":0,
        "ns_count":0,
        "min_ttl":-1,
        "uses_cloudflare":0,
    }
    if not fqdn:
        return features

    resolver = dns.resolver.Resolver()
    resolver.lifetime = DNS_TIMEOUT

#? A record
    try:
        a_ans = resolver.resolve(fqdn, "A")
        ips = [r.address for r in a_ans]
        features["has_a_record"]= 1
        features["a_record_count"] = len(ips)
        features["resolved_ip"] = ips[0] if ips else None
        features["min_ttl"]= a_ans.rrset.ttl if a_ans.rrset else -1
    except Exception:
        pass

#? MX record
    try:
        mx_ans = resolver.resolve(fqdn, "MX")
        features["has_mx_record"] = 1 if mx_ans else 0
    except Exception:
        pass

#? NS record
    try:
        ns_ans = resolver.resolve(fqdn, "NS")
        ns_names = [str(r.target).lower() for r in ns_ans]
        features["ns_count"] = len(ns_names)
        features["uses_cloudflare"] = int(
            any("cloudflare" in ns for ns in ns_names)
        )
    except Exception:
        pass

    return features

def get_cert_features(fqdn: str) -> dict:
    features = {
        "has_https":0,
        "cert_age_days":-1,
        "cert_days_until_expiry":-1,
        "is_self_signed":0,
        "issuer_is_letsencrypt":0,
        "is_wildcard_cert":0,
        "issuer_org":None,
    }
    if not fqdn:
        return features

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE # we still inspect even bad certs

    try:
        with socket.create_connection((fqdn, 443), timeout=TLS_TIMEOUT) as sock:
            with ctx.wrap_socket(sock, server_hostname=fqdn) as ssock:
                cert = ssock.getpeercert()

        if not cert:
            return features

        features["has_https"] = 1

        # Parse not_before / not_after
        fmt = "%b %d %H:%M:%S %Y %Z" #? EX -> "Jan  5 12:00:00 2024 GMT"
        now = datetime.now(timezone.utc)

        not_before_str = cert.get("notBefore", "")
        not_after_str  = cert.get("notAfter", "")

        if not_before_str:
            not_before = datetime.strptime(not_before_str, fmt).replace(tzinfo=timezone.utc)
            features["cert_age_days"] = (now - not_before).days

        if not_after_str:
            not_after = datetime.strptime(not_after_str, fmt).replace(tzinfo=timezone.utc)
            features["cert_days_until_expiry"] = (not_after - now).days

        # Issuer
        issuer = dict(x[0] for x in cert.get("issuer", []))
        org = issuer.get("organizationName", "") or ""
        features["issuer_org"] = org
        features["is_self_signed"] = int(
            issuer.get("commonName", "") == dict(x[0] for x in cert.get("subject", [])).get("commonName", "X")
        )
        features["issuer_is_letsencrypt"] = int("let's encrypt" in org.lower())

        # Wildcard check via SAN or subject CN
        subject = dict(x[0] for x in cert.get("subject", []))
        cn = subject.get("commonName", "")
        san_list = [v for (k, v) in cert.get("subjectAltName", []) if k == "DNS"]
        all_names = [cn] + san_list
        features["is_wildcard_cert"] = int(any(n.startswith("*") for n in all_names))

    except Exception:
        pass  # domain just doesn't support HTTPS or timed out

    return features

# IP / ASN FEATURES 

_ipinfo_handler = ipinfo.getHandler(IPINFO_KEY)

def get_ip_asn_features(ip: str) -> dict:
    features = {
        "asn_org":               None,
        "country_code":          None,
        "region":                None,
        "is_hosting_provider":   0,
        "is_high_risk_asn":      0,
        "is_cloudflare_ip":      0,
    }
    if not ip:
        return features

    try:
        details = _ipinfo_handler.getDetails(ip)
        org = getattr(details, "org", "") or ""
        features["asn_org"]      = org
        features["country_code"] = getattr(details, "country", None)
        features["region"]       = getattr(details, "region", None)

        org_lower = org.lower()
        asn = org_lower.split()[0] if org_lower else ""

        features["is_cloudflare_ip"]    = int("cloudflare" in org_lower)
        features["is_hosting_provider"] = int(
            any(kw in org_lower for kw in HOSTING_KEYWORDS)
        )
        features["is_high_risk_asn"]    = int(asn in HIGH_RISK_ASNS)
    except Exception:
        pass

    return features


def process_row(row_tuple: tuple, cache: dict) -> dict:
    idx, url = row_tuple
    domain = extract_domain(url)
    fqdn   = extract_fqdn(url)

    result = {"url": url, "domain_extracted": domain}

    cache_key = fqdn or domain
    if cache_key and cache_key in cache:
        return {**result, **cache[cache_key]}

    dns_feats  = get_dns_features(fqdn)
    cert_feats = get_cert_features(fqdn)
    resolved_ip = dns_feats.get("resolved_ip")
    if not resolved_ip and fqdn:
        try:
            resolved_ip = socket.gethostbyname(fqdn)
        except Exception:
            pass
    ipasn_feats = get_ip_asn_features(resolved_ip)

    combined = {**dns_feats, **cert_feats, **ipasn_feats}

    if cache_key:
        cache[cache_key] = combined

    return {**result, **combined}


def main():
    log.info("Loading dataset...")
    df = pd.read_csv(INPUT_CSV)
    log.info(f"Loaded {len(df)} rows")

    cache = load_cache(CACHE_FILE)
    log.info(f"Cache loaded: {len(cache)} existing entries")

    rows = list(enumerate(df["url"]))
    results = [None] * len(rows)
    completed = 0

    log.info(f"Starting parallel extraction with {MAX_WORKERS} workers...")

    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        future_to_idx = {
            executor.submit(process_row, row_tuple, cache): row_tuple[0]
            for row_tuple in rows
        }

        for future in as_completed(future_to_idx):
            idx = future_to_idx[future]
            try:
                results[idx] = future.result()
            except Exception as e:
                log.warning(f"Row {idx} failed: {e}")
                results[idx] = {"url": df["url"].iloc[idx]}

            completed += 1
            if completed % 500 == 0:
                log.info(f"Progress: {completed}/{len(rows)} done")
                save_cache(cache, CACHE_FILE)   # checkpoint every 500

    save_cache(cache, CACHE_FILE)
    log.info("Cache saved.")

    cyber_df = pd.DataFrame([r for r in results if r])
    out_df = df.merge(cyber_df, on="url", how="left")

    out_df.to_csv(OUTPUT_CSV, index=False)
    log.info(f"Done! Saved to {OUTPUT_CSV}")
    log.info(f"Output shape: {out_df.shape}")
    log.info(f"\nNew columns added:\n{[c for c in out_df.columns if c not in df.columns]}")

if __name__ == "__main__":
    main()
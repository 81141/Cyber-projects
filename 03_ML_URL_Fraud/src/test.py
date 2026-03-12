import whois

domain_name = "google.com"
try:
    whois_info = whois.query(domain_name)
    print(whois_info)
except Exception as e:
    print(f"Error retrieving WHOIS information: {e}")

# services/url_service.py
import re
import whois
from urllib.parse import urlparse, urljoin
from typing import Dict, Any, List
import socket
import ssl
from datetime import datetime
from app.models.constant import IST
import dns.resolver
import httpx
import asyncio
import pickle
import numpy as np
from pathlib import Path
import requests
from bs4 import BeautifulSoup
import csv
import os
from app.config import settings
from app.services.abnormal_url_feature_extraction import extract_abnormal_url_features
class URLPhishingDetector:
    def __init__(self, model_path: str = "app/ml_models/xgb_phishing_model.pkl", phishtank_path: str = "verified_online.csv", vt_api_key: str = None, opr_api_key: str = None):
        """Initialize the detector with trained XGBoost model and phishtank set"""
        self.known_phishing_domains = set()
        self.model = None
        self.model_path = model_path
        self.phishtank_path = phishtank_path
        self.vt_api_key = vt_api_key or settings.VT_API_KEY
        self.opr_api_key = opr_api_key or settings.OPR_API_KEY
        self.load_model()
        self.load_phishtank_urls()
    def load_model(self):
        """Load the trained XGBoost model"""
        try:
            model_file = Path(self.model_path)
            if model_file.exists():
                with open(self.model_path, 'rb') as f:
                    self.model = pickle.load(f)
                print("XGBoost model loaded successfully")
            else:
                print(f"Model file not found at {self.model_path}")
        except Exception as e:
            print(f"Error loading model: {e}")
            self.model = None
    def load_phishtank_urls(self):
        self.phishing_set = set()
        try:
            with open(self.phishtank_path, newline='', encoding='utf-8') as csvfile:
                reader = csv.DictReader(csvfile)
                for row in reader:
                    url = row['url'].strip().lower()
                    normalized = self.normalize_url(url)
                    self.phishing_set.add(normalized)
        except Exception as e:
            print(f"Error loading phishtank: {e}")

    def normalize_url(self, url: str) -> str:
        """Normalize URL for comparison"""
        url = url.lower().strip()
        # Remove protocol
        if url.startswith(('http://', 'https://')):
            url = url.split('://', 1)[1]
        # Remove www
        if url.startswith('www.'):
            url = url[4:]
        # Remove trailing slash
        url = url.rstrip('/')
        return url
    def check_phishtank(self, url: str) -> str:
        normalized_url = self.normalize_url(url)

        # Exact match first
        if normalized_url in self.phishing_set:
            return "Yes"
        
        for phish_url in self.phishing_set:
            if normalized_url == phish_url:
                return "Yes"
        return "No"
    
    def check_statistical_report_virustotal(self, url: str) -> str:
        import httpx
        import time
        if not self.vt_api_key:
            return "Unknown (No API Key)"
        headers = {"x-apikey": self.vt_api_key}
        scan_url = "https://www.virustotal.com/api/v3/urls"
        data = {"url": url}
        try:
            submit_response = httpx.post(scan_url, headers=headers, data=data)
            submit_response.raise_for_status()
            analysis_id = submit_response.json()["data"]["id"]
            report_url = f"https://www.virustotal.com/api/v3/analyses/{analysis_id}"
            for _ in range(6):  # Wait up to 1 minute
                report_response = httpx.get(report_url, headers=headers)
                report_response.raise_for_status()
                report_data = report_response.json()
                status = report_data["data"]["attributes"]["status"]
                if status == "completed":
                    break
                time.sleep(10)
            stats = report_data["data"]["attributes"]["stats"]
            malicious_count = stats.get("malicious", 0) + stats.get("phishing", 0)
            suspicious_count = stats.get("suspicious", 0)
            if malicious_count > 0 or suspicious_count > 0:
                return f"Malicious: {malicious_count}, Suspicious: {suspicious_count} (Blacklisted)"
            else:
                return "Clean"
        except Exception as e:
            return f"Error: {e}"
    def having_IP_Address(self, url: str) -> int:
        """Check if URL uses IP address instead of domain name"""
        return 1 if re.match(r"https?://(?:\d{1,3}\.){3}\d{1,3}", url) else -1
    def URL_Length(self, url: str) -> int:
        """Analyze URL length"""
        length = len(url)
        if length < 54:
            return -1  # Legitimate (short)
        elif length <= 75:
            return 0   # Suspicious (medium)
        else:
            return 1   # Phishing (long)
    def Shortining_Service(self, url: str) -> int:
        """Check if URL uses shortening service"""
        from urllib.parse import urlparse
        
        shortening_services = {
            'bit.ly', 'goo.gl', 'tinyurl.com', 'ow.ly', 
            'is.gd', 't.co', 'short.link', 'tiny.cc'
        }
        
        domain = urlparse(url).netloc.lower()
        return 1 if domain in shortening_services else -1

    def having_At_Symbol(self, url: str) -> int:
        """Check for @ symbol in URL"""
        return 1 if "@" in url else -1
    def double_slash_redirecting(self, url: str) -> int:
        """Check for double slash redirecting"""
        pos = url.find("//", 6)  # skip http:// or https://
        return 1 if pos > 6 else -1
    def Prefix_Suffix(self, url: str) -> int:
        """Check for prefix-suffix separated by dash in domain"""
        domain = urlparse(url).netloc
        if not domain:
            return -1
        # Convert to string if it's not already
        domain = str(domain)

        return 1 if '-' in domain else -1
    def having_Sub_Domain(self, url: str) -> int:
        """Check number of subdomains"""
        domain = urlparse(url).netloc
        if not domain:
            return 1
        
        # Convert to string if it's not already
        domain = str(domain)

        # Remove www. if present
        if domain.startswith('www.'):
            domain = domain[4:]
        dots = domain.count('.')
        if dots == 1:
            return -1  # Legitimate (domain.com)
        elif dots == 2:
            return 0   # Suspicious (sub.domain.com)
        else:
            return 1   # Phishing (multiple subdomains)
    def Domain_registeration_length(self, url: str) -> int:
        """Check domain registration length"""
        try:
            domain = urlparse(url).netloc
            if not domain:
                return 1
            
            domain = str(domain)

            if domain.startswith('www.'):
                domain = domain[4:]
            w = whois.whois(domain)
            exp = w.expiration_date
            create = w.creation_date
            # Handle list format
            if isinstance(exp, list):
                exp = exp[0]
            if isinstance(create, list):
                create = create[0]
            if exp and create and (exp - create).days >= 365:
                return -1  # Legitimate (registered for more than a year)
        except Exception as e:
            print(f"WHOIS lookup failed for domain: {e}")
        return 1  # Suspicious (short registration or failed lookup)
    def age_of_domain(self, url: str) -> int:
        """Check domain age - Modified: 1 for legitimate, -1 for suspicious"""
        try:
            domain = urlparse(url).netloc
            if not domain:
                return -1
   
            domain = str(domain)

            if domain.startswith('www.'):
                domain = domain[4:]
            w = whois.whois(domain)
            creation_date = w.creation_date
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            if creation_date:
                # Make sure creation_date is timezone-aware
                if creation_date.tzinfo is None:
                    # If the creation_date is naive, assume it's in UTC and make it aware
                    creation_date = creation_date.replace(tzinfo=IST)
                age_in_days = (datetime.now(IST) - creation_date).days
                if age_in_days >= 365:
                    return 1  # Legitimate (old domain)
                else:
                    return -1  # Suspicious (new domain)
        except Exception as e:
            print(f"Domain age lookup failed: {e}")
        return -1  # Suspicious if can't determine age
    def DNSRecord(self, url: str) -> int:
        """Check if domain has proper DNS records - Modified: 1 for legitimate, -1 for suspicious"""
        try:
            domain = urlparse(url).netloc
            if not domain:
                return -1
     
            domain = str(domain)

            if domain.startswith('www.'):
                domain = domain[4:]
            # Try to resolve A record
            dns.resolver.resolve(domain, 'A')
            return 1  # Legitimate (has DNS record)
        except Exception:
            return -1   # Suspicious (no DNS record)
    def get_tranco_rank(self, url: str) -> int:
        """Get Tranco rank using the official Tranco API"""
        try:
            # Extract domain without www.
            parsed_url = urlparse(url)
            domain = parsed_url.netloc
            if not domain:
                return None
            
            domain = str(domain)

            if domain.startswith("www."):
                domain = domain[4:]
            # Handle subdomains - try both subdomain and main domain
            original_domain = domain
            main_domain = None
            # Extract main domain for common subdomains like en.wikipedia.org -> wikipedia.org
            domain_parts = domain.split('.')
            if len(domain_parts) > 2:
                # For cases like en.wikipedia.org, try wikipedia.org
                main_domain = '.'.join(domain_parts[-2:])
            # Try original domain first, then main domain if it fails
            domains_to_try = [domain]
            if main_domain and main_domain != domain:
                domains_to_try.append(main_domain)
            for try_domain in domains_to_try:
                # Use Tranco API endpoint
                api_url = f"https://tranco-list.eu/api/ranks/domain/{try_domain}"
                headers = {
                    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
                    "Accept": "application/json"
                }
                try:
                    response = httpx.get(api_url, headers=headers, timeout=10.0)
                    response.raise_for_status()
                    data = response.json()
                    if "ranks" in data and data["ranks"]:
                        # Get the most recent rank
                        latest_rank = data["ranks"][-1]["rank"]
                        print(f"Tranco Rank for {latest_rank}")
                        return latest_rank
                except httpx.HTTPStatusError as e:
                    if e.response.status_code == 404:
                        continue  # Try next domain
                    else:
                        continue
                except Exception as e:
                    continue
            return None
        except Exception as e:
            print(f"Error getting Tranco rank: {e}")
            return None
    def web_traffic(self, url: str) -> int:
        """Web traffic analysis using Tranco API"""
        rank = self.get_tranco_rank(url)
        if rank is None:
            return -1  # Low or no traffic (domain not ranked)
        elif rank < 100000:
            return 1   # High traffic (rank < 100,000)
        else:
            return 0   # Suspicious / moderate traffic
    async def fetch_opr_rank(self, domain: str, api_key: str) -> dict:
        """Fetch OpenPageRank data"""
        url = f"https://openpagerank.com/api/v1.0/getPageRank?domains[]={domain}"
        headers = {"API-OPR": api_key}
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(url, headers=headers, timeout=10.0)
                if response.status_code != 200:
                    return {"error": "Failed to connect to Open PageRank API"}
                data = response.json()
                if "response" not in data or not data["response"]:
                    return {"error": "Invalid response from Open PageRank"}
                pr_data = data["response"][0]
                pr_score = pr_data.get("page_rank_integer", -1)
                # Map to UCI-style PageRank label
                if pr_score >= 7:
                    rank_class = 1   # High trust
                elif pr_score >= 4:
                    rank_class = 0   # Uncertain
                else:
                    rank_class = -1  # Low or untrusted
                return {
                    "domain": domain,
                    "opr_score": pr_score,
                    "uci_page_rank": rank_class
                }
        except Exception as e:
            return {"error": str(e)}
    def Page_Rank(self, url: str, api_key: str = None) -> int:
        """PageRank analysis using OpenPageRank API"""
        if not api_key:
            api_key = self.opr_api_key
        
        if not api_key:
            return -1
            
        try:
            domain = urlparse(url).netloc
            if not domain:
                return -1
     
            domain = str(domain)
        
            if domain.startswith('www.'):
                domain = domain[4:]
            
            # Use synchronous httpx instead of async
            url_api = f"https://openpagerank.com/api/v1.0/getPageRank?domains[]={domain}"
            headers = {"API-OPR": api_key}
            
            response = httpx.get(url_api, headers=headers, timeout=10.0)
            if response.status_code != 200:
                return -1
                
            data = response.json()
            if "response" not in data or not data["response"]:
                return -1
                
            pr_data = data["response"][0]
            pr_score = pr_data.get("page_rank_integer", -1)
            
            # Map to UCI-style PageRank label
            if pr_score >= 7:
                return 1   # High trust
            elif pr_score >= 4:
                return 0   # Uncertain
            else:
                return -1  # Low or untrusted
                
        except Exception as e:
            print(f"PageRank analysis failed: {e}")
            return -1
    def SSLfinal_State(self, url: str) -> int:
        """Check SSL certificate state - Updated logic"""
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = 443  # Default HTTPS port
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    # If no exception, cert is valid and trusted
                    return 1  # Trusted SSL certificate
        except ssl.SSLError as e:
            print(f"SSL error: {e}")
            return 0  # HTTPS used, but certificate has problems
        except Exception as e:
            print(f"General error: {e}")
            return -1  # No HTTPS or connection failed
    def extract_pop_up_window_feature(self, url: str) -> int:
        """Check for pop-up window features in HTML"""
        try:
            response = requests.get(url, timeout=5)
            html = response.text.lower()
            # If pop-up methods exist, mark as phishing (-1)
            if any(tag in html for tag in ['alert(', 'confirm(', 'prompt(', 'window.open(']):
                return -1  # pop-up present → fake
            else:
                return 1   # no pop-up → legitimate
        except Exception as e:
            print(f"Error fetching URL {url}: {e}")
            return 1  # on error, treat as legitimate (safer default)
    def extract_right_click_feature(self, url: str) -> int:
        """Check for right-click disabling features"""
        try:
            response = requests.get(url, timeout=5)
            html = response.text.lower()
            # More comprehensive patterns using regex
            disabling_patterns = [
                r'oncontextmenu\s*=\s*["\']return\s+false["\']',
                r'event\.button\s*===?\s*2',
                r'event\.which\s*===?\s*3',
                r'document\.oncontextmenu\s*=\s*function',
                r'addeventlistener\s*\(\s*["\']contextmenu["\']',
                r'preventdefault\s*\(\s*\).*contextmenu|contextmenu.*preventdefault',
                r'keycode\s*===?\s*123',  # F12 key
            ]
            for pattern in disabling_patterns:
                if re.search(pattern, html):
                    return -1
            return 1
        except Exception as e:
            print(f"Error fetching URL {url}: {e}")
            return 1
    def extract_on_mouseover_feature(self, url: str) -> int:
        """Check for suspicious mouseover features"""
        try:
            response = requests.get(url, timeout=5)
            html = response.text.lower()
            # Look for suspicious mouseover patterns
            suspicious_patterns = [
                r'onmouseover\s*=\s*["\'][^"\']window\.open[^"\']["\']',  # Pop-ups
                r'onmouseover\s*=\s*["\'][^"\']location\.href[^"\']["\']',  # Redirects
                r'onmouseover\s*=\s*["\'][^"\']document\.location[^"\']["\']',
                r'onmouseover\s*=\s*["\'][^"\']alert\s\([^"\']*["\']',  # Alerts
                r'onmouseover\s*=\s*["\'][^"\']eval\s\([^"\']*["\']',  # Code execution
            ]
            # Check for suspicious patterns
            for pattern in suspicious_patterns:
                if re.search(pattern, html):
                    return -1  # Suspicious mouseover usage
            return 1
        except Exception as e:
            print(f"Error fetching URL {url}: {e}")
            return 1
    def extract_favicon_feature(self, url: str) -> int:
        """Check favicon domain consistency"""
        try:
            response = requests.get(url, timeout=5)
            html = response.text
            # Parse domain of the page URL
            page_domain = urlparse(url).netloc
            soup = BeautifulSoup(html, "html.parser")
            # Find favicon link tags
            icon_link = soup.find("link", rel=lambda x: x and "icon" in x.lower())
            if not icon_link or not icon_link.has_attr("href"):
                # No favicon found
                return -1
            favicon_url = icon_link["href"]
            # Resolve relative favicon URLs to absolute URLs
            favicon_url_parsed = urlparse(urljoin(url, favicon_url))
            # Compare favicon domain to page domain
            if favicon_url_parsed.netloc == page_domain:
                return 1  # Same domain → legitimate
            else:
                return -1  # Different domain → phishing/fake
        except Exception as e:
            print(f"Error fetching URL {url}: {e}")
            return -1  # Treat errors as phishing to be safe
    def extract_iframe_feature(self, url: str) -> int:
        """Check for hidden iframe features"""
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text, 'html.parser')  # Remove .lower()
            iframes = soup.find_all("iframe")
            for iframe in iframes:
                style = iframe.get("style", "").replace(" ", "").lower()  # Handle whitespace
                width = iframe.get("width", "")
                height = iframe.get("height", "")
                if (
                    "display:none" in style or
                    "visibility:hidden" in style or
                    (width in ["0", "0px"] and height in ["0", "0px"]) or  # Better comparison
                    "height:0" in style or "width:0" in style
                ):
                    return -1
            return 1
        except Exception as e:
            print(f"Error fetching URL {url}: {e}")
            return 1
    def extract_sfh_feature(self, url: str) -> int:
        """Check Server Form Handler (SFH) feature"""
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.text.lower(), "html.parser")
            base_domain = urlparse(url).netloc
            forms = soup.find_all("form")
            for form in forms:
                action = form.get("action")
                if not action or action.strip() == "" or action.strip() == "about:blank":
                    return -1  # Phishing: empty or missing action
                full_action_url = urljoin(url, action)
                action_domain = urlparse(full_action_url).netloc
                if action_domain == "" or action_domain == base_domain:
                    return 1  # Legitimate
                else:
                    return 0   # Suspicious (different domain)
            # No form found → no phishing suspicion on SFH
            return 1  # Treat as legitimate
        except Exception as e:
            print(f"Error fetching URL {url}: {e}")
            return 0  # Treat failure as suspicious
    def extract_redirect_feature(self, url: str) -> int:
        """Check for URL redirects"""
        try:
            response = requests.get(url, timeout=5, allow_redirects=True)
            num_redirects = len(response.history)
            if num_redirects <= 1:
                return 0  # Legitimate
            else:
                return 1  # Phishing
        except Exception as e:
            print(f"Error fetching URL {url}: {e}")
            return 1  # Treat failures as suspicious
    def extract_all_features(self, url: str, opr_api_key: str = None) -> tuple[list, dict]:
        """Extract all URL features and return as list for model prediction, and a dict of raw details for reporting"""
        # Collect raw details
        raw_details = {}
        # IP address or domain
        raw_details['uses_ip_address'] = bool(re.match(r"https?://(?:\d{1,3}\.){3}\d{1,3}", url))
        raw_details['url_length'] = len(url)
        raw_details['shortening_service_match'] = re.search(r"(bit\.ly|goo\.gl|tinyurl\.com|ow\.ly|is\.gd|t\.co|short\.link|tiny\.cc)", url) is not None
        raw_details['has_at_symbol'] = "@" in url
        raw_details['double_slash_redirecting_pos'] = url.find("//", 6)
        parsed_url = urlparse(url)
        raw_details['domain'] = parsed_url.netloc if parsed_url.netloc else ""
        if not isinstance(raw_details['domain'], str):
            raw_details['domain'] = str(raw_details['domain'])
        raw_details['has_dash_in_domain'] = '-' in raw_details['domain']
        # Subdomain info
        domain = raw_details['domain']
        if domain and isinstance(domain, str):
            if domain.startswith('www.'):
                domain = domain[4:]
            dots = domain.count('.')
        else:
            dots = 0
        raw_details['subdomain_count'] = dots
        # WHOIS info
        try:
            import whois
            domain_for_whois = domain if isinstance(domain, str) else raw_details['domain']
            if isinstance(domain_for_whois, str):
                w = whois.whois(domain_for_whois)
                raw_details['whois'] = {
                    'domain_name': w.domain_name,
                    'creation_date': str(w.creation_date),
                    'expiration_date': str(w.expiration_date),
                    'updated_date': str(w.updated_date),
                    'registrar': w.registrar,
                    'status': w.status
                }
            else:
                raw_details['whois'] = {'error': 'Invalid domain type'}
        except Exception as e:
            raw_details['whois'] = {'error': str(e)}
        # DNS
        try:
            import dns.resolver
            domain_for_dns = domain if isinstance(domain, str) else raw_details['domain']
            if isinstance(domain_for_dns, str):
                dns.resolver.resolve(domain_for_dns, 'A')
                raw_details['dns_record'] = True
            else:
                raw_details['dns_record'] = False
        except Exception:
            raw_details['dns_record'] = False
        # Tranco rank
        raw_details['tranco_rank'] = self.get_tranco_rank(url)
        # PageRank
        raw_details['page_rank'] = self.Page_Rank(url, opr_api_key)
        # SSL
        try:
            parsed = urlparse(url)
            hostname = parsed.hostname
            port = 443
            context = ssl.create_default_context()
            with socket.create_connection((hostname, port), timeout=5) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    cert = ssock.getpeercert()
                    raw_details['ssl_cert'] = cert
        except Exception as e:
            raw_details['ssl_cert'] = str(e)
        # HTML features with explanations (compact format)
        html_feature_map = {
            'pop_up_window': {
                1: 'No pop-up',
                -1: 'Pop-up used'
            },
            'right_click_disabled': {
                1: 'Right-click enabled',
                -1: 'Right-click disabled'
            },
            'on_mouseover': {
                1: 'No trap on mouseover',
                -1: 'Mouseover hides link'
            },
            'favicon': {
                1: 'Favicon matches domain',
                -1: 'External favicon'
            },
            'iframe': {
                1: 'No iframe used',
                -1: 'Invisible iframe'
            },
            'sfh': {
                1: 'Valid form handler',
                0: 'Empty handler',
                -1: 'Fake/External handler'
            },
            'redirect': {
                0: 'Few redirects',
                1: 'Excessive redirects'
            }
        }
        for feat, func in [
            ('pop_up_window', self.extract_pop_up_window_feature),
            ('right_click_disabled', self.extract_right_click_feature),
            ('on_mouseover', self.extract_on_mouseover_feature),
            ('favicon', self.extract_favicon_feature),
            ('iframe', self.extract_iframe_feature),
            ('sfh', self.extract_sfh_feature),
            ('redirect', self.extract_redirect_feature)
        ]:
            try:
                val = func(url)
                explanation = html_feature_map[feat].get(val, str(val))
                # Store as: key: "value,explanation"
                raw_details[feat] = f"{val},{explanation}"
            except Exception as e:
                raw_details[feat] = f"None,{str(e)}"
        # Encoded features for model
        features = [
            self.having_IP_Address(url),
            self.URL_Length(url),
            self.Shortining_Service(url),
            self.having_At_Symbol(url),
            self.double_slash_redirecting(url),
            self.Prefix_Suffix(url),
            self.having_Sub_Domain(url),
            self.Domain_registeration_length(url),
            self.age_of_domain(url),
            self.DNSRecord(url),
            self.web_traffic(url),
            self.Page_Rank(url, opr_api_key),
            self.SSLfinal_State(url),
            self.extract_pop_up_window_feature(url),
            self.extract_right_click_feature(url),
            self.extract_on_mouseover_feature(url),
            self.extract_favicon_feature(url),
            self.extract_iframe_feature(url),
            self.extract_sfh_feature(url),
            self.extract_redirect_feature(url)
        ]
        # Add phishtank and virustotal results
        raw_details['phishtank_reported'] = self.check_phishtank(url)
        raw_details['virustotal_report'] = self.check_statistical_report_virustotal(url)
        # Add abnormal URL analysis
        raw_details['abnormal_url_analysis'] = extract_abnormal_url_features(url)
        return features, raw_details
    def get_feature_explanations(self, features: dict) -> list:
        """Return a list of dicts with feature, value, and human-readable explanation."""
        explanations = []
        mapping = {
            'having_IP_Address': {
                1: 'Uses IP address (Phishing)',
                -1: 'Uses domain (Legitimate)'
            },
            'URL_Length': {
                1: 'Long URL (Phishing)',
                0: 'Medium URL (Suspicious)',
                -1: 'Short URL (Legitimate)'
            },
            'Shortining_Service': {
                1: 'Uses shortener (Phishing)',
                -1: 'Not shortened (Legitimate)'
            },
            'having_At_Symbol': {
                1: 'Has @ in URL (Phishing)',
                -1: 'No @ in URL (Legitimate)'
            },
            'double_slash_redirecting': {
                1: 'Double slash abnormal (Phishing)',
                -1: 'Double slash normal (Legitimate)'
            },
            'Prefix_Suffix': {
                1: 'Dash in domain (Phishing)',
                -1: 'No dash in domain (Legitimate)'
            },
            'having_Sub_Domain': {
                1: 'Many subdomains (Phishing)',
                0: 'Some subdomains (Suspicious)',
                -1: 'Few subdomains (Legitimate)'
            },
            'Domain_registeration_length': {
                1: 'Long registration (Legitimate)',
                -1: 'Short registration (Phishing)'
            },
            'age_of_domain': {
                1: 'Old domain (Legitimate)',
                -1: 'New domain (Phishing)'
            },
            'DNSRecord': {
                1: 'DNS record present (Legitimate)',
                -1: 'No DNS record (Phishing)'
            },
            'web_traffic': {
                1: 'High traffic (Legitimate)',
                0: 'Moderate traffic (Suspicious)',
                -1: 'Low traffic (Phishing)'
            },
            'Page_Rank': {
                1: 'High PageRank (Legitimate)',
                0: 'Medium PageRank (Suspicious)',
                -1: 'Low PageRank (Phishing)'
            },
            'SSLfinal_State': {
                1: 'Valid HTTPS (Legitimate)',
                0: 'Unclear/Invalid cert (Suspicious)',
                -1: 'No SSL/HTTPS (Phishing)'
            },
            'pop_up_window': {
                1: 'No pop-up (Legitimate)',
                -1: 'Pop-up used (Phishing)'
            },
            'right_click_disabled': {
                1: 'Right-click enabled (Legitimate)',
                -1: 'Right-click disabled (Phishing)'
            },
            'on_mouseover': {
                1: 'No trap on mouseover (Legit)',
                -1: 'Mouseover hides link (Phishing)'
            },
            'favicon': {
                1: 'Favicon matches domain (Legit)',
                -1: 'External favicon (Phishing)'
            },
            'iframe': {
                1: 'No iframe used (Legitimate)',
                -1: 'Invisible iframe (Phishing)'
            },
            'sfh': {
                1: 'Valid form handler (Legit)',
                0: 'Empty handler (Suspicious)',
                -1: 'Fake/External handler (Phishing)'
            },
            'redirect': {
                0: 'Few redirects (Legitimate)',
                1: 'Excessive redirects (Phishing)'
            }
        }
        for k, v in features.items():
            desc = mapping.get(k, {}).get(v, str(v))
            explanations.append({'feature': k, 'value': v, 'description': desc})
        return explanations
    
    def predict_phishing(self, url: str, opr_api_key: str = None) -> dict:
        try:
            if self.model is None:
                return {
                    'is_phishing': True,
                    'error': 'XGBoost model not loaded'
                }
            features, raw_details = self.extract_all_features(url, opr_api_key)
            features_array = np.array(features).reshape(1, -1)
            prediction = self.model.predict(features_array)
            is_phishing = bool(prediction[0])

            feature_names = [
                'having_IP_Address', 'URL_Length', 'Shortining_Service',
                'having_At_Symbol', 'double_slash_redirecting', 'Prefix_Suffix',
                'having_Sub_Domain', 'Domain_registeration_length', 'age_of_domain',
                'DNSRecord', 'web_traffic', 'Page_Rank', 'SSLfinal_State',
                'pop_up_window', 'right_click_disabled', 'on_mouseover',
                'favicon', 'iframe', 'sfh', 'redirect'
            ]
            features_dict = {name: value for name, value in zip(feature_names, features)}
            
            # Override prediction if all trust indicators are positive
            whois_valid = 'error' not in raw_details.get('whois', {})
            ssl_valid = not isinstance(raw_details.get('ssl_cert'), str) and features_dict['SSLfinal_State'] == 1
            dns_valid = raw_details.get('dns_record', False)
            vt_clean = raw_details.get('virustotal_report', '').lower() == 'clean'
            phishtank_clean = raw_details.get('phishtank_reported', '').lower() == 'no'

            # # Check SSL state and web traffic - if both are suspicious/bad, mark as phishing
            ssl_state = features_dict['SSLfinal_State']
            web_traffic_state = features_dict['web_traffic']
            if (ssl_state in [-1, 0]) and (web_traffic_state in [-1, 0]):
                is_phishing = True

            if whois_valid and ssl_valid and dns_valid and vt_clean and phishtank_clean:
                is_phishing = False
            
           
            feature_explanations = self.get_feature_explanations(features_dict)
            return {
                'is_phishing': is_phishing,
                'features': features_dict,
                'feature_explanations': feature_explanations,
                'raw_details': raw_details
            }
        except Exception as e:
            print(f"Error in phishing prediction: {e}")
            return {
                'is_phishing': True,
                'features': {},
                'feature_explanations': [],
                'raw_details': {},
                'error': str(e)
            }

# Create a singleton instance
url_detector = URLPhishingDetector()
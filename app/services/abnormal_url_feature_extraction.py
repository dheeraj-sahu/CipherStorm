import whois
import re
from urllib.parse import urlparse
from typing import Optional, Dict, Any
import logging

def extract_domain_from_url(url: str) -> str:
    if not url.startswith(('http://', 'https://')):
        url = 'http://' + url
    parsed_url = urlparse(url)
    domain = parsed_url.netloc.lower()
    if domain.startswith('www.'):
        domain = domain[4:]
    return domain

def get_whois_info(domain: str) -> Dict[str, Any]:
    try:
        whois_info = whois.whois(domain)
        registrant_org = None
        registrant_email = None
        if hasattr(whois_info, 'registrant_org') and whois_info.registrant_org:
            registrant_org = whois_info.registrant_org
        elif hasattr(whois_info, 'org') and whois_info.org:
            registrant_org = whois_info.org
        elif hasattr(whois_info, 'registrant_organization') and whois_info.registrant_organization:
            registrant_org = whois_info.registrant_organization
        if hasattr(whois_info, 'registrant_email') and whois_info.registrant_email:
            registrant_email = whois_info.registrant_email
        elif hasattr(whois_info, 'emails') and whois_info.emails:
            registrant_email = whois_info.emails[0] if isinstance(whois_info.emails, list) else whois_info.emails
        elif hasattr(whois_info, 'email') and whois_info.email:
            registrant_email = whois_info.email
        return {
            'registrant_org': registrant_org,
            'registrant_email': registrant_email,
            'registrar': getattr(whois_info, 'registrar', None),
            'creation_date': getattr(whois_info, 'creation_date', None),
            'expiration_date': getattr(whois_info, 'expiration_date', None),
            'name_servers': getattr(whois_info, 'name_servers', None),
            'raw_whois': str(whois_info)
        }
    except Exception as e:
        return {
            'registrant_org': None,
            'registrant_email': None,
            'error': str(e)
        }

def check_domain_similarity(url_domain: str, whois_info: Dict[str, Any]) -> Dict[str, Any]:
    def normalize_domain(domain_str: str) -> str:
        if not domain_str:
            return ""
        return re.sub(r'[^a-zA-Z0-9]', '', domain_str.lower())
    def extract_domain_keywords(domain: str) -> set:
        domain_without_tld = domain.split('.')[0]
        keywords = re.split(r'[-_]', domain_without_tld)
        return set(keyword.lower() for keyword in keywords if len(keyword) > 2)
    
    # *CHANGE 1: Added function to extract keywords from any text*
    def extract_keywords_from_text(text: str) -> set:
        if not text:
            return set()
        # Extract meaningful keywords (3+ characters, alphabetic)
        keywords = re.findall(r'[a-zA-Z]{3,}', text.lower())
        return set(keywords)
    
    url_domain_normalized = normalize_domain(url_domain)
    url_keywords = extract_domain_keywords(url_domain)
    registrant_org = whois_info.get('registrant_org', '')
    registrant_email = whois_info.get('registrant_email', '')
    cheap_registrars = [
        'godaddy', 'namecheap', 'hostgator', 'bluehost', 'dreamhost',
        'hostinger', 'siteground', 'a2hosting', '1and1', 'ionos',
        'cheapdomains', 'dynadot', 'porkbun', 'namesilo', 'hover'
    ]
    abnormality_flags = []
    abnormal_score = 0.0
    org_similarity = False
    if registrant_org:
        org_normalized = normalize_domain(registrant_org)
        org_keywords = set(re.findall(r'[a-zA-Z]{3,}', registrant_org.lower()))
        if url_domain_normalized in org_normalized or any(keyword in org_normalized for keyword in url_keywords):
            org_similarity = True
        elif any(keyword in url_domain_normalized for keyword in org_keywords if len(keyword) > 3):
            org_similarity = True
    if not org_similarity and registrant_org:
        abnormality_flags.append("Domain name doesn't match registrant organization")
        abnormal_score += 0.3
    registrar = whois_info.get('registrar', '')
    if registrar:
        registrar_lower = registrar.lower()
        if any(cheap_registrar in registrar_lower for cheap_registrar in cheap_registrars):
            abnormality_flags.append("Registered through cheap/budget registrar")
            abnormal_score += 0.2
    if registrant_email:
        try:
            email_domain = registrant_email.split('@')[1].lower()
            email_domain_normalized = normalize_domain(email_domain)
            
            # *CHANGE 2: Enhanced email domain matching logic*
            email_matches_domain = url_domain_normalized in email_domain_normalized or email_domain_normalized in url_domain_normalized
            
            # Extract keywords from email domain, registrant org, registrar, and URL domain
            email_keywords = extract_keywords_from_text(email_domain)
            org_keywords = extract_keywords_from_text(registrant_org) if registrant_org else set()
            # *CHANGE 3: Added registrar keyword matching*
            registrar_keywords = extract_keywords_from_text(registrar) if registrar else set()
            
            # Check if email domain shares keywords with URL domain, registrant org, or registrar
            keyword_match = False
            if email_keywords:
                # Check if any email keyword matches URL keywords
                if url_keywords.intersection(email_keywords):
                    keyword_match = True
                # Check if any email keyword matches organization keywords
                elif org_keywords.intersection(email_keywords):
                    keyword_match = True
                # *CHANGE 3: Check if any email keyword matches registrar keywords*
                elif registrar_keywords.intersection(email_keywords):
                    keyword_match = True
            
            # Only flag as abnormal if email domain doesn't match AND no keyword overlap
            if not email_matches_domain and not keyword_match:
                generic_emails = ['gmail', 'yahoo', 'hotmail', 'outlook', 'aol', 'protonmail']
                if any(generic in email_domain for generic in generic_emails):
                    abnormality_flags.append("Uses generic email service for registration")
                    abnormal_score += 0.1
                else:
                    abnormality_flags.append("Email domain doesn't match website domain")
                    abnormal_score += 0.25
        except:
            pass
    if not registrant_org or registrant_org.lower() in ['redacted', 'private', 'n/a', '']:
        abnormality_flags.append("Missing or redacted registrant organization")
        abnormal_score += 0.2
    abnormal_score = min(abnormal_score, 1.0)
    return {
        'abnormality_flags': abnormality_flags,
        'abnormal_score': abnormal_score,
        'org_similarity': org_similarity,
        'url_keywords': list(url_keywords),
        'registrant_org_normalized': normalize_domain(registrant_org) if registrant_org else None,
        'uses_cheap_registrar': any(cheap_registrar in (registrar or '').lower() for cheap_registrar in cheap_registrars)
    }

def extract_abnormal_url_features(url: str) -> dict:
    """Main function to extract abnormal URL features for integration"""
    extracted_domain = extract_domain_from_url(url)
    whois_info = get_whois_info(extracted_domain)
    similarity_analysis = check_domain_similarity(extracted_domain, whois_info)
    abnormal_threshold = 0.3
    is_abnormal = similarity_analysis['abnormal_score'] >= abnormal_threshold
    details = {
        'whois_available': 'error' not in whois_info,
        'similarity_analysis': similarity_analysis,
        'whois_registrar': whois_info.get('registrar'),
        'whois_creation_date': str(whois_info.get('creation_date')) if whois_info.get('creation_date') else None,
        'abnormal_threshold': abnormal_threshold
    }
    return {
        'url': url,
        'extracted_domain': extracted_domain,
        'whois_registrant_org': whois_info.get('registrant_org'),
        'whois_registrant_email': whois_info.get('registrant_email'),
        'is_abnormal': is_abnormal,
        'abnormal_score': similarity_analysis['abnormal_score'],
        'details': details
    }
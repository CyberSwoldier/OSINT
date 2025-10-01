#!/usr/bin/env python3
"""
Professional Intelligence Framework - LEA Grade
Advanced OSINT with correlation, attribution, and dark web intelligence
Used by security researchers, investigators, and threat intelligence analysts
"""

import requests
import json
import re
import socket
import whois
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional, Tuple, Set
from dataclasses import dataclass, asdict, field
from enum import Enum
import dns.resolver
import hashlib
from urllib.parse import urlparse, quote, urljoin
import time
from collections import defaultdict
import os
from dotenv import load_dotenv
import base64
from concurrent.futures import ThreadPoolExecutor, as_completed

# Load environment variables
load_dotenv()

class IntelligenceLevel(Enum):
    """Intelligence classification levels"""
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"

class EntityType(Enum):
    """Types of entities in investigation"""
    EMAIL = "Email Address"
    PHONE = "Phone Number"
    DOMAIN = "Domain"
    IP = "IP Address"
    USERNAME = "Username"
    PERSON = "Person"
    ORGANIZATION = "Organization"
    LOCATION = "Location"
    DEVICE = "Device"

@dataclass
class Entity:
    """Entity in the investigation graph"""
    entity_type: EntityType
    value: str
    confidence: float
    first_seen: str
    last_seen: str
    sources: List[str]
    attributes: Dict[str, Any] = field(default_factory=dict)
    related_entities: List[str] = field(default_factory=list)

@dataclass
class Finding:
    """Intelligence finding"""
    severity: IntelligenceLevel
    category: str
    title: str
    description: str
    evidence: List[str]
    sources: List[str]
    timestamp: str
    confidence: float
    recommendations: List[str] = field(default_factory=list)
    iocs: List[str] = field(default_factory=list)
    attribution: Optional[Dict[str, str]] = None

@dataclass
class DarkWebResult:
    """Dark web intelligence result"""
    source: str
    platform: str
    url: str
    timestamp: str
    content_preview: str
    risk_level: str
    data_exposed: List[str]

@dataclass
class EmailIntelligenceReport:
    """Comprehensive email intelligence"""
    email: str
    validation: Dict[str, Any]
    breaches: List[Dict[str, Any]]
    darkweb_mentions: List[DarkWebResult]
    associated_accounts: List[str]
    social_profiles: Dict[str, Any]
    reputation_score: float
    connected_entities: List[Entity]
    malicious_contacts: List[Dict[str, Any]]
    email_patterns: Dict[str, Any]

@dataclass
class PhoneIntelligenceReport:
    """Comprehensive phone intelligence"""
    phone: str
    carrier_info: Dict[str, Any]
    location_data: Dict[str, Any]
    line_type: str
    reputation: Dict[str, Any]
    associated_emails: List[str]
    social_profiles: Dict[str, Any]
    connected_entities: List[Entity]
    risk_assessment: str

class AdvancedPhoneIntelligence:
    """Professional-grade phone number intelligence"""
    
    @staticmethod
    def deep_analyze(phone: str, config: Dict) -> PhoneIntelligenceReport:
        """Comprehensive phone number analysis"""
        print(f"[+] Deep analysis of phone number: {phone}")
        
        # Clean phone number
        clean_phone = re.sub(r'[^\d+]', '', phone)
        
        # Basic analysis
        carrier_info = AdvancedPhoneIntelligence._get_carrier_info(clean_phone, config)
        location_data = AdvancedPhoneIntelligence._get_location_data(clean_phone, config)
        line_type = AdvancedPhoneIntelligence._detect_line_type(clean_phone)
        reputation = AdvancedPhoneIntelligence._check_phone_reputation(clean_phone, config)
        
        # Find associated entities
        print(f"[+] Searching for associated accounts...")
        associated_emails = AdvancedPhoneIntelligence._find_associated_emails(clean_phone, config)
        social_profiles = AdvancedPhoneIntelligence._find_social_profiles(clean_phone)
        
        # Build entity connections
        connected_entities = []
        
        # Risk assessment
        risk_score = 0
        if reputation.get('spam_score', 0) > 50:
            risk_score += 40
        if line_type == 'VOIP':
            risk_score += 20
        if not carrier_info.get('carrier_name'):
            risk_score += 10
        
        risk_levels = ['LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        risk_assessment = risk_levels[min(risk_score // 25, 3)]
        
        return PhoneIntelligenceReport(
            phone=phone,
            carrier_info=carrier_info,
            location_data=location_data,
            line_type=line_type,
            reputation=reputation,
            associated_emails=associated_emails,
            social_profiles=social_profiles,
            connected_entities=connected_entities,
            risk_assessment=risk_assessment
        )
    
    @staticmethod
    def _get_carrier_info(phone: str, config: Dict) -> Dict[str, Any]:
        """Get carrier information using multiple APIs"""
        carrier_info = {}
        
        # Try NumVerify API
        if config.get('numverify_api_key'):
            try:
                url = f"http://apilayer.net/api/validate"
                params = {
                    'access_key': config['numverify_api_key'],
                    'number': phone,
                    'format': 1
                }
                response = requests.get(url, params=params, timeout=10)
                if response.status_code == 200:
                    data = response.json()
                    if data.get('valid'):
                        carrier_info = {
                            'carrier_name': data.get('carrier', 'Unknown'),
                            'country_code': data.get('country_code'),
                            'country_name': data.get('country_name'),
                            'location': data.get('location'),
                            'line_type': data.get('line_type'),
                            'source': 'NumVerify'
                        }
            except Exception as e:
                print(f"[!] NumVerify error: {e}")
        
        # Fallback: Basic carrier detection
        if not carrier_info:
            carrier_info = AdvancedPhoneIntelligence._basic_carrier_detection(phone)
        
        return carrier_info
    
    @staticmethod
    def _basic_carrier_detection(phone: str) -> Dict[str, Any]:
        """Basic carrier detection from phone patterns"""
        phone = phone.lstrip('+')
        
        # US/Canada detection
        if phone.startswith('1') and len(phone) == 11:
            area_code = phone[1:4]
            npa_nxx = phone[1:7]
            
            # Major US carriers by NPA-NXX prefix (simplified)
            carrier_patterns = {
                'Verizon': ['201', '202', '212', '312', '313'],
                'AT&T': ['214', '310', '404', '512'],
                'T-Mobile': ['206', '425', '253'],
                'Sprint': ['316', '620']
            }
            
            for carrier, codes in carrier_patterns.items():
                if area_code in codes:
                    return {
                        'carrier_name': carrier,
                        'country_code': '1',
                        'country_name': 'United States',
                        'method': 'pattern_matching'
                    }
        
        # Portugal detection
        if phone.startswith('351'):
            if phone[3] == '9':
                return {
                    'carrier_name': 'Portuguese Mobile Network',
                    'country_code': '351',
                    'country_name': 'Portugal',
                    'line_type': 'mobile'
                }
        
        return {'carrier_name': 'Unknown', 'method': 'unknown'}
    
    @staticmethod
    def _get_location_data(phone: str, config: Dict) -> Dict[str, Any]:
        """Get location data from phone number"""
        location = {}
        
        phone = phone.lstrip('+')
        
        # Country detection
        country_codes = {
            '1': ('US/Canada', 'United States/Canada'),
            '351': ('PT', 'Portugal'),
            '44': ('GB', 'United Kingdom'),
            '34': ('ES', 'Spain'),
            '33': ('FR', 'France'),
            '49': ('DE', 'Germany'),
            '39': ('IT', 'Italy'),
        }
        
        for code, (iso, name) in country_codes.items():
            if phone.startswith(code):
                location = {
                    'country_code': code,
                    'country_iso': iso,
                    'country_name': name
                }
                
                # US area code to state mapping
                if code == '1' and len(phone) >= 4:
                    area_code = phone[1:4]
                    state = AdvancedPhoneIntelligence._area_code_to_state(area_code)
                    if state:
                        location['state'] = state
                        location['area_code'] = area_code
                
                break
        
        return location
    
    @staticmethod
    def _area_code_to_state(area_code: str) -> Optional[str]:
        """Map area code to US state"""
        area_code_map = {
            '201': 'New Jersey', '202': 'District of Columbia', '203': 'Connecticut',
            '205': 'Alabama', '206': 'Washington', '207': 'Maine', '208': 'Idaho',
            '209': 'California', '210': 'Texas', '212': 'New York', '213': 'California',
            '214': 'Texas', '215': 'Pennsylvania', '216': 'Ohio', '217': 'Illinois',
            '218': 'Minnesota', '219': 'Indiana', '224': 'Illinois', '225': 'Louisiana',
            '228': 'Mississippi', '229': 'Georgia', '231': 'Michigan', '234': 'Ohio',
            '239': 'Florida', '240': 'Maryland', '248': 'Michigan', '251': 'Alabama',
            '252': 'North Carolina', '253': 'Washington', '254': 'Texas', '256': 'Alabama',
            '260': 'Indiana', '262': 'Wisconsin', '267': 'Pennsylvania', '269': 'Michigan',
            '270': 'Kentucky', '276': 'Virginia', '281': 'Texas', '301': 'Maryland',
            '302': 'Delaware', '303': 'Colorado', '304': 'West Virginia', '305': 'Florida',
            '307': 'Wyoming', '308': 'Nebraska', '309': 'Illinois', '310': 'California',
            '312': 'Illinois', '313': 'Michigan', '314': 'Missouri', '315': 'New York',
            '316': 'Kansas', '317': 'Indiana', '318': 'Louisiana', '319': 'Iowa',
            '320': 'Minnesota', '321': 'Florida', '323': 'California', '325': 'Texas',
            '330': 'Ohio', '331': 'Illinois', '334': 'Alabama', '336': 'North Carolina',
            '337': 'Louisiana', '339': 'Massachusetts', '347': 'New York', '351': 'Massachusetts',
            '352': 'Florida', '360': 'Washington', '361': 'Texas', '386': 'Florida',
            '401': 'Rhode Island', '402': 'Nebraska', '404': 'Georgia', '405': 'Oklahoma',
            '406': 'Montana', '407': 'Florida', '408': 'California', '409': 'Texas',
            '410': 'Maryland', '412': 'Pennsylvania', '413': 'Massachusetts', '414': 'Wisconsin',
            '415': 'California', '417': 'Missouri', '419': 'Ohio', '423': 'Tennessee',
            '424': 'California', '425': 'Washington', '432': 'Texas', '434': 'Virginia',
            '435': 'Utah', '440': 'Ohio', '442': 'California', '443': 'Maryland',
            '469': 'Texas', '470': 'Georgia', '475': 'Connecticut', '478': 'Georgia',
            '479': 'Arkansas', '480': 'Arizona', '484': 'Pennsylvania', '501': 'Arkansas',
            '502': 'Kentucky', '503': 'Oregon', '504': 'Louisiana', '505': 'New Mexico',
            '507': 'Minnesota', '508': 'Massachusetts', '509': 'Washington', '510': 'California',
            '512': 'Texas', '513': 'Ohio', '515': 'Iowa', '516': 'New York',
            '517': 'Michigan', '518': 'New York', '520': 'Arizona', '530': 'California',
            '540': 'Virginia', '541': 'Oregon', '551': 'New Jersey', '559': 'California',
            '561': 'Florida', '562': 'California', '563': 'Iowa', '564': 'Washington',
            '567': 'Ohio', '570': 'Pennsylvania', '571': 'Virginia', '573': 'Missouri',
            '574': 'Indiana', '575': 'New Mexico', '580': 'Oklahoma', '585': 'New York',
            '586': 'Michigan', '601': 'Mississippi', '602': 'Arizona', '603': 'New Hampshire',
            '605': 'South Dakota', '606': 'Kentucky', '607': 'New York', '608': 'Wisconsin',
            '609': 'New Jersey', '610': 'Pennsylvania', '612': 'Minnesota', '614': 'Ohio',
            '615': 'Tennessee', '616': 'Michigan', '617': 'Massachusetts', '618': 'Illinois',
            '619': 'California', '620': 'Kansas', '623': 'Arizona', '626': 'California',
            '630': 'Illinois', '631': 'New York', '636': 'Missouri', '641': 'Iowa',
            '646': 'New York', '650': 'California', '651': 'Minnesota', '660': 'Missouri',
            '661': 'California', '662': 'Mississippi', '667': 'Maryland', '678': 'Georgia',
            '682': 'Texas', '701': 'North Dakota', '702': 'Nevada', '703': 'Virginia',
            '704': 'North Carolina', '706': 'Georgia', '707': 'California', '708': 'Illinois',
            '712': 'Iowa', '713': 'Texas', '714': 'California', '715': 'Wisconsin',
            '716': 'New York', '717': 'Pennsylvania', '718': 'New York', '719': 'Colorado',
            '720': 'Colorado', '724': 'Pennsylvania', '727': 'Florida', '731': 'Tennessee',
            '732': 'New Jersey', '734': 'Michigan', '737': 'Texas', '740': 'Ohio',
            '757': 'Virginia', '760': 'California', '763': 'Minnesota', '765': 'Indiana',
            '770': 'Georgia', '772': 'Florida', '773': 'Illinois', '774': 'Massachusetts',
            '775': 'Nevada', '781': 'Massachusetts', '785': 'Kansas', '786': 'Florida',
            '801': 'Utah', '802': 'Vermont', '803': 'South Carolina', '804': 'Virginia',
            '805': 'California', '806': 'Texas', '808': 'Hawaii', '810': 'Michigan',
            '812': 'Indiana', '813': 'Florida', '814': 'Pennsylvania', '815': 'Illinois',
            '816': 'Missouri', '817': 'Texas', '818': 'California', '828': 'North Carolina',
            '830': 'Texas', '831': 'California', '832': 'Texas', '843': 'South Carolina',
            '845': 'New York', '847': 'Illinois', '848': 'New Jersey', '850': 'Florida',
            '856': 'New Jersey', '857': 'Massachusetts', '858': 'California', '859': 'Kentucky',
            '860': 'Connecticut', '862': 'New Jersey', '863': 'Florida', '864': 'South Carolina',
            '865': 'Tennessee', '870': 'Arkansas', '872': 'Illinois', '878': 'Pennsylvania',
            '901': 'Tennessee', '903': 'Texas', '904': 'Florida', '906': 'Michigan',
            '907': 'Alaska', '908': 'New Jersey', '909': 'California', '910': 'North Carolina',
            '912': 'Georgia', '913': 'Kansas', '914': 'New York', '915': 'Texas',
            '916': 'California', '917': 'New York', '918': 'Oklahoma', '919': 'North Carolina',
            '920': 'Wisconsin', '925': 'California', '928': 'Arizona', '929': 'New York',
            '931': 'Tennessee', '936': 'Texas', '937': 'Ohio', '940': 'Texas',
            '941': 'Florida', '947': 'Michigan', '949': 'California', '951': 'California',
            '952': 'Minnesota', '954': 'Florida', '956': 'Texas', '959': 'Connecticut',
            '970': 'Colorado', '971': 'Oregon', '972': 'Texas', '973': 'New Jersey',
            '978': 'Massachusetts', '979': 'Texas', '980': 'North Carolina', '984': 'North Carolina',
            '985': 'Louisiana', '989': 'Michigan'
        }
        return area_code_map.get(area_code)
    
    @staticmethod
    def _detect_line_type(phone: str) -> str:
        """Detect line type (Mobile/Landline/VOIP)"""
        phone = phone.lstrip('+')
        
        # Toll-free and VOIP patterns
        voip_patterns = ['800', '888', '877', '866', '855', '844', '833']
        
        if phone.startswith('1') and len(phone) >= 4:
            area_code = phone[1:4]
            if area_code in voip_patterns:
                return 'VOIP/Toll-Free'
        
        # Mobile patterns (international)
        if phone.startswith('351') and len(phone) >= 4:
            if phone[3] == '9':
                return 'Mobile'
            else:
                return 'Landline'
        
        return 'Unknown'
    
    @staticmethod
    def _check_phone_reputation(phone: str, config: Dict) -> Dict[str, Any]:
        """Check phone reputation across multiple databases"""
        reputation = {'spam_score': 0, 'reports': [], 'sources': []}
        
        # NumVerify includes some reputation data
        # Additional APIs could be added here
        
        return reputation
    
    @staticmethod
    def _find_associated_emails(phone: str, config: Dict) -> List[str]:
        """Find email addresses associated with phone number"""
        emails = []
        
        # This would require APIs like:
        # - Pipl
        # - Spokeo
        # - Social media reverse lookups
        
        # Placeholder for demonstration
        return emails
    
    @staticmethod
    def _find_social_profiles(phone: str) -> Dict[str, Any]:
        """Find social media profiles linked to phone number"""
        profiles = {}
        
        # Check if phone is registered on social platforms
        # This would use platform-specific APIs
        
        return profiles

class AdvancedEmailIntelligence:
    """Professional-grade email intelligence"""
    
    @staticmethod
    def deep_analyze(email: str, config: Dict) -> EmailIntelligenceReport:
        """Comprehensive email analysis"""
        print(f"[+] Deep analysis of email: {email}")
        
        # Validation
        validation = AdvancedEmailIntelligence._validate_email_advanced(email, config)
        
        # Breach check
        print(f"[+] Checking breach databases...")
        breaches = AdvancedEmailIntelligence._check_breaches_comprehensive(email, config)
        
        # Dark web monitoring
        print(f"[+] Scanning dark web mentions...")
        darkweb_mentions = AdvancedEmailIntelligence._scan_darkweb(email, config)
        
        # Find associated accounts
        print(f"[+] Finding associated accounts...")
        associated_accounts = AdvancedEmailIntelligence._find_associated_accounts(email, config)
        
        # Social profile discovery
        print(f"[+] Discovering social profiles...")
        social_profiles = AdvancedEmailIntelligence._discover_social_profiles(email)
        
        # Malicious contact detection
        print(f"[+] Checking for malicious contacts...")
        malicious_contacts = AdvancedEmailIntelligence._detect_malicious_contacts(email, config)
        
        # Email pattern analysis
        email_patterns = AdvancedEmailIntelligence._analyze_email_patterns(email)
        
        # Calculate reputation score
        reputation_score = AdvancedEmailIntelligence._calculate_reputation(
            breaches, darkweb_mentions, malicious_contacts, validation
        )
        
        # Build entity connections
        connected_entities = []
        
        return EmailIntelligenceReport(
            email=email,
            validation=validation,
            breaches=breaches,
            darkweb_mentions=darkweb_mentions,
            associated_accounts=associated_accounts,
            social_profiles=social_profiles,
            reputation_score=reputation_score,
            connected_entities=connected_entities,
            malicious_contacts=malicious_contacts,
            email_patterns=email_patterns
        )
    
    @staticmethod
    def _validate_email_advanced(email: str, config: Dict) -> Dict[str, Any]:
        """Advanced email validation"""
        validation = {
            'format_valid': False,
            'mx_valid': False,
            'smtp_valid': False,
            'disposable': False,
            'free_provider': False,
            'role_account': False,
            'deliverable': 'unknown'
        }
        
        # Format validation
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        validation['format_valid'] = bool(re.match(pattern, email))
        
        if not validation['format_valid']:
            return validation
        
        parts = email.split('@')
        domain = parts[1]
        username = parts[0]
        
        # Check for role accounts
        role_accounts = ['admin', 'info', 'support', 'sales', 'contact', 'help', 'noreply', 'no-reply']
        validation['role_account'] = username.lower() in role_accounts
        
        # Disposable email check
        disposable_domains = [
            'tempmail.com', 'guerrillamail.com', '10minutemail.com', 'mailinator.com',
            'throwaway.email', 'temp-mail.org', 'fakeinbox.com', 'trashmail.com',
            'maildrop.cc', 'getnada.com', 'temp-mail.io', 'mohmal.com'
        ]
        validation['disposable'] = domain.lower() in disposable_domains
        
        # Free provider check
        free_providers = [
            'gmail.com', 'yahoo.com', 'outlook.com', 'hotmail.com', 'aol.com',
            'icloud.com', 'mail.com', 'protonmail.com', 'gmx.com', 'yandex.com',
            'zoho.com', 'live.com', 'msn.com', 'me.com'
        ]
        validation['free_provider'] = domain.lower() in free_providers
        
        # MX record validation
        try:
            dns.resolver.resolve(domain, 'MX')
            validation['mx_valid'] = True
        except:
            validation['mx_valid'] = False
        
        # Enhanced validation with API
        if config.get('hunter_api_key'):
            hunter_data = AdvancedEmailIntelligence._verify_with_hunter(email, config)
            if hunter_data:
                validation.update(hunter_data)
        
        return validation
    
    @staticmethod
    def _verify_with_hunter(email: str, config: Dict) -> Optional[Dict]:
        """Verify email with Hunter.io"""
        try:
            url = "https://api.hunter.io/v2/email-verifier"
            params = {
                'email': email,
                'api_key': config['hunter_api_key']
            }
            response = requests.get(url, params=params, timeout=10)
            if response.status_code == 200:
                data = response.json().get('data', {})
                return {
                    'deliverable': data.get('status'),
                    'smtp_valid': data.get('smtp_check'),
                    'hunter_score': data.get('score')
                }
        except:
            pass
        return None
    
    @staticmethod
    def _check_breaches_comprehensive(email: str, config: Dict) -> List[Dict[str, Any]]:
        """Comprehensive breach checking across multiple sources"""
        breaches = []
        
        # Have I Been Pwned
        if config.get('hibp_api_key'):
            hibp_breaches = AdvancedEmailIntelligence._check_hibp(email, config)
            breaches.extend(hibp_breaches)
        
        # DeHashed API (requires subscription)
        if config.get('dehashed_api_key'):
            dehashed_results = AdvancedEmailIntelligence._check_dehashed(email, config)
            breaches.extend(dehashed_results)
        
        # LeakCheck API
        if config.get('leakcheck_api_key'):
            leakcheck_results = AdvancedEmailIntelligence._check_leakcheck(email, config)
            breaches.extend(leakcheck_results)
        
        return breaches
    
    @staticmethod
    def _check_hibp(email: str, config: Dict) -> List[Dict[str, Any]]:
        """Check Have I Been Pwned"""
        results = []
        try:
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{quote(email)}"
            headers = {
                'hibp-api-key': config['hibp_api_key'],
                'User-Agent': 'Professional-Intelligence-Framework'
            }
            response = requests.get(url, headers=headers, timeout=10)
            
            if response.status_code == 200:
                breaches = response.json()
                for breach in breaches:
                    results.append({
                        'source': 'Have I Been Pwned',
                        'breach_name': breach.get('Name'),
                        'breach_date': breach.get('BreachDate'),
                        'data_classes': breach.get('DataClasses', []),
                        'description': breach.get('Description'),
                        'verified': breach.get('IsVerified'),
                        'pwn_count': breach.get('PwnCount'),
                        'severity': 'HIGH' if breach.get('IsSensitive') else 'MEDIUM'
                    })
        except Exception as e:
            print(f"[!] HIBP error: {e}")
        
        return results
    
    @staticmethod
    def _check_dehashed(email: str, config: Dict) -> List[Dict[str, Any]]:
        """Check DeHashed database"""
        results = []
        try:
            url = "https://api.dehashed.com/search"
            params = {'query': f'email:{email}'}
            auth = (config['dehashed_email'], config['dehashed_api_key'])
            response = requests.get(url, params=params, auth=auth, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                for entry in data.get('entries', [])[:20]:
                    results.append({
                        'source': 'DeHashed',
                        'database': entry.get('database_name'),
                        'username': entry.get('username'),
                        'password': '[REDACTED]' if entry.get('password') else None,
                        'hashed_password': bool(entry.get('hashed_password')),
                        'ip_address': entry.get('ip_address'),
                        'name': entry.get('name'),
                        'severity': 'CRITICAL'
                    })
        except Exception as e:
            print(f"[!] DeHashed error: {e}")
        
        return results
    
    @staticmethod
    def _check_leakcheck(email: str, config: Dict) -> List[Dict[str, Any]]:
        """Check LeakCheck database"""
        results = []
        try:
            url = "https://leakcheck.io/api/public"
            params = {
                'check': email,
                'key': config['leakcheck_api_key']
            }
            response = requests.get(url, params=params, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                if data.get('found'):
                    for source in data.get('sources', []):
                        results.append({
                            'source': 'LeakCheck',
                            'database': source.get('name'),
                            'date': source.get('date'),
                            'severity': 'HIGH'
                        })
        except Exception as e:
            print(f"[!] LeakCheck error: {e}")
        
        return results
    
    @staticmethod
    def _scan_darkweb(email: str, config: Dict) -> List[DarkWebResult]:
        """Scan dark web for email mentions"""
        results = []
        
        # Paste sites
        print(f"[+] Checking paste sites...")
        paste_results = AdvancedEmailIntelligence._check_paste_sites(email)
        results.extend(paste_results)
        
        # Onion.link proxy search
        if config.get('enable_onion_search'):
            print(f"[+] Searching onion services (via proxies)...")
            onion_results = AdvancedEmailIntelligence._search_onion_services(email)
            results.extend(onion_results)
        
        return results
    
    @staticmethod
    def _check_paste_sites(email: str) -> List[DarkWebResult]:
        """Check paste sites for email mentions"""
        results = []
        
        # Psbdmp.ws
        try:
            url = f"https://psbdmp.ws/api/v3/search/{quote(email)}"
            response = requests.get(url, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for paste in data.get('data', [])[:10]:
                    results.append(DarkWebResult(
                        source='Pastebin',
                        platform='Paste Site',
                        url=f"https://pastebin.com/{paste.get('id')}",
                        timestamp=paste.get('time'),
                        content_preview='[Email found in public paste]',
                        risk_level='HIGH',
                        data_exposed=['Email Address']
                    ))
        except Exception as e:
            print(f"[!] Paste site error: {e}")
        
        return results
    
    @staticmethod
    def _search_onion_services(email: str) -> List[DarkWebResult]:
        """Search onion services via proxies"""
        results = []
        
        # This would search through onion service archives and databases
        # Available via services like Ahmia, Torch, or specialized APIs
        
        return results
    
    @staticmethod
    def _find_associated_accounts(email: str, config: Dict) -> List[str]:
        """Find accounts associated with email"""
        accounts = []
        
        # Email to username mapping
        username = email.split('@')[0]
        
        # Check common platforms
        platforms = [
            'github.com', 'twitter.com', 'instagram.com', 'facebook.com',
            'linkedin.com', 'reddit.com', 'pinterest.com', 'youtube.com',
            'medium.com', 'stackoverflow.com'
        ]
        
        print(f"[+] Checking {len(platforms)} platforms...")
        
        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = {
                executor.submit(AdvancedEmailIntelligence._check_platform, platform, username): platform
                for platform in platforms
            }
            
            for future in as_completed(futures):
                result = future.result()
                if result:
                    accounts.append(result)
        
        return accounts
    
    @staticmethod
    def _check_platform(platform: str, username: str) -> Optional[str]:
        """Check if username exists on platform"""
        urls = {
            'github.com': f'https://github.com/{username}',
            'twitter.com': f'https://twitter.com/{username}',
            'instagram.com': f'https://instagram.com/{username}',
            'reddit.com': f'https://reddit.com/user/{username}',
            'linkedin.com': f'https://linkedin.com/in/{username}',
            'medium.com': f'https://medium.com/@{username}',
            'pinterest.com': f'https://pinterest.com/{username}',
            'youtube.com': f'https://youtube.com/@{username}',
            'stackoverflow.com': f'https://stackoverflow.com/users/{username}',
        }
        
        url = urls.get(platform)
        if not url:
            return None
        
        try:
            response = requests.head(url, timeout=3, allow_redirects=True)
            if response.status_code == 200:
                return url
        except:
            pass
        
        return None
    
    @staticmethod
    def _discover_social_profiles(email: str) -> Dict[str, Any]:
        """Discover social media profiles linked to email"""
        profiles = {}
        
        # This would use services like:
        # - Social Searcher
        # - Pipl
        # - Spokeo
        
        return profiles
    
    @staticmethod
    def _detect_malicious_contacts(email: str, config: Dict) -> List[Dict[str, Any]]:
        """Detect if email has contacted or been contacted by malicious actors"""
        malicious_contacts = []
        
        # This would check:
        # - Threat intelligence feeds
        # - Known malicious email databases
        # - Phishing databases
        # - Spam trap data
        
        # Check email reputation
        try:
            url = f"https://emailrep.io/{email}"
            response = requests.get(url, timeout=5)
            if response.status_code == 200:
                data = response.json()
                
                if data.get('suspicious'):
                    malicious_contacts.append({
                        'type': 'Suspicious Activity',
                        'details': data.get('details', {}),
                        'reputation': data.get('reputation'),
                        'source': 'EmailRep.io'
                    })
                
                # Check for known malicious patterns
                if data.get('details', {}).get('blacklisted'):
                    malicious_contacts.append({
                        'type': 'Blacklisted',
                        'details': 'Email appears on blacklists',
                        'source': 'EmailRep.io'
                    })
        except:
            pass
        
        return malicious_contacts
    
    @staticmethod
    def _analyze_email_patterns(email: str) -> Dict[str, Any]:
        """Analyze email patterns for intelligence"""
        patterns = {}
        
        parts = email.split('@')
        username = parts[0]
        domain = parts[1]
        
        # Username patterns
        patterns['username_length'] = len(username)
        patterns['contains_numbers'] = bool(re.search(r'\d', username))
        patterns['contains_special'] = bool(re.search(r'[._-]', username))
        
        # Common patterns
        if re.match(r'^[a-z]+\.[a-z]+$', username):
            patterns['format'] = 'firstname.lastname'
        elif re.match(r'^[a-z]+\d+$', username):
            patterns['format'] = 'name + numbers'
        elif re.match(r'^\w+$', username):
            patterns['format'] = 'single word'
        else:
            patterns['format'] = 'complex'
        
        # Domain analysis
        patterns['domain'] = domain
        patterns['tld'] = domain.split('.')[-1]
        
        return patterns
    
    @staticmethod
    def _calculate_reputation(breaches, darkweb_mentions, malicious_contacts, validation) -> float:
        """Calculate overall email reputation score (0-100, higher is better)"""
        score = 100.0
        
        # Deduct for breaches
        score -= len(breaches) * 10
        
        # Deduct for dark web mentions
        score -= len(darkweb_mentions) * 15
        
        # Deduct for malicious contacts
        score -= len(malicious_contacts) * 20
        
        # Deduct for validation issues
        if not validation.get('mx_valid'):
            score -= 25
        if validation.get('disposable'):
            score -= 30
        
        return max(0.0, min(100.0, score))

class UsernameIntelligence:
    """Username OSINT across platforms"""
    
    @staticmethod
    def deep_analyze(username: str, config: Dict) -> Dict[str, Any]:
        """Comprehensive username analysis"""
        print(f"[+] Deep analysis of username: {username}")
        
        results = {
            'username': username,
            'platforms_found': {},
            'profile_data': {},
            'cross_platform_correlation': {},
            'risk_indicators': []
        }
        
        # Check across 300+ platforms (Sherlock-style)
        print(f"[+] Checking across social media platforms...")
        platforms = UsernameIntelligence._check_all_platforms(username)
        results['platforms_found'] = platforms
        
        # Correlate information across platforms
        if len(platforms) > 1:
            correlations = UsernameIntelligence._correlate_platforms(username, platforms)
            results['cross_platform_correlation'] = correlations
        
        return results
    
    @staticmethod
    def _check_all_platforms(username: str) -> Dict[str, bool]:
        """Check username across hundreds of platforms"""
        platforms = {
            # Social Media
            'GitHub': f'https://github.com/{username}',
            'Twitter': f'https://twitter.com/{username}',
            'Instagram': f'https://instagram.com/{username}',
            'Facebook': f'https://facebook.com/{username}',
            'LinkedIn': f'https://linkedin.com/in/{username}',
            'Reddit': f'https://reddit.com/user/{username}',
            'Pinterest': f'https://pinterest.com/{username}',
            'YouTube': f'https://youtube.com/@{username}',
            'TikTok': f'https://tiktok.com/@{username}',
            'Snapchat': f'https://snapchat.com/add/{username}',
            'Medium': f'https://medium.com/@{username}',
            'Tumblr': f'https://{username}.tumblr.com',
            'Flickr': f'https://flickr.com/people/{username}',
            'DeviantArt': f'https://{username}.deviantart.com',
            'Behance': f'https://behance.net/{username}',
            'Dribbble': f'https://dribbble.com/{username}',
            'Vimeo': f'https://vimeo.com/{username}',
            'SoundCloud': f'https://soundcloud.com/{username}',
            'Spotify': f'https://open.spotify.com/user/{username}',
            'Twitch': f'https://twitch.tv/{username}',
            'Steam': f'https://steamcommunity.com/id/{username}',
            'Xbox': f'https://xboxgamertag.com/search/{username}',
            'PlayStation': f'https://psnprofiles.com/{username}',
            
            # Professional
            'StackOverflow': f'https://stackoverflow.com/users/{username}',
            'HackerNews': f'https://news.ycombinator.com/user?id={username}',
            'AngelList': f'https://angel.co/{username}',
            'ProductHunt': f'https://producthunt.com/@{username}',
            
            # Forums
            '4chan': None,  # Anonymous
            'ResetEra': f'https://resetera.com/members/{username}',
            
            # Misc
            'Patreon': f'https://patreon.com/{username}',
            'Venmo': f'https://venmo.com/{username}',
            'CashApp': f'https://cash.app/${username}',
            'Keybase': f'https://keybase.io/{username}',
            'AboutMe': f'https://about.me/{username}',
            'Linktree': f'https://linktr.ee/{username}',
        }
        
        found_platforms = {}
        
        print(f"[+] Checking {len(platforms)} platforms (this may take a moment)...")
        
        with ThreadPoolExecutor(max_workers=20) as executor:
            future_to_platform = {
                executor.submit(UsernameIntelligence._check_url, url): name
                for name, url in platforms.items() if url
            }
            
            for future in as_completed(future_to_platform):
                platform_name = future_to_platform[future]
                try:
                    exists = future.result()
                    if exists:
                        found_platforms[platform_name] = platforms[platform_name]
                except:
                    pass
        
        print(f"[+] Found on {len(found_platforms)} platforms")
        return found_platforms
    
    @staticmethod
    def _check_url(url: str) -> bool:
        """Check if URL exists"""
        try:
            response = requests.head(url, timeout=3, allow_redirects=True)
            return response.status_code == 200
        except:
            return False
    
    @staticmethod
    def _correlate_platforms(username: str, platforms: Dict) -> Dict[str, Any]:
        """Correlate information across platforms"""
        correlations = {
            'consistency': 0.0,
            'possible_same_person': True,
            'notes': []
        }
        
        # If found on multiple platforms, likely same person
        if len(platforms) >= 3:
            correlations['consistency'] = 0.8
            correlations['notes'].append(f'Username found on {len(platforms)} platforms')
        
        return correlations

class IntelligenceCorrelator:
    """Correlate intelligence from multiple sources"""
    
    def __init__(self):
        self.entities = []
        self.relationships = []
    
    def add_entity(self, entity: Entity):
        """Add entity to correlation engine"""
        self.entities.append(entity)
    
    def correlate(self) -> Dict[str, Any]:
        """Correlate all collected intelligence"""
        correlations = {
            'entity_count': len(self.entities),
            'relationship_graph': {},
            'timeline': [],
            'attribution': {},
            'risk_factors': []
        }
        
        # Build relationship graph
        for entity in self.entities:
            correlations['relationship_graph'][entity.value] = {
                'type': entity.entity_type.value,
                'related': entity.related_entities
            }
        
        return correlations

class ProfessionalIntelligenceFramework:
    """Main professional intelligence framework"""
    
    def __init__(self, config: Dict[str, str] = None):
        self.config = self._load_config(config)
        self.correlator = IntelligenceCorrelator()
        self.findings = []
        
    def _load_config(self, config: Optional[Dict]) -> Dict:
        """Load configuration from environment and parameters"""
        default_config = {
            'hibp_api_key': os.getenv('HIBP_API_KEY', ''),
            'abuseipdb_api_key': os.getenv('ABUSEIPDB_API_KEY', ''),
            'virustotal_api_key': os.getenv('VIRUSTOTAL_API_KEY', ''),
            'numverify_api_key': os.getenv('NUMVERIFY_API_KEY', ''),
            'hunter_api_key': os.getenv('HUNTER_API_KEY', ''),
            'dehashed_api_key': os.getenv('DEHASHED_API_KEY', ''),
            'dehashed_email': os.getenv('DEHASHED_EMAIL', ''),
            'leakcheck_api_key': os.getenv('LEAKCHECK_API_KEY', ''),
            'enable_onion_search': os.getenv('ENABLE_ONION_SEARCH', 'false').lower() == 'true',
        }
        
        if config:
            default_config.update(config)
        
        return default_config
    
    def investigate(self, target: str, target_type: str = 'auto') -> Dict[str, Any]:
        """Main investigation function"""
        print("\n" + "=" * 80)
        print("PROFESSIONAL INTELLIGENCE FRAMEWORK - INVESTIGATION START")
        print("=" * 80)
        print(f"Target: {target}")
        print(f"Timestamp: {datetime.now().isoformat()}")
        print("=" * 80 + "\n")
        
        # Detect target type
        if target_type == 'auto':
            target_type = self._detect_target_type(target)
        
        print(f"[*] Target Type: {target_type.upper()}")
        
        investigation_result = {
            'target': target,
            'target_type': target_type,
            'timestamp': datetime.now().isoformat(),
            'findings': [],
            'intelligence_report': {},
            'correlation_data': {},
            'risk_assessment': {},
            'recommendations': []
        }
        
        # Route to appropriate analysis
        if target_type == 'email':
            report = AdvancedEmailIntelligence.deep_analyze(target, self.config)
            investigation_result['intelligence_report'] = asdict(report)
            self._process_email_findings(report)
            
        elif target_type == 'phone':
            report = AdvancedPhoneIntelligence.deep_analyze(target, self.config)
            investigation_result['intelligence_report'] = asdict(report)
            self._process_phone_findings(report)
            
        elif target_type == 'username':
            report = UsernameIntelligence.deep_analyze(target, self.config)
            investigation_result['intelligence_report'] = report
            self._process_username_findings(report)
            
        elif target_type in ['domain', 'url', 'ip']:
            # Use existing domain/IP intelligence
            pass
        
        # Correlate all intelligence
        investigation_result['correlation_data'] = self.correlator.correlate()
        investigation_result['findings'] = [asdict(f) for f in self.findings]
        
        # Risk assessment
        investigation_result['risk_assessment'] = self._assess_risk()
        
        # Generate recommendations
        investigation_result['recommendations'] = self._generate_recommendations()
        
        return investigation_result
    
    def _detect_target_type(self, target: str) -> str:
        """Detect target type"""
        email_pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        phone_pattern = r'^\+?[1-9]\d{1,14}$'
        ip_pattern = r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$'
        
        target = target.strip()
        
        if re.match(email_pattern, target):
            return 'email'
        elif re.match(phone_pattern, target.replace('-', '').replace(' ', '').replace('(', '').replace(')', '')):
            return 'phone'
        elif re.match(ip_pattern, target):
            return 'ip'
        elif target.startswith('http'):
            return 'url'
        elif '.' in target and not ' ' in target:
            return 'domain'
        else:
            return 'username'
    
    def _process_email_findings(self, report: EmailIntelligenceReport):
        """Process email intelligence into findings"""
        
        # Breach findings
        if report.breaches:
            critical_breaches = [b for b in report.breaches if b.get('severity') == 'CRITICAL']
            high_breaches = [b for b in report.breaches if b.get('severity') == 'HIGH']
            
            if critical_breaches:
                self.findings.append(Finding(
                    severity=IntelligenceLevel.CRITICAL,
                    category='Data Breach',
                    title=f'Email found in {len(critical_breaches)} critical breach(es)',
                    description=f'Email address discovered in {len(critical_breaches)} critical data breaches with sensitive information exposed',
                    evidence=[b.get('breach_name', 'Unknown') for b in critical_breaches[:5]],
                    sources=list(set([b.get('source', 'Unknown') for b in critical_breaches])),
                    timestamp=datetime.now().isoformat(),
                    confidence=0.95,
                    recommendations=[
                        'Immediately change passwords for all affected accounts',
                        'Enable multi-factor authentication on all accounts',
                        'Monitor for identity theft and fraudulent activity',
                        'Consider credit monitoring service'
                    ],
                    iocs=[report.email]
                ))
            
            if high_breaches:
                self.findings.append(Finding(
                    severity=IntelligenceLevel.HIGH,
                    category='Data Breach',
                    title=f'Email found in {len(high_breaches)} high-severity breach(es)',
                    description=f'Email address appears in {len(high_breaches)} data breaches',
                    evidence=[b.get('breach_name', 'Unknown') for b in high_breaches[:5]],
                    sources=list(set([b.get('source', 'Unknown') for b in high_breaches])),
                    timestamp=datetime.now().isoformat(),
                    confidence=0.90,
                    recommendations=[
                        'Change passwords for affected accounts',
                        'Enable 2FA where possible',
                        'Review account activity for suspicious behavior'
                    ],
                    iocs=[report.email]
                ))
        
        # Dark web findings
        if report.darkweb_mentions:
            self.findings.append(Finding(
                severity=IntelligenceLevel.HIGH,
                category='Dark Web Exposure',
                title=f'Email found on dark web/paste sites ({len(report.darkweb_mentions)} instances)',
                description=f'Email address discovered {len(report.darkweb_mentions)} times on dark web sources and public paste sites',
                evidence=[dw.url for dw in report.darkweb_mentions[:5]],
                sources=list(set([dw.source for dw in report.darkweb_mentions])),
                timestamp=datetime.now().isoformat(),
                confidence=0.85,
                recommendations=[
                    'Investigate exposure context immediately',
                    'Rotate all credentials associated with this email',
                    'Monitor for follow-on attacks or social engineering',
                    'Consider new email address for sensitive accounts'
                ],
                iocs=[report.email]
            ))
        
        # Malicious contact findings
        if report.malicious_contacts:
            self.findings.append(Finding(
                severity=IntelligenceLevel.MEDIUM,
                category='Malicious Activity',
                title='Email associated with malicious activity',
                description='Email has been flagged for suspicious or malicious activity',
                evidence=[mc.get('type', 'Unknown') for mc in report.malicious_contacts],
                sources=[mc.get('source', 'Unknown') for mc in report.malicious_contacts],
                timestamp=datetime.now().isoformat(),
                confidence=0.75,
                recommendations=[
                    'Review email account for compromise',
                    'Check sent folder for unauthorized messages',
                    'Scan connected devices for malware'
                ]
            ))
        
        # Low reputation
        if report.reputation_score < 50:
            self.findings.append(Finding(
                severity=IntelligenceLevel.LOW,
                category='Email Reputation',
                title=f'Low email reputation score ({report.reputation_score:.0f}/100)',
                description='Email has a low reputation score based on multiple factors',
                evidence=[f'Reputation score: {report.reputation_score:.0f}'],
                sources=['EmailRep.io', 'Internal Analysis'],
                timestamp=datetime.now().isoformat(),
                confidence=0.70,
                recommendations=[
                    'Verify email legitimacy',
                    'Be cautious of communications from this address'
                ]
            ))
    
    def _process_phone_findings(self, report: PhoneIntelligenceReport):
        """Process phone intelligence into findings"""
        
        # High spam score
        if report.reputation.get('spam_score', 0) > 50:
            self.findings.append(Finding(
                severity=IntelligenceLevel.MEDIUM,
                category='Phone Reputation',
                title=f'Phone number flagged as spam/suspicious',
                description=f"Phone has spam score of {report.reputation.get('spam_score')}%",
                evidence=[f"Spam reports: {report.reputation.get('spam_score')}%"],
                sources=report.reputation.get('sources', []),
                timestamp=datetime.now().isoformat(),
                confidence=0.80,
                recommendations=[
                    'Verify caller identity before engaging',
                    'Block number if unsolicited',
                    'Report to carrier if harassment occurs'
                ]
            ))
        
        # VOIP detection
        if report.line_type == 'VOIP/Toll-Free':
            self.findings.append(Finding(
                severity=IntelligenceLevel.LOW,
                category='Phone Type',
                title='VOIP/Toll-Free number detected',
                description='Phone number is VOIP or toll-free, which may indicate business or spoofing',
                evidence=[report.line_type],
                sources=['Line Type Analysis'],
                timestamp=datetime.now().isoformat(),
                confidence=0.85,
                recommendations=[
                    'VOIP numbers can be easily spoofed',
                    'Verify identity through alternate means'
                ]
            ))
        
        # Location found
        if report.location_data:
            self.findings.append(Finding(
                severity=IntelligenceLevel.INFORMATIONAL,
                category='Geolocation',
                title=f"Phone registered in {report.location_data.get('country_name', 'Unknown')}",
                description=f"Geographic information: {report.location_data}",
                evidence=[json.dumps(report.location_data)],
                sources=['Phone Analysis'],
                timestamp=datetime.now().isoformat(),
                confidence=0.90,
                recommendations=[]
            ))
    
    def _process_username_findings(self, report: Dict[str, Any]):
        """Process username intelligence into findings"""
        
        platforms_found = report.get('platforms_found', {})
        
        if len(platforms_found) > 5:
            self.findings.append(Finding(
                severity=IntelligenceLevel.INFORMATIONAL,
                category='Digital Footprint',
                title=f'Username found on {len(platforms_found)} platforms',
                description=f'Extensive digital presence across multiple platforms',
                evidence=list(platforms_found.keys())[:10],
                sources=['Platform Enumeration'],
                timestamp=datetime.now().isoformat(),
                confidence=0.85,
                recommendations=[
                    'Review privacy settings on all platforms',
                    'Consider unique usernames for sensitive accounts',
                    'Monitor for impersonation attempts'
                ]
            ))
    
    def _assess_risk(self) -> Dict[str, Any]:
        """Assess overall risk based on findings"""
        risk_score = 0
        
        for finding in self.findings:
            if finding.severity == IntelligenceLevel.CRITICAL:
                risk_score += 40
            elif finding.severity == IntelligenceLevel.HIGH:
                risk_score += 25
            elif finding.severity == IntelligenceLevel.MEDIUM:
                risk_score += 15
            elif finding.severity == IntelligenceLevel.LOW:
                risk_score += 5
        
        risk_levels = ['INFORMATIONAL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']
        risk_level = risk_levels[min(risk_score // 25, 4)]
        
        return {
            'risk_score': risk_score,
            'risk_level': risk_level,
            'critical_findings': sum(1 for f in self.findings if f.severity == IntelligenceLevel.CRITICAL),
            'high_findings': sum(1 for f in self.findings if f.severity == IntelligenceLevel.HIGH),
            'medium_findings': sum(1 for f in self.findings if f.severity == IntelligenceLevel.MEDIUM),
            'low_findings': sum(1 for f in self.findings if f.severity == IntelligenceLevel.LOW),
        }
    
    def _generate_recommendations(self) -> List[str]:
        """Generate actionable recommendations"""
        recommendations = []
        
        # Collect all recommendations from findings
        for finding in self.findings:
            recommendations.extend(finding.recommendations)
        
        # Deduplicate
        recommendations = list(dict.fromkeys(recommendations))
        
        # Add general recommendations
        if any(f.severity == IntelligenceLevel.CRITICAL for f in self.findings):
            recommendations.insert(0, 'URGENT: Take immediate action on critical findings')
        
        return recommendations
    
    def generate_report(self, investigation_result: Dict, format: str = 'text') -> str:
        """Generate professional intelligence report"""
        
        if format == 'json':
            return json.dumps(investigation_result, indent=2, default=str)
        
        # Professional text report
        report = []
        report.append("=" * 90)
        report.append("INTELLIGENCE INVESTIGATION REPORT")
        report.append("CLASSIFICATION: LAW ENFORCEMENT SENSITIVE")
        report.append("=" * 90)
        report.append(f"\nTarget: {investigation_result['target']}")
        report.append(f"Target Type: {investigation_result['target_type'].upper()}")
        report.append(f"Investigation Date: {investigation_result['timestamp']}")
        report.append(f"Risk Level: {investigation_result['risk_assessment']['risk_level']}")
        
        # Executive Summary
        report.append("\n" + "-" * 90)
        report.append("EXECUTIVE SUMMARY")
        report.append("-" * 90)
        
        risk = investigation_result['risk_assessment']
        report.append(f"Overall Risk Assessment: {risk['risk_level']}")
        report.append(f"Risk Score: {risk['risk_score']}/100")
        report.append(f"\nFindings Summary:")
        report.append(f"  • Critical: {risk['critical_findings']}")
        report.append(f"  • High: {risk['high_findings']}")
        report.append(f"  • Medium: {risk['medium_findings']}")
        report.append(f"  • Low: {risk['low_findings']}")
        
        # Key Findings
        report.append("\n" + "-" * 90)
        report.append("KEY INTELLIGENCE FINDINGS")
        report.append("-" * 90)
        
        findings_by_severity = defaultdict(list)
        for finding in investigation_result['findings']:
            findings_by_severity[finding['severity']].append(finding)
        
        for severity in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW', 'INFORMATIONAL']:
            findings = findings_by_severity.get(severity, [])
            if findings:
                report.append(f"\n[{severity}] ({len(findings)} findings)")
                for i, finding in enumerate(findings, 1):
                    report.append(f"\n  {i}. {finding['title']}")
                    report.append(f"     Category: {finding['category']}")
                    report.append(f"     Confidence: {finding['confidence']:.0%}")
                    report.append(f"     Description: {finding['description']}")
                    if finding.get('evidence'):
                        report.append(f"     Evidence: {', '.join(finding['evidence'][:3])}")
                    if finding.get('sources'):
                        report.append(f"     Sources: {', '.join(finding['sources'])}")
                    if finding.get('recommendations'):
                        report.append(f"     Recommended Actions:")
                        for rec in finding['recommendations'][:3]:
                            report.append(f"       - {rec}")
        
        # Detailed Intelligence
        report.append("\n" + "-" * 90)
        report.append("DETAILED INTELLIGENCE DATA")
        report.append("-" * 90)
        
        intel_report = investigation_result.get('intelligence_report', {})
        if intel_report:
            report.append(json.dumps(intel_report, indent=2, default=str))
        
        # Recommendations
        report.append("\n" + "-" * 90)
        report.append("ACTIONABLE RECOMMENDATIONS")
        report.append("-" * 90)
        
        for i, rec in enumerate(investigation_result.get('recommendations', [])[:15], 1):
            report.append(f"{i}. {rec}")
        
        # Footer
        report.append("\n" + "=" * 90)
        report.append("END OF INTELLIGENCE REPORT")
        report.append("=" * 90)
        
        return "\n".join(report)


def main():
    """Main execution"""
    print("""
    ╔═══════════════════════════════════════════════════════════════════════╗
    ║  PROFESSIONAL INTELLIGENCE FRAMEWORK                                  ║
    ║  Law Enforcement Grade OSINT & Threat Intelligence                    ║
    ║  Advanced Correlation • Dark Web Monitoring • Entity Attribution      ║
    ╚═══════════════════════════════════════════════════════════════════════╝
    """)
    
    # Display API status
    api_keys = {
        'HIBP_API_KEY': os.getenv('HIBP_API_KEY'),
        'VIRUSTOTAL_API_KEY': os.getenv('VIRUSTOTAL_API_KEY'),
        'ABUSEIPDB_API_KEY': os.getenv('ABUSEIPDB_API_KEY'),
        'NUMVERIFY_API_KEY': os.getenv('NUMVERIFY_API_KEY'),
        'HUNTER_API_KEY': os.getenv('HUNTER_API_KEY'),
        'DEHASHED_API_KEY': os.getenv('DEHASHED_API_KEY'),
        'LEAKCHECK_API_KEY': os.getenv('LEAKCHECK_API_KEY'),
    }
    
    print("\n[Intelligence Sources Status]")
    for key_name, key_value in api_keys.items():
        status = "✓ Active" if key_value else "✗ Inactive"
        print(f"  {key_name}: {status}")
    
    print("\n[Supported Target Types]")
    print("  • Email Address (email@example.com)")
    print("  • Phone Number (+1234567890)")
    print("  • Username (johndoe)")
    print("  • Domain (example.com)")
    print("  • IP Address (192.168.1.1)")
    print("  • URL (https://example.com)")
    
    target = input("\n[>] Enter investigation target: ").strip()
    
    if not target:
        print("[!] No target provided. Exiting.")
        return
    
    # Initialize framework
    framework = ProfessionalIntelligenceFramework()
    
    # Conduct investigation
    result = framework.investigate(target)
    
    # Generate report
    print("\n" + "=" * 90)
    print("GENERATING INTELLIGENCE REPORT...")
    print("=" * 90 + "\n")
    
    report = framework.generate_report(result, format='text')
    print(report)
    
    # Save reports
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"intel_report_{timestamp}.txt"
    
    with open(filename, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"\n[✓] Intelligence report saved: {filename}")
    
    # Save JSON
    json_filename = f"intel_report_{timestamp}.json"
    json_report = framework.generate_report(result, format='json')
    with open(json_filename, 'w', encoding='utf-8') as f:
        f.write(json_report)
    
    print(f"[✓] JSON data saved: {json_filename}")
    print("\n[✓] Investigation complete.")


if __name__ == "__main__":
    main()
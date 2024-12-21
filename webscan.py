import os
import requests
import socket
import whois
from bs4 import BeautifulSoup
from urllib.parse import urlparse
import ssl
import dns.resolver
from datetime import datetime
from urllib.request import urlopen


def banner():
    print("=" * 70)
    print("Web Scanner Tool - Choose Your Target Type: IP or URL")
    print("A comprehensive tool for testing web vulnerabilities.")
    print("=" * 70)


# 1. Scan open ports for IP targets with services
def scan_ports(ip):
    print(f"\n[+] Scanning open ports on {ip}...")
    # Define common port services
    port_services = {
        21: "FTP",
        22: "SSH",
        23: "Telnet",
        25: "SMTP",
        53: "DNS",
        80: "HTTP",
        110: "POP3",
        143: "IMAP",
        443: "HTTPS",
        3306: "MySQL",
        8080: "HTTP Proxy",
        8443: "HTTPS Proxy",
        8888: "HTTP-alt",
        135: "MS RPC",
        445: "Microsoft-DS"
    }

    for port in range(1, 1025):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(0.5)
            result = sock.connect_ex((ip, port))
            if result == 0:
                service = port_services.get(port, "Unknown Service")
                print(f"Port {port}: OPEN - {service}")
            sock.close()
        except Exception as e:
            print(f"Error scanning port {port}: {e}")


# 2. Perform a reverse IP lookup
def reverse_ip_lookup(ip):
    print(f"\n[+] Performing reverse IP lookup for {ip}...")
    try:
        hostname, _, _ = socket.gethostbyaddr(ip)
        print(f"Hostname: {hostname}")
    except socket.herror as e:
        print(f"Error during reverse IP lookup: Hostname not found for IP {ip}. Error: {e}")
    except socket.gaierror as e:
        print(f"Error during reverse IP lookup: DNS resolution error. Error: {e}")
    except Exception as e:
        print(f"Error during reverse IP lookup: {e}")


# 3. Scan HTTP headers for URL targets
def scan_headers(url):
    print(f"\n[+] Scanning HTTP headers for {url}...")
    try:
        response = requests.get(url)
        for header, value in response.headers.items():
            print(f"{header}: {value}")
        server_info = response.headers.get('Server', 'Unknown')
        print(f"Server: {server_info}")
    except Exception as e:
        print(f"Error scanning headers: {e}")


# 4. Extract links from URL
def scan_links(url):
    print(f"\n[+] Extracting links from {url}...")
    try:
        response = requests.get(url)
        soup = BeautifulSoup(response.text, 'html.parser')
        for link in soup.find_all('a', href=True):
            print(f"Link found: {link['href']}")
    except Exception as e:
        print(f"Error extracting links: {e}")


# 5. Test for XSS vulnerabilities
def test_xss(url):
    print(f"\n[+] Testing for XSS vulnerabilities on {url}...")
    
    payloads = [
        # Simple Script Injection
        "<script>alert('XSS')</script>",  
        "<img src=x onerror=alert('XSS')>",  
        "<svg/onload=alert('XSS')>",  
        "<input type='text' value='<script>alert(\"XSS\")</script>'>",  
        "<body onload=alert('XSS')>",  

        # Redirects & URL Manipulation
        "<script>window.location='http://malicious.com'</script>",  # Redirect to a malicious site
        "<a href='javascript:alert(1)'>Click me</a>",  # Link with JS alert
        "<img src=x onerror=window.location='http://malicious.com'>",  # Redirect via img tag

        # DOM-based XSS
        "<script>document.location='http://malicious.com'</script>",  # DOM-based redirect
        "<iframe src='http://malicious.com'></iframe>",  # Embedded malicious iframe

        # Using other HTML elements for payloads
        "<input type='text' value='<script>alert(1)</script>' autofocus>",  # Autofocus on input
        "<form><input type='submit' value='<script>alert(1)</script>'></form>",  # Form submit button
        "<select><option value=''><script>alert(1)</script></option></select>",  # Select menu XSS

        # Malicious JavaScript with event handlers
        "<button onclick='alert(1)'>Click Me</button>",  # Button with JS handler
        "<a href='#' onmouseover='alert(1)'>Hover me</a>",  # Hover event trigger
        "<div onmouseover='alert(1)'>Hover over me</div>",  # Div with hover event

        # SVG XSS payloads
        "<svg/onload=alert('XSS')>",  # Inline SVG XSS
        "<svg><script>alert('XSS')</script></svg>",  # SVG with embedded script

        # Base64 Encoded XSS Payload
        "<img src='data:image/svg+xml;base64,PHN2ZyBvbmxvbadwPWh0dHBzOi8vbWFsaWNpb3VzLmNvbS9leGFtcGxlX2NvbQ=='>",  # Base64 encoded image with XSS
    ]
    
    for payload in payloads:
        try:
            response = requests.get(f"{url}?q={payload}")
            if payload in response.text:
                print(f"Vulnerable to XSS: {payload}")
        except Exception as e:
            print(f"Error testing XSS: {e}")



# 6. Test for SQL Injection vulnerabilities
def test_sqli(url):
    print(f"\n[+] Testing for SQL injection vulnerabilities on {url}...")
    payloads = [
        "' OR '1'='1' --",  
        "' UNION SELECT NULL, NULL, NULL --",  
        "' AND 1=1 --",  
        "' OR 1=1 #",  
        "'; DROP TABLE users; --",  
    ]
    for payload in payloads:
        try:
            response = requests.get(f"{url}?id={payload}")
            if "SQL" in response.text or "error" in response.text:
                print(f"Vulnerable to SQL injection: {payload}")
        except Exception as e:
            print(f"Error testing SQL injection: {e}")


# 7. WHOIS lookup for URLs
def whois_lookup(url):
    print(f"\n[+] Performing WHOIS lookup for {url}...")
    try:
        domain = urlparse(url).netloc
        info = whois.whois(domain)
        print(info)
    except Exception as e:
        print(f"Error during WHOIS lookup: {e}")


# 8. SSL certificate check for URLs
def ssl_certificate_check(url):
    print(f"\n[+] Checking SSL certificate for {url}...")
    try:
        hostname = urlparse(url).netloc
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print("SSL Certificate Details:")
                for key, value in cert.items():
                    print(f"{key}: {value}")
                expiry_date = cert.get('notAfter', None)
                if expiry_date:
                    expiry_date = datetime.strptime(expiry_date, "%b %d %H:%M:%S %Y GMT")
                    print(f"SSL Certificate Expiry Date: {expiry_date}")
    except Exception as e:
        print(f"Error checking SSL certificate: {e}")


# 9. Directory brute force (common directories)
def brute_force_directories(url):
    print(f"\n[+] Brute forcing common directories for {url}...")
    common_dirs = [
        "/admin", "/login", "/dashboard", "/upload", "/api", "/config", "/admin.php", "/admin/login"
    ]
    for directory in common_dirs:
        try:
            response = requests.get(f"{url}{directory}")
            if response.status_code == 200:
                print(f"Found directory: {url}{directory}")
        except Exception as e:
            print(f"Error brute forcing directory {directory}: {e}")


# 10. DNS Lookup for URLs
def dns_lookup(url):
    print(f"\n[+] Performing DNS lookup for {url}...")
    try:
        domain = urlparse(url).netloc
        result = dns.resolver.resolve(domain, 'A')
        for ipval in result:
            print(f"IP Address for {domain}: {ipval.to_text()}")
    except Exception as e:
        print(f"Error during DNS lookup: {e}")

#11.Directory traversal  attack
def test_directory_traversal(url):
    print(f"\n[+] Testing for Directory Traversal vulnerabilities on {url}...")
    payloads = [
        "../../../../etc/passwd",  # Unix-like system file
        "..\\..\\..\\windows\\win.ini",  # Windows system file
    ]
    
    for payload in payloads:
        try:
            response = requests.get(f"{url}/{payload}")
            if response.status_code == 200:
                print(f"Vulnerable to Directory Traversal: {url}/{payload}")
        except Exception as e:
            print(f"Error testing Directory Traversal: {e}")

#12.Redirect test
def test_open_redirect(url):
    print(f"\n[+] Testing for Open Redirect vulnerabilities on {url}...")
    payloads = [
        "http://malicious.com",
        "javascript:alert('XSS')",
        "http://example.com?redirect=http://malicious.com"
    ]
    
    for payload in payloads:
        try:
            response = requests.get(f"{url}?redirect={payload}")
            if "malicious.com" in response.text or "alert('XSS')" in response.text:
                print(f"Vulnerable to Open Redirect: {url}?redirect={payload}")
        except Exception as e:
            print(f"Error testing Open Redirect: {e}")

#13.Security headers check
def check_security_headers(url):
    print(f"\n[+] Checking Security Headers for {url}...")
    expected_headers = [
        "Strict-Transport-Security",
        "X-Content-Type-Options",
        "X-XSS-Protection",
        "Content-Security-Policy",
        "X-Frame-Options",
        "Referrer-Policy"
    ]
    
    try:
        response = requests.get(url)
        headers = response.headers
        for header in expected_headers:
            if header not in headers:
                print(f"Missing header: {header}")
            else:
                print(f"Header {header}: {headers[header]}")
    except Exception as e:
        print(f"Error checking security headers: {e}")

#14.HTTP enumeration
def check_http_methods(url):
    print(f"\n[+] Checking allowed HTTP methods for {url}...")
    try:
        response = requests.options(url)
        methods = response.headers.get('allow', '')
        if methods:
            print(f"Allowed HTTP Methods: {methods}")
        else:
            print("No allowed methods found.")
    except Exception as e:
        print(f"Error checking HTTP methods: {e}")



# Main menu for IP input
def ip_menu():
    ip = input("\nEnter the target IP address: ")
    while True:
        print("\n[IP Menu] Select an option:")
        print("1. Scan Ports")
        print("2. Reverse IP Lookup")
        print("3. Back to Main Menu")
        choice = input("Enter your choice: ")

        if choice == "1":
            scan_ports(ip)
        elif choice == "2":
            reverse_ip_lookup(ip)
        elif choice == "3":
            break
        else:
            print("Invalid choice. Please try again.")


# Main menu for URL input
def url_menu():
    url = input("\nEnter the target URL: ")
    while True:
        print("\n[URL Menu] Select an option:")
        print("1. Scan HTTP Headers")
        print("2. Extract Links")
        print("3. Test for XSS Vulnerabilities")
        print("4. Test for SQL Injection Vulnerabilities")
        print("5. Perform WHOIS Lookup")
        print("6. Check SSL Certificate")
        print("7. Brute Force Directories")
        print("8. Perform DNS Lookup")
        print("9. Test for Directory Traversal")
        print("10. Test for Open Redirect")
        print("11. Check Security Headers")
        print("12. Check HTTP Methods")
        print("13. Back to Main Menu")
        choice = input("Enter your choice: ")

        if choice == "1":
            scan_headers(url)
        elif choice == "2":
            scan_links(url)
        elif choice == "3":
            test_xss(url)
        elif choice == "4":
            test_sqli(url)
        elif choice == "5":
            whois_lookup(url)
        elif choice == "6":
            ssl_certificate_check(url)
        elif choice == "7":
            brute_force_directories(url)
        elif choice == "8":
            dns_lookup(url)
        elif choice == "9":
            test_directory_traversal(url)
        elif choice == "10":
            test_open_redirect(url)
        elif choice == "11":
            check_security_headers(url)
        elif choice == "12":
            check_http_methods(url)
        elif choice == "13":
            break
        else:
            print("Invalid choice. Please try again.")


# Main program
def main():
    banner()
    while True:
        print("\n[Main Menu] Select an input type:")
        print("1. IP Address")
        print("2. URL")
        print("3. Exit")
        choice = input("Enter your choice: ")

        if choice == "1":
            ip_menu()
        elif choice == "2":
            url_menu()
        elif choice == "3":
            print("Exiting...")
            break
        else:
            print("Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
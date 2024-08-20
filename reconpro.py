import os
import requests
from dotenv import load_dotenv
from colorama import init, Fore, Style

# Initialize colorama
init(autoreset=True)

# Load environment variables from .env file
load_dotenv()

# API keys from environment variables
C99_API_KEY = os.getenv('C99_API_KEY')
HIBP_API_KEY = os.getenv('HIBP_API_KEY')

def find_subdomains(domain):
    print(f"\n{Fore.CYAN}Finding subdomains for: {domain}\n{Style.RESET_ALL}")
    url = f"https://api.c99.nl/subdomainfinder?key={C99_API_KEY}&domain={domain}"
    response = requests.get(url)
    if response.status_code == 200:
        subdomains = response.text.split('<br>')
        if subdomains:
            print(f"{Fore.GREEN}Subdomains found:\n{Style.RESET_ALL}")
            for sub in subdomains:
                print(f"{Fore.YELLOW}- {sub}")
        else:
            print(f"{Fore.RED}No subdomains found for {domain}.")
    else:
        print(f"{Fore.RED}Failed to retrieve subdomains or empty response received.")

def detect_waf(url_input):
    print(f"\n{Fore.CYAN}Detecting WAF for: {url_input}\n{Style.RESET_ALL}")
    url = f"https://api.c99.nl/firewalldetector?key={C99_API_KEY}&url={url_input}"
    response = requests.get(url)
    if response.status_code == 200 and response.text.strip():
        print(f"{Fore.GREEN}WAF Detection Result:\n{Style.RESET_ALL}{response.text}")
    else:
        print(f"{Fore.RED}Failed to detect WAF or empty response received.")

def scan_ports(host):
    print(f"\n{Fore.CYAN}Scanning ports for: {host}\n{Style.RESET_ALL}")
    url = f"https://api.c99.nl/portscanner?key={C99_API_KEY}&host={host}"
    response = requests.get(url)
    if response.status_code == 200 and response.text.strip():
        print(f"{Fore.GREEN}Open Ports Found:\n{Style.RESET_ALL}")
        ports = response.text.split('<br>')
        for port in ports:
            print(f"{Fore.YELLOW}- {port}")
    else:
        print(f"{Fore.RED}Failed to scan ports or empty response received.")

def geoip_lookup(ip_address):
    print(f"\n{Fore.CYAN}Performing GeoIP lookup for: {ip_address}\n{Style.RESET_ALL}")
    url = f"https://api.c99.nl/geoip?key={C99_API_KEY}&host={ip_address}"
    response = requests.get(url)
    if response.status_code == 200 and response.text.strip():
        geoip_data = response.text.replace('<br>', '\n').strip()
        formatted_geoip_data = ""
        for line in geoip_data.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                formatted_geoip_data += f"{Fore.YELLOW}{key.strip()}: {Fore.GREEN}{value.strip()}\n"
            else:
                formatted_geoip_data += f"{Fore.YELLOW}{line.strip()}\n"
        print(f"{Fore.GREEN}GeoIP Information:\n{Style.RESET_ALL}{formatted_geoip_data}")
    else:
        print(f"{Fore.RED}Failed to retrieve GeoIP information or empty response received.")

def validate_email(email):
    print(f"\n{Fore.CYAN}Validating email: {email}\n{Style.RESET_ALL}")
    url = f"https://api.c99.nl/emailvalidator?key={C99_API_KEY}&email={email}"
    response = requests.get(url)
    if response.status_code == 200 and response.text.strip():
        email_data = response.text.replace('<br>', '\n').strip()
        formatted_email_data = ""
        for line in email_data.split('\n'):
            if ':' in line:
                key, value = line.split(':', 1)
                formatted_email_data += f"{Fore.YELLOW}{key.strip()}: {Fore.GREEN}{value.strip()}\n"
            else:
                formatted_email_data += f"{Fore.YELLOW}{line.strip()}\n"
        print(f"{Fore.GREEN}Email Validation Result:\n{Style.RESET_ALL}{formatted_email_data}")
    else:
        print(f"{Fore.RED}Failed to validate email or empty response received.")

def check_email_leak(email):
    print(f"\n{Fore.CYAN}Checking for email leaks: {email}\n{Style.RESET_ALL}")
    url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}?truncateResponse=false"
    headers = {
        'User-Agent': 'YourAppNameHere',
        'hibp-api-key': HIBP_API_KEY
    }
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        breaches = response.json()
        if breaches:
            print(f"{Fore.GREEN}Leaked Breaches Found:\n{Style.RESET_ALL}")
            for breach in breaches:
                print(f"{Fore.YELLOW}- {breach['Name']} (Date: {breach['BreachDate']})")
        else:
            print(f"{Fore.GREEN}No breaches found for this email.\n")
    elif response.status_code == 404:
        print(f"{Fore.GREEN}No breaches found for this email.\n")
    else:
        print(f"{Fore.RED}Failed to check email leak or empty response received.")

if __name__ == "__main__":
    while True:
        # Main menu to select a service
        print(f"\n{Fore.BLUE}{Style.BRIGHT}Choose a service:")
        print(f"{Fore.YELLOW}1. Find Subdomains")
        print(f"{Fore.YELLOW}2. Detect WAF")
        print(f"{Fore.YELLOW}3. Scan Ports")
        print(f"{Fore.YELLOW}4. GeoIP Lookup")
        print(f"{Fore.YELLOW}5. Email Validator")
        print(f"{Fore.YELLOW}6. Check Email Leak")
        print(f"{Fore.YELLOW}7. Exit{Style.RESET_ALL}")
        
        choice = input(f"{Fore.CYAN}Enter the number of the service you want to use: {Style.RESET_ALL}")
        
        if choice == '1':
            domain = input(f"{Fore.CYAN}Enter the domain to find subdomains: {Style.RESET_ALL}")
            find_subdomains(domain)
        elif choice == '2':
            url_input = input(f"{Fore.CYAN}Enter the URL for WAF detection: {Style.RESET_ALL}")
            detect_waf(url_input)
        elif choice == '3':
            host = input(f"{Fore.CYAN}Enter the IP or domain to scan ports: {Style.RESET_ALL}")
            scan_ports(host)
        elif choice == '4':
            ip_address = input(f"{Fore.CYAN}Enter the IP address for GeoIP lookup: {Style.RESET_ALL}")
            geoip_lookup(ip_address)
        elif choice == '5':
            email = input(f"{Fore.CYAN}Enter the email address to validate: {Style.RESET_ALL}")
            validate_email(email)
        elif choice == '6':
            email = input(f"{Fore.CYAN}Enter the email address to check for leaks: {Style.RESET_ALL}")
            check_email_leak(email)
        elif choice == '7':
            print(f"{Fore.GREEN}Exiting the program.")
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please select a valid service.")

import os
import requests
from dotenv import load_dotenv

# Load environment variables from .env file
load_dotenv()

# API keys from environment variables
C99_API_KEY = os.getenv('C99_API_KEY')

def find_subdomains(domain):
    url = f"https://api.c99.nl/subdomainfinder?key={C99_API_KEY}&domain={domain}"
    response = requests.get(url)
    if response.status_code == 200:
        subdomains = response.text.split('<br>')
        for sub in subdomains:
            print(sub)
    else:
        print("Failed to retrieve subdomains or empty response received.")

if __name__ == "__main__":
    # Example usage
    domain = input("Enter the domain to find subdomains: ")
    find_subdomains(domain)
